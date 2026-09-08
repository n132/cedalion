#!/usr/bin/env bash
# Reproduce a published bug from bugs.sh.
#
#     ./repro.sh build 5e2bcf11e7027510      # fetch it, build the kernel and the reproducer
#     ./repro.sh run   5e2bcf11e7027510      # boot run.sh with the reproducer in it
#
# Everything a bug needs to be re-run is already public at bugs.sh/b/<id>/: the
# reproducer, the config it was built with, and the exact qemu line. `build`
# puts all of that in a per-bug Docker image and turns it into a bzImage and a
# static binary; `run` starts that image and boots them. They are separate
# because building is minutes and booting is seconds, and a bug that needs a few
# attempts to land should cost the second and not the first.
#
# Both work inside the container the Dockerfile beside this file describes,
# which is built on first use. That is where the expensive and unchanging parts
# are cached: the toolchain, qemu, the 650MB kernelCTF image every published
# run.sh boots, and a public mainline kernel mirror.
#
# A run does not mount a host work directory. Per-bug writable state is committed
# into the Docker image named n132/cedalion:co-<bug_id>-vul. Throwing the work
# away is `docker image rm n132/cedalion:co-<bug_id>-vul`. The one thing not
# stored under /work is the kernel object store every checkout comes out of:
# /opt/cedalion/linux.git is a read-only layer of the public image, cloned from
# public mainline when the image was built, not once per directory that ever
# runs a bug.
#
# Environment:
#   CEDALION_BASE            site to fetch from        (default https://bugs.sh)
#   CEDALION_LINUX_URL       kernel remote to clone    (default torvalds/linux)
#   CEDALION_TIMEOUT         seconds to let the VM run (default 300)
#   CEDALION_IMAGE           image to build and run in (default cedalion-repro)
#   CEDALION_ROOTFS          kernelCTF image           (image default:
#                                                       /opt/cedalion/rootfs.img)
#   CEDALION_LINUX_CACHE     bare kernel clone to take checkouts out of; the
#                            image sets this to the public one baked into it
set -euo pipefail

ARGV=("$@")   # kept so the script can hand itself the same arguments in docker

BASE=${CEDALION_BASE:-https://bugs.sh}
LINUX_URL=${CEDALION_LINUX_URL:-https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git}
ROOTFS_URL=https://storage.googleapis.com/kernelctf-build/files/rootfs_repro_v2.img.gz
TIMEOUT=${CEDALION_TIMEOUT:-300}
IMAGE=${CEDALION_IMAGE:-cedalion-repro}
JOBS=$(nproc)
COMMIT=
RUNAS=root
FORCE=0
NO_CACHE=0
SHELL_ONLY=0
CMD=
BUG=

usage() {
	cat <<EOF
usage: $0 build <bug_id>    fetch the bug, build its kernel and reproducer
       $0 run   <bug_id>    boot it and look for the crash
       $0 --shell           a shell in the container

  -c, --commit SHA   kernel commit to build (default: the one artifacts.json
                     records for this bug)                          [build]
  -j, --jobs N       make -j (default $JOBS)                            [build]
  -f, --force        rebuild the per-bug image without cache         [build]
      --no-cache     rebuild the container with docker --no-cache --pull
                     before running; useful when the baked-in kernel mirror
                     may be older than a moving target branch
  -t, --timeout SEC  how long to let the VM run (default $TIMEOUT)        [run]
  -u, --as-user      run the reproducer as 'user' rather than root     [run]
EOF
}

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
note() { printf '    %s\n' "$*"; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
	case $1 in
	-c|--commit)  COMMIT=$2; shift 2 ;;
	-j|--jobs)    JOBS=$2; shift 2 ;;
	-t|--timeout) TIMEOUT=$2; shift 2 ;;
	-u|--as-user) RUNAS=user; shift ;;
	-f|--force)   FORCE=1; shift ;;
	--no-cache)   NO_CACHE=1; shift ;;
	--shell)      SHELL_ONLY=1; shift ;;
	-h|--help)    usage; exit 0 ;;
	-*)           usage >&2; die "unknown option $1" ;;
	*)            if   [ -z "$CMD" ]; then CMD=$1
	              elif [ -z "$BUG" ]; then BUG=$1
	              else die "too many arguments"; fi; shift ;;
	esac
done

if [ "$SHELL_ONLY" = 0 ]; then
	case $CMD in
	build|run) ;;
	*)         usage >&2; exit 2 ;;
	esac
	case $BUG in
	"")          usage >&2; die "which bug?" ;;
	*[!0-9a-f]*) die "'$BUG' is not a bug id (16 hex characters)" ;;
	esac
fi

# ------------------------------------------------------------------- container
#
# This script's job is to run itself inside Docker. `build` uses Docker's image
# build path to produce n132/cedalion:co-<bug_id>-vul with the checked-out
# kernel, bzImage and compiled reproducer already inside it. `run` starts that
# per-bug image. No host work directory is mounted.
if [ -z "${CEDALION_IN_CONTAINER:-}" ]; then
	HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
	command -v docker >/dev/null || die "docker is not installed"
	[ -f "$HERE/Dockerfile" ] || die "no Dockerfile next to $0; run this from the public Cedalion checkout"
	BUG_IMAGE="n132/cedalion:co-$BUG-vul"
	BUG_CONTAINER="co-$BUG-vul"

	# The image carries a copy of this script, so an edit to either file is a
	# reason to build again. Nothing else here is in the image.
	stale=1
	if created=$(docker image inspect -f '{{.Created}}' "$IMAGE" 2>/dev/null); then
		if ts=$(date -d "$created" +%s 2>/dev/null); then
			stale=0
			for f in "$HERE/Dockerfile" "$HERE/repro.sh"; do
				[ "$(stat -c %Y "$f")" -gt "$ts" ] && stale=1
			done
		fi
	fi
	if [ "$NO_CACHE" = 1 ]; then
		say "building $IMAGE without docker cache"
		docker build --pull --no-cache -t "$IMAGE" "$HERE"
	elif [ "$stale" = 1 ]; then
		say "building $IMAGE"
		docker build -t "$IMAGE" "$HERE"
	fi

	if [ "$SHELL_ONLY" = 1 ]; then
		opts=(--rm -i -w /work)
		[ -t 0 ] && opts+=(-t)
		for v in CEDALION_BASE CEDALION_LINUX_URL CEDALION_TIMEOUT; do
			[ -n "${!v:-}" ] && opts+=(-e "$v=${!v}")
		done
		exec docker run "${opts[@]}" --entrypoint bash "$IMAGE"
	fi

	if [ "$CMD" = build ]; then
		[ "$FORCE" = 1 ] && docker image rm "$BUG_IMAGE" >/dev/null 2>&1 || true
		build_opts=(-t "$BUG_IMAGE" --build-arg "BASE_IMAGE=$IMAGE"
		            --build-arg "BUG=$BUG" --build-arg "JOBS=$JOBS")
		[ -n "$COMMIT" ] && build_opts+=(--build-arg "COMMIT=$COMMIT")
		[ -n "${CEDALION_BASE:-}" ] && build_opts+=(--build-arg "CEDALION_BASE=$CEDALION_BASE")
		[ -n "${CEDALION_LINUX_URL:-}" ] && build_opts+=(--build-arg "CEDALION_LINUX_URL=$CEDALION_LINUX_URL")
		[ -n "${CEDALION_TIMEOUT:-}" ] && build_opts+=(--build-arg "CEDALION_TIMEOUT=$CEDALION_TIMEOUT")
		{ [ "$NO_CACHE" = 1 ] || [ "$FORCE" = 1 ]; } && build_opts+=(--no-cache)
		say "building ready-to-run image $BUG_IMAGE"
		docker build "${build_opts[@]}" -f - "$HERE" <<'EOF'
ARG BASE_IMAGE=cedalion-repro
FROM ${BASE_IMAGE}
ARG BUG
ARG COMMIT
ARG JOBS
ARG CEDALION_BASE
ARG CEDALION_LINUX_URL
ARG CEDALION_TIMEOUT
ENV CEDALION_IN_CONTAINER=1
WORKDIR /work
RUN set -eu; \
	if [ -n "${COMMIT:-}" ]; then set -- -c "$COMMIT"; else set --; fi; \
	/usr/local/bin/repro.sh "$@" -j "$JOBS" build "$BUG"
EOF
		note "image: $BUG_IMAGE"
		note "run it with: ${0##*/} run $BUG"
		exit 0
	fi

	docker image inspect "$BUG_IMAGE" >/dev/null 2>&1 ||
		die "no image $BUG_IMAGE -- build it first: ${0##*/} build $BUG"
	[ -e /dev/kvm ] || die "/dev/kvm is missing; every published run.sh boots with -enable-kvm"
	if old=$(docker ps -aq --filter "name=^/${BUG_CONTAINER}$"); then
		if [ -n "$old" ]; then
			running=$(docker inspect -f '{{.State.Running}}' "$old")
			[ "$running" = false ] || die "$BUG_CONTAINER is already running"
			docker rm "$old" >/dev/null
		fi
	fi
	run_opts=(--rm -i --name "$BUG_CONTAINER" --device /dev/kvm -w /work)
	[ -t 0 ] && run_opts+=(-t)
	for v in CEDALION_TIMEOUT; do
		[ -n "${!v:-}" ] && run_opts+=(-e "$v=${!v}")
	done
	exec docker run "${run_opts[@]}" "$BUG_IMAGE" "${ARGV[@]}"
fi

[ "$SHELL_ONLY" = 1 ] && die "--shell needs docker"

# In the container both of these are layers of the public reproduction image.
CACHE=$PWD/.cache
ROOTFS=${CEDALION_ROOTFS:-$CACHE/rootfs.img}
MIRROR=${CEDALION_LINUX_CACHE:-$CACHE/linux.git}
DIR=$PWD

# =============================================================================
if [ "$CMD" = build ]; then
# =============================================================================

for t in git gcc make curl python3 gzip flock; do
	command -v "$t" >/dev/null || die "$t is not installed"
done
mkdir -p "$CACHE"

# ---------------------------------------------------------------- 1. artifacts
#
# The index says which files a bug has published and which commit it was found
# on. A bug can be listed with some of its files withheld ("request from
# co@bugs.sh"), so read the entry rather than assuming the three URLs exist --
# and read it before making the bug's directory, so that a bug id nothing is
# published for leaves nothing behind.
say "1/4  fetching artifacts for $BUG"

curl -fsSL "$BASE/artifacts.json" -o "$CACHE/artifacts.json" ||
	die "cannot reach $BASE/artifacts.json"

meta=$(python3 - "$BUG" "$CACHE/artifacts.json" <<'EOF'
import json, shlex, sys
bug, index = sys.argv[1], sys.argv[2]
entry = json.load(open(index)).get(bug)
if entry is None:
    sys.exit(f"error: {bug} is not in artifacts.json -- nothing is published for it")
files = {k for k, v in (entry.get("files") or {}).items() if v}
missing = {"repro.c", "config.gz", "run.sh"} - files
if missing:
    sys.exit("error: " + bug + " does not publish " + ", ".join(sorted(missing)) +
             " -- request from co@bugs.sh")
# What the bug says about itself, for whichever of it is disclosed. Not needed
# to reproduce anything, which is why it is separate from the three above.
reading = [f for f in ("report.md", "report.eml", "patch.diff") if f in files]
print("ENTRY_COMMIT=" + shlex.quote(entry.get("kernel_commit") or ""))
print("TITLE=" + shlex.quote(entry.get("title") or ""))
print("READING=" + shlex.quote(" ".join(reading)))
EOF
) || exit 1
eval "$meta"

cd "$DIR"

# One at a time per bug. Two builds in one directory step on each other deep
# inside make -- objtool failing on a half-written object file -- and the error
# says nothing about the cause.
exec 9>".lock"
flock -n 9 || die "something else is already working on $BUG"
[ "$FORCE" = 1 ] && rm -f bzImage exp/repro run-repro.sh

[ -n "$COMMIT" ] || COMMIT=$ENTRY_COMMIT
[ -n "$COMMIT" ] || die "no kernel commit for $BUG; pass one with --commit"
[ -n "$TITLE" ] && note "$TITLE"
note "kernel commit: $COMMIT"

for f in repro.c config.gz run.sh; do
	[ -s "$f" ] && [ "$FORCE" = 0 ] && { note "have $f"; continue; }
	curl -fsSL "$BASE/b/$BUG/$f" -o "$f" || die "cannot fetch $f"
	note "got $f"
done
chmod +x run.sh

# The report and the patch land here too: what a bug is lives next to what
# demonstrates it, and reading the analysis should not mean going back to the
# site. A bug that withholds one is not an error -- the reproduction does not
# depend on any of them.
for f in $READING; do
	[ -s "$f" ] && [ "$FORCE" = 0 ] && continue
	curl -fsSL "$BASE/b/$BUG/$f" -o "$f" || { rm -f "$f"; continue; }
	note "got $f"
done

# ------------------------------------------------------------------- 2. source
#
# The image's public bare clone is the object store. A bug's ./linux is a
# working copy in /work that borrows those objects before the per-bug image is
# committed.
say "2/4  kernel source at $COMMIT"

has_commit() { git -C "$1" cat-file -e "$COMMIT^{commit}" 2>/dev/null; }

if [ ! -d "$MIRROR" ]; then
	die "kernel object store is missing from the reproduction image: $MIRROR"
fi

# The bug's own clone owns nothing but its refs -- every object it can already
# see comes from the public store baked into the image, which stays read-only
# and shared.
if [ ! -d linux/.git ]; then
	git clone --quiet --shared --no-checkout "$MIRROR" linux
	git -C linux remote set-url origin "$LINUX_URL"
	note "sharing objects with ${MIRROR#$PWD/}"
fi

# A commit newer than the store -- the image has aged, or the bug is on a tree
# that is not mainline. Fetching it into the bug's clone is the writable half
# of the arrangement: only the objects the store lacks come down.
has_commit linux || {
	note "$COMMIT is not in the store; fetching it"
	git -C linux fetch --quiet --no-tags origin "$COMMIT" 2>/dev/null ||
		git -C linux fetch --quiet --no-tags origin ||
		die "cannot fetch $COMMIT from $LINUX_URL"
}
has_commit linux || die "$COMMIT is not reachable from $LINUX_URL"

if [ "$(git -C linux rev-parse HEAD 2>/dev/null || true)" != "$COMMIT" ]; then
	git -C linux checkout --quiet --detach --force "$COMMIT"
	git -C linux clean -qfdx
fi
note "HEAD is $(git -C linux log -1 --format='%h %s' HEAD)"

# -------------------------------------------------------------------- 3. build
say "3/4  building the kernel (-j$JOBS)"
if [ -s bzImage ] && [ "$FORCE" = 0 ]; then
	note "bzImage already built"
else
	gzip -dc config.gz > linux/.config
	make -C linux olddefconfig >/dev/null
	make -C linux -j"$JOBS" bzImage
	cp linux/arch/x86/boot/bzImage bzImage
	note "bzImage: $(du -h bzImage | cut -f1)"
fi

# --------------------------------------------------------------- 4. reproducer
#
# Static, because the VM's userland is not the one this compiles against. The
# binary goes in exp/, which the VM mounts over 9p.
say "4/4  compiling the reproducer"
mkdir -p exp
gcc -O2 -static -o exp/repro repro.c -lpthread -w
note "exp/repro: $(du -h exp/repro | cut -f1)"

say "built"
note "boot it with: ${0##*/} run $BUG"
exit 0
fi

# =============================================================================
# run
#
# run.sh is the bug's own qemu line and is left exactly as published -- it
# carries per-bug detail (cpu count, nic model, extra devices, cmdline flags)
# that the crash may depend on. run-repro.sh is that file with two things
# added: the 9p mounts that carry the reproducer in, and init=/init, which the
# kernelCTF image answers by running init/init.sh from the first of them.
# panic=-1 rides along so a panicking kernel reboots into -no-reboot and qemu
# exits then and there, rather than sitting at "Rebooting in 86400 seconds"
# until the timeout. It cannot change a crash that has already happened.
# =============================================================================

for t in qemu-system-x86_64 flock; do
	command -v "$t" >/dev/null || die "$t is not installed"
done

cd "$DIR"

# One at a time per bug. Two builds in one directory step on each other deep
# inside make -- objtool failing on a half-written object file -- and the error
# says nothing about the cause.
exec 9>".lock"
flock -n 9 || die "something else is already working on $BUG"

for f in bzImage exp/repro run.sh; do
	[ -s "$f" ] || die "no $f in the per-bug image -- build it first: ${0##*/} build $BUG"
done

say "booting $BUG"

[ -s "$ROOTFS" ] || {
	note "fetching the kernelCTF repro image (once, into .cache)"
	mkdir -p "$(dirname "$ROOTFS")"
	curl -fL "$ROOTFS_URL" -o "$ROOTFS.gz"
	gzip -df "$ROOTFS.gz"
}
# Relative when it is the cached copy, so moving or copying the work directory
# does not leave a dangling link; absolute when it is the one inside the image.
case $ROOTFS in
"$CACHE"/*) ln -sf "../.cache/${ROOTFS##*/}" rootfs.img ;;
*)          ln -sf "$ROOTFS" rootfs.img ;;
esac

mkdir -p init
sed "s/@RUNAS@/$RUNAS/" > init/init.sh <<'EOF'
#!/bin/sh
# Runs as pid 1 inside the VM: /init on the kernelCTF image mounts the 9p tag
# 'init' and execs this.
mount -t proc none /proc 2>/dev/null
mount -t sysfs none /sys 2>/dev/null
mkdir -p /tmp/exp_ro /tmp/exp
mount -t 9p exp /tmp/exp_ro
cp /tmp/exp_ro/repro /tmp/exp/repro
chmod 755 /tmp/exp /tmp/exp/repro
ifconfig lo 127.0.0.1 netmask 255.0.0.0 up 2>/dev/null || ip link set lo up
echo "::REPRO OUTPUT FROM HERE::"
su @RUNAS@ -c /tmp/exp/repro
echo "::REPRO EXITED rc=$? ::"
sync; sleep 2
poweroff -f 2>/dev/null || echo o > /proc/sysrq-trigger
EOF
chmod +x init/init.sh

grep -q -- '-kernel bzImage' run.sh || die "run.sh is not the qemu line this expects"
sed -e 's|^\([[:blank:]]*\)-kernel bzImage \\|\1-kernel bzImage \\\n\1-virtfs local,path=init,mount_tag=init,security_model=none,readonly=on \\\n\1-virtfs local,path=exp,mount_tag=exp,security_model=none,readonly=on \\|' \
    -e 's|-append "|-append "init=/init panic=-1 |' \
    run.sh > run-repro.sh
chmod +x run-repro.sh

# Some bugs need a device set up before qemu starts -- a TPM socket, a usbredir
# channel. Those run.sh files name it through the environment; say so rather
# than booting into an unexplained failure.
for v in $(grep -oE '\$[A-Za-z_][A-Za-z0-9_]*' run-repro.sh | tr -d '$' | sort -u); do
	[ -n "${!v:-}" ] || note "warning: run.sh uses \$$v and it is unset"
done

note "up to ${TIMEOUT}s; console also in repro.log inside the per-bug image"
set +e
timeout --foreground -k 5 "$TIMEOUT" ./run-repro.sh nodebug </dev/null 2>&1 | tee repro.log
rc=${PIPESTATUS[0]}
set -e

say "result"
if grep -qE 'KASAN|KMSAN|UBSAN|BUG: |general protection fault|Oops|kernel BUG at|WARNING: |Kernel panic|refcount_t:|INFO: task .* blocked' repro.log; then
	grep -nE 'KASAN|KMSAN|UBSAN|BUG: |general protection fault|Oops|kernel BUG at|WARNING: |Kernel panic|refcount_t:' repro.log | head -5 | sed 's/^/    /'
	note "crash reproduced -- full log in repro.log inside the per-bug image"
	exit 0
fi
[ "$rc" = 124 ] && note "the VM ran out of time (${TIMEOUT}s) with no crash"
note "no crash found in repro.log inside the per-bug image"
exit 1
