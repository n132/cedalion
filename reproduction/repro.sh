#!/usr/bin/env bash
# Reproduce a published bug from bugs.sh.
#
#     ./repro.sh build 5e2bcf11e7027510      # fetch it, build the kernel and the reproducer
#     ./repro.sh run   5e2bcf11e7027510      # boot run.sh with the reproducer in it
#
# Everything a bug needs to be re-run is already public at bugs.sh/b/<id>/: the
# reproducer, the config it was built with, and the exact qemu line. `build`
# puts all of that in ./<bug_id>/ and turns it into a bzImage and a static
# binary; `run` boots them. They are separate because building is minutes and
# booting is seconds, and a bug that needs a few attempts to land should cost
# the second and not the first.
#
# Both work inside the container the Dockerfile beside this file describes,
# which is built on first use. That is where the expensive and unchanging parts
# are cached: the toolchain, qemu, and the 650MB kernelCTF image every
# published run.sh boots. --host uses what is installed here instead.
#
# Nothing is read or written outside the directory this is run from: per-bug
# work is ./<bug_id>/, and throwing the whole thing away is `rm -rf`. The one
# thing not kept there is the kernel object store every checkout comes out of,
# which is a layer of the image -- clone it once when the image is built, not
# once per directory that ever runs a bug. --host has no image to take it from
# and clones into ./.cache/linux.git instead.
#
# Environment:
#   CEDALION_BASE            site to fetch from        (default https://bugs.sh)
#   CEDALION_LINUX_URL       kernel remote to clone    (default torvalds/linux)
#   CEDALION_TIMEOUT         seconds to let the VM run (default 300)
#   CEDALION_IMAGE           image to build and run in (default cedalion-repro)
#   CEDALION_ROOTFS          kernelCTF image           (default ./.cache/rootfs.img)
#   CEDALION_LINUX_CACHE     bare kernel clone to take checkouts out of; the
#                            image sets this to the one baked into it, and
#                            --host clones into ./.cache/linux.git instead
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
HOST=0
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
  -f, --force        redo every step, even ones already done         [build]
  -t, --timeout SEC  how long to let the VM run (default $TIMEOUT)        [run]
  -u, --as-user      run the reproducer as 'user' rather than root     [run]
      --host         work here rather than in the container
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
	--host)       HOST=1; shift ;;
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
# Unless told otherwise, this script's job is to run itself inside the image,
# with the current directory as the container's /work and as the calling uid --
# so ./<bug_id>/ and ./.cache/ appear here, owned by whoever ran this, exactly
# as they would have without docker. That bind mount is the only thing the
# container can see of this machine.
if [ -z "${CEDALION_IN_CONTAINER:-}" ] && { [ "$HOST" = 0 ] || [ "$SHELL_ONLY" = 1 ]; }; then
	HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
	command -v docker >/dev/null || die "docker is not installed; --host works without it"
	[ -e /dev/kvm ] || die "/dev/kvm is missing; every published run.sh boots with -enable-kvm"
	[ -f "$HERE/Dockerfile" ] || die "no Dockerfile next to $0; --host works without one"

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
	[ "$stale" = 1 ] && { say "building $IMAGE"; docker build -t "$IMAGE" "$HERE"; }

	opts=(--rm -i --device /dev/kvm --group-add "$(stat -c %g /dev/kvm)"
	      --user "$(id -u):$(id -g)" -v "$PWD:/work" -w /work)
	[ -t 0 ] && opts+=(-t)
	for v in CEDALION_BASE CEDALION_LINUX_URL CEDALION_TIMEOUT; do
		[ -n "${!v:-}" ] && opts+=(-e "$v=${!v}")
	done

	[ "$SHELL_ONLY" = 1 ] && exec docker run "${opts[@]}" --entrypoint bash "$IMAGE"
	exec docker run "${opts[@]}" "$IMAGE" "${ARGV[@]}"
fi

[ "$SHELL_ONLY" = 1 ] && die "--shell needs the container"

# In the container both of these are layers of the image; on --host they are
# fetched once into ./.cache/ and shared by every bug built in this directory.
CACHE=$PWD/.cache
ROOTFS=${CEDALION_ROOTFS:-$CACHE/rootfs.img}
MIRROR=${CEDALION_LINUX_CACHE:-$CACHE/linux.git}
DIR=$PWD/$BUG

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

mkdir -p "$DIR"
cd "$DIR"

# One at a time per bug. Two builds in one directory step on each other deep
# inside make -- objtool failing on a half-written object file -- and the error
# says nothing about the cause.
exec 9>".lock"
flock -n 9 || die "something else is already working in $BUG/"
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
# One bare clone under .cache/ is the object store for every bug built in this
# directory: the first pays for it, the rest get a checkout out of it in a
# second. A bug's ./linux is a working copy that borrows those objects through
# a *relative* alternates path, so the same directory works whether the build
# runs in the container (as /work/...) or on the host (as $PWD/...).
say "2/4  kernel source at $COMMIT"

has_commit() { git -C "$1" cat-file -e "$COMMIT^{commit}" 2>/dev/null; }

# --host has no image to take the object store from, so it makes its own.
if [ ! -d "$MIRROR" ]; then
	note "cloning $LINUX_URL into .cache/linux.git (once; this takes a while)"
	git clone --quiet --bare "$LINUX_URL" "$MIRROR"
fi

# The bug's own clone owns nothing but its refs -- every object it can already
# see comes from the store, which stays read-only and shared. In .cache/ that
# link is written relative, so the work directory survives being moved or
# copied; the one in the image is an absolute path that only exists in it.
if [ ! -d linux/.git ]; then
	git clone --quiet --shared --no-checkout "$MIRROR" linux
	git -C linux remote set-url origin "$LINUX_URL"
	case $MIRROR in
	"$CACHE"/*)
		python3 - "$MIRROR" <<'EOF'
import os, sys
alt = "linux/.git/objects/info/alternates"
with open(alt, "w") as f:
    f.write(os.path.relpath(os.path.join(sys.argv[1], "objects"),
                            os.path.abspath("linux/.git/objects")) + "\n")
EOF
		;;
	esac
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

[ -d "$DIR" ] || die "no ./$BUG here -- build it first: ${0##*/} build $BUG"
cd "$DIR"

# One at a time per bug. Two builds in one directory step on each other deep
# inside make -- objtool failing on a half-written object file -- and the error
# says nothing about the cause.
exec 9>".lock"
flock -n 9 || die "something else is already working in $BUG/"

for f in bzImage exp/repro run.sh; do
	[ -s "$f" ] || die "no $BUG/$f -- build it first: ${0##*/} build $BUG"
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

note "up to ${TIMEOUT}s; console also in $BUG/repro.log"
set +e
timeout --foreground -k 5 "$TIMEOUT" ./run-repro.sh nodebug </dev/null 2>&1 | tee repro.log
rc=${PIPESTATUS[0]}
set -e

say "result"
if grep -qE 'KASAN|KMSAN|UBSAN|BUG: |general protection fault|Oops|kernel BUG at|WARNING: |Kernel panic|refcount_t:|INFO: task .* blocked' repro.log; then
	grep -nE 'KASAN|KMSAN|UBSAN|BUG: |general protection fault|Oops|kernel BUG at|WARNING: |Kernel panic|refcount_t:' repro.log | head -5 | sed 's/^/    /'
	note "crash reproduced -- full log in $BUG/repro.log"
	exit 0
fi
[ "$rc" = 124 ] && note "the VM ran out of time (${TIMEOUT}s) with no crash"
note "no crash found in $BUG/repro.log"
exit 1
