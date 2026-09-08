# Reproduction Images

`repro.sh` turns a disclosed bug into a ready-to-run Docker image.

## Build

```bash
./repro.sh build 4bda3bf8e1a2b780
```

The output image is:

```text
n132/cedalion:co-4bda3bf8e1a2b780-vul
```

Build order:

1. build or reuse the public base image `cedalion-repro`;
2. fetch `artifacts.json` and the bug's public `repro.c`, `config.gz` and `run.sh` from `bugs.sh`;
3. check out the exact kernel commit under `/work/linux`;
4. build `/work/bzImage`;
5. compile the static reproducer as `/work/exp/repro`;
6. store the result in `n132/cedalion:co-<bug_id>-vul`.

No host work directory is mounted. The base image contains only public shared
resources: the toolchain, qemu, the kernelCTF rootfs at
`/opt/cedalion/rootfs.img`, and a bare public mainline mirror at
`/opt/cedalion/linux.git`. If the target commit is newer than that mirror, the
per-bug image build fetches the missing objects from the public kernel remote.

## Latest kernel

`--latest` skips the recorded commit and builds the current tip of the kernel
remote instead, which answers "does this bug still reproduce on mainline?":

```bash
./repro.sh build 4bda3bf8e1a2b780 --latest
./repro.sh run   4bda3bf8e1a2b780 --latest
```

It goes in a separate image, `n132/cedalion:co-<bug_id>-latest`, so the two
answers do not overwrite each other -- which is why `run` needs the flag too.
The tip is resolved from the remote on every build, and the per-bug layer is
always rebuilt without Docker cache, so a build a week later is a build of that
week's tree. Everything else is unchanged: the bug's published `config.gz` still
configures it (through `olddefconfig`) and its published `run.sh` still boots it.

## Host mode

`--host` does the same work on this machine instead of in a container, and never
invokes `docker` at all:

```bash
./repro.sh build 4bda3bf8e1a2b780 --host
./repro.sh run   4bda3bf8e1a2b780 --host
./repro.sh build 4bda3bf8e1a2b780 --host --latest    # composes with --latest
```

It needs `git gcc make curl python3 gzip flock` for `build`, plus
`qemu-system-x86_64` and `/dev/kvm` for `run` — and it builds with whatever
compiler is installed here, which is not the pinned one the image carries. Old
recorded commits do not always build under a new gcc; that is the price of
skipping the container.

Nothing is written outside the directory you run it from:

```text
./.cache/linux.git        bare object store, cloned once
./.cache/rootfs.img       the kernelCTF image
./<bug_id>/               repro.c config.gz run.sh report.md linux/ bzImage exp/repro repro.log
./<bug_id>-latest/        the same for --latest, so it cannot build over the pinned tree
```

Each bug's `linux/` is a `git clone --shared` off the store and owns only its
refs, so the per-bug cost is a checkout and its build objects, not another copy
of the history. `CEDALION_LINUX_CACHE` points the store somewhere else, and
`--shared` borrows from a non-bare clone too:

```bash
CEDALION_LINUX_CACHE=~/kernel/net ./repro.sh build 4bda3bf8e1a2b780 --host
```

That skips the initial clone entirely, provided the clone is a full one — check
with `git -C <path> rev-parse --is-shallow-repository`. Git cannot borrow from a
shallow repository; it copies the objects instead, once per bug and at the size
of the whole store, so `--host` warns and carries on rather than looking hung.
The catch of any `--shared` clone also applies: the bug's tree borrows objects it
does not own, so a `git gc` in the repository you pointed at can prune objects
out from under it.

`--host --shell` is refused — `--shell` is a shell in the container, and host
mode has none. The refusal happens at the argument checks, so nothing is built
or started.

Use `--no-cache` when the base image may be stale:

```bash
./repro.sh --no-cache build 4bda3bf8e1a2b780
```

Use `-f` to rebuild the per-bug image without Docker cache:

```bash
./repro.sh -f build 4bda3bf8e1a2b780
```

## Run

Run a locally built image:

```bash
./repro.sh run 4bda3bf8e1a2b780
```

Run directly after the image has been pushed:

```bash
docker run --rm --name co-4bda3bf8e1a2b780-vul --device /dev/kvm \
  n132/cedalion:co-4bda3bf8e1a2b780-vul run 4bda3bf8e1a2b780
```

Docker pulls the image automatically if it is not local. The machine running it
needs Docker, `/dev/kvm`, and permission to use KVM. The full VM console log is
written as `/work/repro.log` inside the running container.

`run.sh` is left exactly as published. `run` derives `run-repro.sh` from it by
adding the 9p mounts and `init=/init`, then boots qemu. A bug whose `run.sh`
needs a device set up first names it through the environment, and the script
says so before booting rather than after.

## Environment

| variable | points at |
|---|---|
| `CEDALION_IMAGE` | the base image to build from (default `cedalion-repro`) |
| `CEDALION_LINUX_URL` | the public kernel remote a missing commit is fetched from |
| `CEDALION_LINUX_CACHE` | the bare public mainline clone checkouts come out of; the base image sets this, and `--host` clones `./.cache/linux.git` when it is unset |
| `CEDALION_TIMEOUT` | how long to let the VM run (default 300s) |
| `CEDALION_ROOTFS` | the public kernelCTF image baked into the container |
| `CEDALION_BASE` | the site to fetch from (default `https://bugs.sh`) |
