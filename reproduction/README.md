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
| `CEDALION_LINUX_CACHE` | the bare public mainline clone checkouts come out of; the base image sets this |
| `CEDALION_TIMEOUT` | how long to let the VM run (default 300s) |
| `CEDALION_ROOTFS` | the public kernelCTF image baked into the container |
| `CEDALION_BASE` | the site to fetch from (default `https://bugs.sh`) |
