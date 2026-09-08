# Cedalion

https://bugs.sh

We have discovered a more efficient approach to finding vulnerabilities in the
Linux kernel. Because the manpower to review LLM-generated patches is limited,
we make low-severity bugs public and ask for the community's help patching them,
similar to syzbot.

bugs.sh presents each disclosed issue with a reproduction environment and a PoC
that triggers the reported vulnerability. This repository contains the public
data and the [reproduction script](reproduction/repro.sh).

If you are interested in helping the Linux kernel address these security issues,
visit https://bugs.sh. You can also reach
us at co@bugs.sh.

## Reproduce A Bug

Use [`reproduction/repro.sh`](reproduction/repro.sh):

Build the image:

```bash
reproduction/repro.sh build 4bda3bf8e1a2b780
```

Run it:

```bash
reproduction/repro.sh run 4bda3bf8e1a2b780
```

The built image is tagged as:

```text
n132/cedalion:co-4bda3bf8e1a2b780-vul
```

No host work directory is mounted. The image is built only from public inputs:
this repository, `bugs.sh` artifacts, the public Linux git remote, and the
public kernelCTF rootfs.

## Dataset (in-progress)

We are building an interactive reproduction dataset similar to
[ARVO](https://github.com/n132/ARVO-Meta/blob/main/2026155803.pdf).

Only public/patched (no race) bugs are included.

After an image has been pushed, another machine can reproduce the bug with one
Docker command:

```bash
docker run --rm --name co-4bda3bf8e1a2b780-vul --device /dev/kvm \
  n132/cedalion:co-4bda3bf8e1a2b780-vul run 4bda3bf8e1a2b780
```

Expected output:

![Expected docker run output](reproduction/assets/expected-output.png)

## More

Detailed reproduction notes are in [`reproduction/README.md`](reproduction/README.md).
