# Cedalion (bugs.sh)

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

## Reproduce a bug

```bash
# Build the image
reproduction/repro.sh build 4bda3bf8e1a2b780
# Run it
reproduction/repro.sh run 4bda3bf8e1a2b780
```

## Docker Hub archive

We are building an archive of ready-to-run reproduction images for
vulnerabilities that have an assigned CVE or have been patched. The archive
currently excludes race conditions.

For example, reproduce `CVE-2026-89783`, corresponding to bugs.sh local ID
`98dcb2414482df0b`:

```bash
docker run -it --rm --device /dev/kvm n132/cedalion:CVE-2026-89783 co vul
```

Replace `co vul` with `co fix` to run the precompiled kernel at the patching commit,
or with `co patch` to display the related patch.

The CVE tag is an alias associated with the local ID. Docker downloads the image
automatically when needed. The host requires Docker and access to `/dev/kvm`.
The dataset is still being built. We will publish a release when it is ready.

See [the archive guide](archive/README.md) for image tags and usage.

## More

Detailed reproduction notes are in [`reproduction/README.md`](reproduction/README.md).
