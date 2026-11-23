# Docker Hub archive

The [Cedalion archive on Docker Hub](https://hub.docker.com/r/n132/cedalion/tags)
provides ready-to-run reproduction images for vulnerabilities that have an
assigned CVE or have been patched. The archive currently excludes race
conditions. The dataset is still being built. We will publish a release when
it is ready. An issue listed on bugs.sh does not necessarily have a published
image.

## Image tags and local IDs

Each bug has a bugs.sh local ID. A CVE tag is an alias associated with that ID.
For the example used throughout the documentation:

| CVE alias | bugs.sh local ID | Published report |
|---|---|---|
| `CVE-2026-89783` | `98dcb2414482df0b` | [report.eml](https://bugs.sh/b/98dcb2414482df0b/report.eml) |

The mapping is recorded in [`bugs.json`](../bugs.json), in the `cve` and
`bug_id` fields of the same entry. Patched vulnerabilities without CVEs are
also eligible for the archive; their tag convention is not yet documented.

## Run an archived reproducer

The host needs Docker and access to `/dev/kvm`:

```bash
docker run -it --rm --device /dev/kvm n132/cedalion:CVE-2026-89783 co vul
```

Docker downloads the image automatically if it is not already available
locally. Select a tag published in the Docker Hub archive.

## Commands

| Command | What it does |
|---|---|
| `co vul` | Runs the reproducer on the vulnerable kernel. |
| `co fix` | Runs the precompiled kernel at the patching commit. |
| `co patch` | Displays the related patch. |

Run the precompiled kernel at the patching commit:

```bash
docker run -it --rm --device /dev/kvm n132/cedalion:CVE-2026-89783 co fix
```

Display the related patch:

```bash
docker run --rm n132/cedalion:CVE-2026-89783 co patch
```

`co patch` does not boot a VM and does not need access to `/dev/kvm`.
