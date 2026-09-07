https://bugs.sh

Cedalion is a register of Linux kernel bugs found by LLM-assisted source
analysis and confirmed by reproducing them on a real build. This repository is
the published data and the means to check it. Deciding what to disclose is done
elsewhere; nothing here reads a bug's artifacts or a private database.

## Running it

    export CEDALION_DB=...            # see below
    python3 extract.py                # rebuild bugs.json from the triage database
    python3 build.py                  # docs/ from web/ + bugs.json + published/
    python3 app.py                    # or serve it locally on :60001
    python3 preview.py                # docs/ plus the /b/<id> routes, on :60002

`extract.py` takes every path from the environment and has no defaults, so this
file describes nothing about the machine it runs on. It exits naming the
variable if one is missing.

| variable | points at |
|---|---|
| `CEDALION_DB` | the triage SQLite database, opened read-only |
| `CEDALION_CVE_DIR` | a clone of the kernel CVE corpus (`cve/published`) |
| `CEDALION_LORE_DB` | a local lore mirror's SQLite index |
| `CEDALION_STABLE_REPO` | a clone of the stable kernel, for a fix's subject |

## Reproducing a bug

Every disclosed bug publishes what it takes to run it again, so `repro.sh`
needs nothing but the id:

    reproduction/repro.sh build 5e2bcf11e7027510
    reproduction/repro.sh run   5e2bcf11e7027510

`build` downloads `repro.c`, `config.gz` and `run.sh` into `./<bug_id>/`,
builds the kernel at the commit `artifacts.json` records for that bug, and
compiles the reproducer statically. `run` boots the two and looks for the
crash: it exits 0 when the console has one and 1 when the VM ran to the end
without it, and either way the full log is `<bug_id>/repro.log`.

Whatever the bug also publishes about itself -- `report.md`, `report.eml`,
`patch.diff` -- lands in the same directory, so what a bug is sits next to what
demonstrates it. None of it is needed to reproduce anything and a bug that
withholds one is not an error, which is why it is fetched separately from the
three files that are.

They are separate because building is minutes and booting is seconds, and a
bug that takes a few attempts to land should cost the second and not the first.
Both skip whatever is already done, so `build` after a failure resumes rather
than restarts; `-f` redoes it.

Both work inside the container `reproduction/Dockerfile` describes, which is built on first
use -- "it reproduces" should be a claim about a toolchain anyone can get
rather than one about the machine that made it. Everything that is the same for
every bug is a layer of it: the toolchain, qemu, the 650MB kernelCTF image, and
a bare clone of mainline. So the image is large and building it is slow, once,
and after that a bug costs its own kernel build and nothing else. `docker save`
it and someone else can reproduce a bug needing the network for three files.
`--host` uses what is installed here and clones into `./.cache/linux.git`
instead; `--shell` opens a shell in the container.

If the image may be stale, `--no-cache` rebuilds it with Docker's cache disabled
and pulls a fresh base image before running the requested command:

    reproduction/repro.sh --no-cache build 5e2bcf11e7027510

Nothing is read or written outside the directory it is run from -- that
directory is the container's `/work` and its only view of the machine, and the
work happens as the invoking uid, so what lands there belongs to whoever ran
it. A bug's `linux/` owns nothing but its refs; the objects come from the store
in the image, which stays read-only and shared. A commit newer than the image
-- it has aged, or the bug is not on mainline -- is fetched into that clone,
which is the writable half of the arrangement, so only what the store lacks
comes down. `rm -rf` is the whole cleanup story.

`run.sh` is left exactly as published -- it is the qemu line the bug was found
on, down to the cpu count and cmdline flags, and some of those the crash
depends on. What boots is `run-repro.sh`: that file plus two 9p mounts and
`init=/init`, which is how the reproducer gets in and gets run. A bug whose
`run.sh` needs a device set up first (a TPM socket, a usbredir channel) names
it through the environment, and the script says so before booting rather than
after.

| variable | points at |
|---|---|
| `CEDALION_IMAGE` | the image to build and work in (default `cedalion-repro`) |
| `CEDALION_LINUX_URL` | the kernel remote a missing commit is fetched from |
| `CEDALION_LINUX_CACHE` | the bare clone checkouts come out of; the image sets this to its own, and `--host` clones into `.cache/linux.git` |
| `CEDALION_TIMEOUT` | how long to let the VM run (default 300s) |
| `CEDALION_ROOTFS` | the kernelCTF image; in the container it is the one baked in, and on `--host` it is fetched once into `.cache/` |
| `CEDALION_BASE` | the site to fetch from (default `https://bugs.sh`) |

## Disclosure

Nothing about a bug is public until it is named twice: once in
`disclose_allow.json`, which lists the bugs cleared to share, and again as an
individual file recorded in `artifacts.json`. Anything absent from that index
answers "request from co@bugs.sh" — the default is deny, per bug and per
file.

`published/` holds the files themselves. `worker.js` serves
them at `bugs.sh/b/<bug_id>/<artifact>`, which is the URL a mailed report
carries. Reports are immutable once sent, so that URL never changes: setting
`STORAGE_BASE` on the Worker turns the same paths into redirects to a
storage provider, and everything already sent keeps resolving. The redirects
are 302, so no client caches a destination that may need to move.

A bug's page is its report and nothing else. Headings, code blocks, links and
the copy controls are presentation; anything about what the report *says*
belongs in the generator that writes it.

## Layout

    extract.py      bugs.json from the triage database (read-only)
    build.py        docs/ from web/, bugs.json and published/
    app.py          local server for the register
    preview.py      local server including the /b/<id> routes
    worker.js       the Worker serving /b/<id>/<artifact>
    wrangler.jsonc  how it is deployed
    web/            the register and the bug page
    published/      disclosed artifacts
    artifacts.json  what is disclosed, and where it lives
    disclose_allow.json   which bugs may be disclosed at all
    reproduction/   repro.sh, and the container it builds and runs itself in
