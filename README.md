https://bugs.sh

Cedalion is a register of Linux kernel bugs found by LLM-assisted source
analysis and confirmed by reproducing them on a real build. This repository is
the published data and the means to check it. Deciding what to disclose is done
elsewhere; nothing here reads a bug's artifacts or a private database.

## Running it

    ./run.sh                          # extract, build, serve on :60002

or one step at a time:

    export CEDALION_DB=...            # see below
    python3 extract.py                # rebuild bugs.json from the triage database
    python3 build.py                  # docs/ from web/ + bugs.json + published/
    python3 preview.py                # serve docs/ and the /b/<id> routes

`extract.py` takes every path from the environment and has no defaults, so this
file describes nothing about the machine it runs on. It exits naming the
variable if one is missing.

| variable | points at |
|---|---|
| `CEDALION_DB` | the triage SQLite database, opened read-only |
| `CEDALION_CVE_DIR` | a clone of the kernel CVE corpus (`cve/published`) |
| `CEDALION_LORE_DB` | a local lore mirror's SQLite index |

## Reporting a bug

Generating and mailing a report is not done here. It reads a bug's own working
directory -- the crash, the config, the reproducer, the tree it was built in --
and none of that is published, so the tool lives with the rest of the private
pipeline rather than in the repository that publishes the results:

    ~/KFC/claudeManager/co/mkbugreport.py <bug-dir> --trim-report

It writes `bugreport.eml` and `send-report.sh` and sends nothing. What reaches
this repository afterwards is what a report links to, and that arrives the same
way every other artifact does -- see below.

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
    preview.py      local server: docs/ and the /b/<id> routes
    worker.js       the Worker serving /b/<id>/<artifact>
    wrangler.jsonc  how it is deployed
    web/            the register and the bug page
    published/      disclosed artifacts
    artifacts.json  what is disclosed, and where it lives
    disclose_allow.json   which bugs may be disclosed at all

Everything here reads from three places and nowhere else: the triage database,
the kernel CVE corpus, and a lore mirror. The tools that act on a bug rather
than publish one -- mkbugreport.py, cfsend.py, publish.py -- live in
~/KFC/claudeManager/co/, because they read a bug's working directory and this
repository must not.
