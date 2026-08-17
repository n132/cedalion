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
| `CEDALION_TRIAGED` | directory of triaged bug reports |
| `CEDALION_TRIAGE` | directory of bugs still in triage |
| `CEDALION_CVE_DIR` | a clone of the kernel CVE corpus (`cve/published`) |
| `CEDALION_LORE_DB` | a local lore mirror's SQLite index |
| `CEDALION_STABLE_REPO` | a clone of the stable kernel, for a fix's subject |

## Disclosure

Nothing about a bug is public until it is named twice: once in
`disclose_allow.json`, which lists the bugs cleared to share, and again as an
individual file recorded in `artifacts.json`. Anything absent from that index
answers "request from todo@bugs.sh" — the default is deny, per bug and per
file.

`published/` holds the files themselves. `functions/b/[id]/[[path]].js` serves
them at `bugs.sh/b/<bug_id>/<artifact>`, which is the URL a mailed report
carries. Reports are immutable once sent, so that URL never changes: setting
`STORAGE_BASE` on the Pages project turns the same paths into redirects to a
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
    functions/      Cloudflare Pages Function serving artifacts
    web/            the register and the bug page
    published/      disclosed artifacts
    artifacts.json  what is disclosed, and where it lives
    disclose_allow.json   which bugs may be disclosed at all
