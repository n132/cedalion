#!/usr/bin/env python3
"""Assemble the static site into docs/, for GitHub Pages or any file host.

The register is a table drawn in the browser from one JSON document, so it does
not need a server: app.py exists to serve that document over the LAN, not to
compute anything. Copying web/ and bugs.json into one directory is the whole
build.

    python3 build.py                  # docs/ from ./bugs.json
    python3 build.py path/to/bugs.json

Nothing is rewritten on the way. The page asks for its stylesheet, its script
and `bugs.json` by relative path, so the same index.html works at a domain root,
under a project path like /cedalion/, and from a file:// directory. If that ever
stops being true, this script is not the place to patch it — the page is.

WHAT THIS PUBLISHES. docs/bugs.json is the register itself, and putting it on a
public Pages site puts it on the open internet, where it will be crawled and
cached. That is a disclosure decision, not a build step:

  * Vulnerable rows carry an opaque bug id and a report fingerprint, nothing
    else — no path, no description, no PoC. extract.py's check_published()
    refuses to write anything more.
  * Processing and Patched rows carry titles, message-ids, diffs and CVE
    numbers that are already public on lore and in the kernel's own history.

So the file is safe to publish by its own rules. It is still the whole register,
including the count of what is unfixed, and the repo's .gitignore keeps it out
of git for that reason. docs/ is ignored too; publishing means deliberately
adding it, and this script says so rather than deciding for you.
"""
from __future__ import annotations

import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WEB = os.path.join(HERE, "web")
OUT = os.path.join(HERE, "docs")

# Everything the page loads. Named rather than globbed, for the same reason
# app.py names its routes: a stray file in web/ should not become published by
# having been dropped there.
ASSETS = ("index.html", "reporting.html", "style.css", "cedalion.js",
          "bugpage.js", "logo.svg", "logo-light.svg", "favicon.svg")


def main() -> None:
    data = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 \
        else os.path.join(HERE, "bugs.json")
    if not os.path.isfile(data):
        sys.exit(f"no data to publish: {data}\n"
                 f"run `python3 extract.py` first, or pass a bugs.json path")

    os.makedirs(OUT, exist_ok=True)
    for name in ASSETS:
        src = os.path.join(WEB, name)
        if not os.path.isfile(src):
            sys.exit(f"missing asset: {src}")
        shutil.copy2(src, os.path.join(OUT, name))
    shutil.copy2(data, os.path.join(OUT, "bugs.json"))
    allow = os.path.join(HERE, "disclose_allow.json")
    if os.path.isfile(allow):
        shutil.copy2(allow, os.path.join(OUT, "disclose_allow.json"))

    # Disclosed artifacts, copied ONE BY ONE off the index rather than as a
    # tree. The index is the only thing that decides, in both places a file can
    # be reached from -- and there are two, which is why this is not a copytree.
    #
    #   /b/<id>/<file>   the URL a mailed report carries. worker.js
    #                    reads artifacts.json and answers 404 for anything not
    #                    in it, 403 for an embargoed bug.
    #   /a/<id>/<file>   where the bytes sit. Served as a plain static path, by
    #                    the host, with no function in front of it and so no
    #                    index consulted.
    #
    # Copying the tree published everything under published/ at /a/ whatever
    # artifacts.json said. A file dropped in that directory and never passed to
    # publish.py was live; an embargoed bug answered 403 at /b/ and handed the
    # file over at /a/. The gate was on one door of two.
    #
    # This also outlives /a/ itself: setting STORAGE_BASE moves artifacts to a
    # provider and the function stops reading /a/ at all, but a copytree here
    # would go on publishing that directory to a site nothing reads it from.
    index = os.path.join(HERE, "artifacts.json")
    if os.path.isfile(index):
        with open(index) as f:
            entries = json.load(f)
        # report.md used to be refused outright here, while the analysis was
        # a triage document with nothing in it written for a maintainer. What
        # publish.py indexes under that name now is a deliberate cut of it,
        # and it gets there only by passing that tool's checks. This build
        # decides nothing either way: a bug carries the analysis if the index
        # says so, and one that never had a cut made still names it null and
        # answers "not public yet".
        shutil.copy2(index, os.path.join(OUT, "artifacts.json"))
        dst = os.path.join(OUT, "a")
        shutil.rmtree(dst, ignore_errors=True)
        for bug_id, entry in entries.items():
            # An embargoed bug is answered 403 by the function, which only
            # works while the bytes are not also sitting at a static path.
            if entry.get("embargoed"):
                continue
            for name, key in (entry.get("files") or {}).items():
                # Named with no key: listed so a reader knows the artifact
                # exists, withheld until it is cleared. There are no bytes to
                # copy, and there must not be -- /b/ answers 403 for it, which
                # is only true while nothing sits at a static path.
                if not key:
                    continue
                src = os.path.join(HERE, "published", bug_id, name)
                if not os.path.isfile(src):
                    sys.exit(f"artifacts.json names {bug_id}/{name}, which is "
                             f"not in published/ -- publish it or revoke it")
                # The key is the path the function fetches under /a/. Writing to
                # exactly that path is what keeps the two in agreement; a key
                # that disagrees with the file's own name would 404 at /b/ while
                # the file sat there under another name.
                out = os.path.join(dst, key)
                os.makedirs(os.path.dirname(out), exist_ok=True)
                shutil.copy2(src, out)

    # Pages runs Jekyll over the site unless told not to, and Jekyll drops any
    # file or directory whose name starts with an underscore. Nothing here does
    # today, but the failure is silent when it happens.
    open(os.path.join(OUT, ".nojekyll"), "w").close()

    n = len(ASSETS) + 2
    size = sum(os.path.getsize(os.path.join(OUT, f)) for f in os.listdir(OUT))
    print(f"{n} files -> {OUT}  ({size // 1024} KiB)")
    print(f"  data   : {data}")
    print(f"  check  : python3 -m http.server -d {OUT} 8000")
    print(f"  publish: push. Cloudflare runs this script and `wrangler deploy`,")
    print(f"           which uploads docs/ and the Worker beside it (see")
    print(f"           wrangler.jsonc). This puts the register on the public")
    print(f"           internet — see the note at the top of this script.")


if __name__ == "__main__":
    main()
