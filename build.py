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

import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WEB = os.path.join(HERE, "web")
OUT = os.path.join(HERE, "docs")

# Everything the page loads. Named rather than globbed, for the same reason
# app.py names its routes: a stray file in web/ should not become published by
# having been dropped there.
ASSETS = ("index.html", "style.css", "cedalion.js",
          "logo.svg", "logo-light.svg", "favicon.svg")


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

    # Pages runs Jekyll over the site unless told not to, and Jekyll drops any
    # file or directory whose name starts with an underscore. Nothing here does
    # today, but the failure is silent when it happens.
    open(os.path.join(OUT, ".nojekyll"), "w").close()

    n = len(ASSETS) + 2
    size = sum(os.path.getsize(os.path.join(OUT, f)) for f in os.listdir(OUT))
    print(f"{n} files -> {OUT}  ({size // 1024} KiB)")
    print(f"  data   : {data}")
    print(f"  check  : python3 -m http.server -d {OUT} 8000")
    print(f"  publish: git add -f docs && git commit && git push, then set")
    print(f"           Pages to deploy from the docs/ folder. This puts the")
    print(f"           register on the public internet — see the note in this")
    print(f"           script before doing it.")


if __name__ == "__main__":
    main()
