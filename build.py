#!/usr/bin/env python3
"""Build the static site from the published register and indexed artifacts."""
from __future__ import annotations

import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WEB = os.path.join(HERE, "web")
OUT = os.path.join(HERE, "docs")

ASSETS = ("index.html", "reporting.html", "patch.html", "disclosure.html",
          "contributors.html", "contributors.js",
          "style.css", "cedalion.js",
          "bugpage.js", "logo.svg", "logo-light.svg", "favicon.svg")


def main() -> None:
    data = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 \
        else os.path.join(HERE, "bugs.json")
    if not os.path.isfile(data):
        sys.exit(f"no data to publish: {data}\n"
                 f"provide bugs.json, or pass a path to a published register")

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

    index = os.path.join(HERE, "artifacts.json")
    if os.path.isfile(index):
        with open(index) as f:
            entries = json.load(f)
        shutil.copy2(index, os.path.join(OUT, "artifacts.json"))
        dst = os.path.join(OUT, "a")
        shutil.rmtree(dst, ignore_errors=True)
        for bug_id, entry in entries.items():
            if entry.get("embargoed"):
                continue
            for name, key in (entry.get("files") or {}).items():
                if not key:
                    continue
                src = os.path.join(HERE, "published", bug_id, name)
                if not os.path.isfile(src):
                    sys.exit(f"artifacts.json names {bug_id}/{name}, which is "
                             f"not in published/ -- publish it or revoke it")
                out = os.path.join(dst, key)
                os.makedirs(os.path.dirname(out), exist_ok=True)
                shutil.copy2(src, out)

    open(os.path.join(OUT, ".nojekyll"), "w").close()

    n = len(ASSETS) + 2
    size = sum(os.path.getsize(os.path.join(OUT, f)) for f in os.listdir(OUT))
    print(f"{n} files -> {OUT}  ({size // 1024} KiB)")
    print(f"  data   : {data}")
    print(f"  check  : python3 -m http.server -d {OUT} 8000")
    print(f"  publish: push. Cloudflare runs this script and `wrangler deploy`,")
    print(f"           which uploads docs/ and the Worker beside it (see")
    print(f"           wrangler.jsonc). This puts the register on the public")
    print(f"           internet.")


if __name__ == "__main__":
    main()
