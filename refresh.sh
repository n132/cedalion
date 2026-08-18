#!/bin/sh
# Rebuild the register and publish it.
#
# The site is built by Cloudflare from this repo, so publishing is a push:
# `python3 build.py` runs there, on their side, against whatever bugs.json this
# commit carries. Nothing here copies files anywhere, and docs/ stays ignored —
# it is build output, and the only machine that needs to produce it is the one
# doing the deploy. The repo itself stays private; only the built site is public.
#
#   ./refresh.sh            # extract, commit, push — Cloudflare rebuilds
#   ./refresh.sh --dry-run  # extract and stop, showing what changed
#
# What a push publishes, and why it is safe to, is written down in the README's
# "What is published" and enforced by check_published() in extract.py.
set -e
cd "$(dirname "$0")"

# See run.sh. It matters more here: this one commits and pushes, so an
# extraction that ran without the lore mirror or the CVE corpus would publish a
# register with the columns they fill silently blank.
[ -f .env ] && . ./.env

python3 extract.py

if [ "$1" = "--dry-run" ]; then
    git --no-pager diff --stat -- bugs.json
    python3 -c "
import json
d = json.load(open('bugs.json'))
print('  ', d['views'], 'cves:', d['counts']['cves'])"
    echo "(dry run — nothing committed)"
    exit 0
fi

# The extractor stamps a fresh generated_at every run, so a no-op refresh still
# dirties the file. Committing that would fill the history with commits that
# change one line and mean nothing — and each one triggers a rebuild.
if [ -z "$(git status --porcelain -- bugs.json)" ]; then
    echo "no change"
    exit 0
fi
if ! git diff --quiet -- bugs.json && \
   [ "$(git diff -U0 -- bugs.json | grep -c '^[-+][^-+]')" -eq 2 ]; then
    echo "only the timestamp moved — nothing to publish"
    git checkout -- bugs.json
    exit 0
fi

git add bugs.json
git commit -q -m "Refresh the register, $(date -u '+%Y-%m-%d')"
git push -q
echo "pushed: $(git log --oneline -1)"
echo "Cloudflare rebuilds from this commit; the site follows in a minute."
