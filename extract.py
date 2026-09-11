#!/usr/bin/env python3
"""Extract the Cedalion bug list from the triage database. READ-ONLY.

This script never writes to that database and never touches a bug's artifacts —
before opening it read-only, it asks claudeManager to reconcile missing lore
Message-IDs.  That manager-owned hook is the only writer.
Its one output is bugs.json next to this file. It also reads the local kernel
CVE corpus for base scores and the stable clone for fixing-commit titles. Lore
Message-IDs are persisted in the database before extraction.

Per bug it produces:

  bug_id  the bug's hash_id, the identifier bugs are referred to by
  hash    sha256 of the report the database holds, i.e. a fingerprint of the
          report's exact content (NOT the same thing as hash_id, which
          identifies the bug rather than the text of its report)
  view    vulnerable | processing | patched — which tab it belongs to

Each view emits only its own columns; see the README.

Dismissed, Dup and manually-entered bugs are left out. So are scooped ones —
somebody upstream fixed the same defect first — which are counted instead:
the fix is not ours and neither is any CVE on it.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "bugs.json")

# Every path this reads comes from the environment. There are no defaults: a
# default is a description of one machine's layout, and this file is public.
# See the README for the variables and what each one points at.
def path(var: str) -> str:
    v = os.environ.get(var)
    if not v:
        sys.exit(f"{var} is not set -- see the README for the paths "
                 f"extract.py needs")
    return os.path.expanduser(v)


DB = path("CEDALION_DB")

# Kernel findings only. The database also carries chrome-v8 and chromium rows
# from the same pipeline; this register is about the kernel, so other repos are
# out. Older rows predate the column, hence the COALESCE to the default.
PROJECT_TYPE = "kernel"

EXCLUDED_STATES = ("Dismissed", "Dup")

# A finding is "scooped" when somebody upstream fixed the same defect before we
# got there. The marker lives in the free-text notes ("Scooped", "scooped:
# <commit>"), independently of state: of the 134, 116 were then dismissed.
#
# Dismissed means dismissed — those 116 are excluded with every other dismissed
# row, no exception. The rest are counted but not listed: the fix is not ours
# and neither is any CVE on it, so a row for one has nothing to show.
#
# Two things in the notes are NOT a scoop, and reading them as one was wrong:
#
#   * "Could be Scooped" is a suspicion, not an outcome. Three rows say only
#     that, all of them Reported — they belong in Processing, not dropped.
#   * A row carrying an ASSIGNED CVE is ours whatever the note says. One row
#     (CVE-2026-64048) has both, and dropping it put the register one CVE below
#     the manager's own count.
SCOOPED_NOTE = "%scoop%"
SCOOPED_MAYBE = "%could be scoop%"
SCOOPED_STATE = "Fixed by others"

# Two kinds of row are not findings of this pipeline, and both are identified
# by the shape of their id rather than by any column, because the database has
# no field that says where a bug came from:
#
#   * typed in by hand — a synthetic "manual-" + a 16-hex digest of the
#     description (see the manual-add endpoint in the triage tool);
#   * from syzbot — named by syzbot's own 40-hex sha1.
#
# The pipeline names its own findings with a bare 16-hex digest, so the three
# populations are told apart by id alone. That split is categorical rather than
# statistical, which is what makes it safe to filter on: all 1496 of the 16-char
# rows carry a report, and none of the 224 40-char rows carries one — there is
# no report because the crash was somebody else's to begin with. Two of the
# 40-char rows were already known as anomalies before the source of them was:
# the pair dropped from Patched for having nothing to show are both syzbot.
#
# Neither kind appears in Vulnerable or Processing. Both still contribute a CVE:
# an assigned CVE is this project's output whoever first tripped over the bug,
# and the register would understate itself by 11 without them. The exception is
# gated on the states that land in Patched, whose columns are cve / commit /
# cvss — so such a row contributes its number and nothing else, no foreign id
# and no hand-entered text.
#
# NB: the bugs table also has a `manual` column, and it is NOT the first of
# these — it is set on 1265 of the 1297 in-scope rows, so filtering on it would
# empty the list.
MANUAL_ID_PREFIX = "manual-"
SYZBOT_ID_LEN = 40

# A claimed CVE means the fix is already upstream, so "CVE Claimed" and "Fixed"
# describe the same place on the road. They are tallied as one category, named
# "Fixed" — the outcome rather than the paperwork.
STATE_ALIASES = {"CVE Claimed": "Fixed"}

# The three views on the findings page. A row publishes only which of these it
# is in — never the state name itself. "Exp Available" attached to a specific,
# still-unfixed id would tell a reader a working exploit exists for it, which is
# a different disclosure from "not fixed yet"; the view says only the latter.
VIEW_PATCHED = "patched"          # landed upstream, ours or somebody else's
VIEW_PROCESSING = "processing"    # a live bug we've chosen to extract something for
VIEW_VULNERABLE = "vulnerable"    # still live, nothing disclosed
_PATCHED_BY_STATE = {"Fixed": VIEW_PATCHED, "CVE Claimed": VIEW_PATCHED}

# The states that land in Patched — derived rather than written out again, so
# the CVE exception below cannot drift from this map.
PATCHED_STATES = tuple(_PATCHED_BY_STATE)

# co/disclose_allow.json — the same file publish.py gates on — read here too.
# Processing is not a triage state at all: it used to be "Reported" (sent
# upstream), but that conflated "we mailed it" with "we disclosed something
# about it", and those are different facts. The only thing that makes a row
# Processing instead of Vulnerable is being on this list: a live bug we have
# chosen to extract artifacts for. Everything else about it — its shape in
# this register — is identical to Vulnerable; see PUBLISHED below.
ALLOW_FILE = os.path.join(HERE, "disclose_allow.json")


def load_disclose_allow() -> set:
    try:
        with open(ALLOW_FILE) as f:
            return set(json.load(f))
    except (OSError, ValueError):
        return set()


def view_of(state: str, hash_id: str, allowed: set) -> str:
    if state in _PATCHED_BY_STATE:
        return VIEW_PATCHED
    return VIEW_PROCESSING if hash_id in allowed else VIEW_VULNERABLE


# The kernel CVE corpus, one JSON record per CVE, for the CVSS base score.
CVE_DIR = path("CEDALION_CVE_DIR")


def cvss_score(cve: str, _cache: dict = {}) -> str:
    """Base score from the published CVE record, read off disk.

    Offline: this reads the local corpus at CVE_DIR, never the network. A CVE
    with no record or no metrics comes back empty and prints as a dash.
    """
    if not cve:
        return ""
    if cve in _cache:
        return _cache[cve]
    score = ""
    try:
        year = cve.split("-")[1]
        with open(os.path.join(CVE_DIR, year, cve + ".json")) as f:
            rec = json.load(f)
        metrics = rec.get("containers", {}).get("cna", {}).get("metrics") or []
        for m in metrics:
            for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
                base = (m.get(key) or {}).get("baseScore")
                if base is not None:
                    score = f"{float(base):g}"
                    break
            if score:
                break
    except (OSError, ValueError, TypeError, IndexError, json.JSONDecodeError):
        score = ""
    _cache[cve] = score
    return score


# cgit link to the fixing commit: .../commit/?id=<hash>
_COMMIT_LINK_RE = re.compile(r"id=([0-9a-f]{7,40})", re.IGNORECASE)


def fix_commit_of(link: str | None) -> str:
    m = _COMMIT_LINK_RE.search(link or "")
    return short(m.group(1).lower()) if m else ""


# The local kernel clone the fixing commits are resolved against.
STABLE_REPO = path("CEDALION_STABLE_REPO")


def commit_title(sha: str, _cache: dict = {}) -> str:
    """Subject line of a fixing commit, read from the local clone.

    Offline: this reads STABLE_REPO, never the network. A commit not in that
    tree comes back empty and prints as a dash. The subject of a merged commit
    is public the moment it lands, so publishing it discloses nothing.
    """
    if not sha:
        return ""
    if sha in _cache:
        return _cache[sha]
    title = ""
    if os.path.isdir(STABLE_REPO):
        try:
            p = subprocess.run(
                ["git", "-C", STABLE_REPO, "log", "-1", "--format=%s", sha],
                capture_output=True, text=True, timeout=30,
            )
            if p.returncode == 0:
                title = p.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            title = ""
    _cache[sha] = title
    return title


def own_finding(hash_id: str) -> bool:
    """Whether this row is one of ours, told by the shape of its id.

    A bare 16-hex digest is this pipeline's own. The two other populations are
    a hand-entered `manual-` row and syzbot's 40-hex sha1 — both reach Patched
    when they carry a CVE, and neither has a bug id worth publishing: syzbot's
    names somebody else's finding, `manual-` names nothing at all, and no
    artifact exists under either, so both would only 404 on /b/<id>.
    """
    return not (hash_id.startswith(MANUAL_ID_PREFIX)
                or len(hash_id) == SYZBOT_ID_LEN)


def report_hash_of(report: str | None) -> str:
    """Fingerprint of a bug's report, from the database's own copy of it.

    This used to sha256 a report.md off disk, out of one of two triage
    directories. That made the fingerprint depend on a layout that exists on
    exactly one machine, and on a tree nothing maintains: of the rows in scope,
    the first directory held 772 and the second 1196, they overlapped on 804,
    and 49 bugs were in neither. The database is the store that is actually kept
    — every row has passed through it, and it is what gets backed up — so the
    fingerprint is taken there.

    The two disagree on 148 of 1307 rows, and only ever by whitespace: the
    triage tool's copy is missing a newline ahead of a `## ` heading that the
    file on disk has. Same report, different digest, so the switch does move
    those 148 values. It moves nothing that has been handed out: of the bugs
    disclosed so far, every one hashes identically from either source.
    """
    return hashlib.sha256(report.encode()).hexdigest() if report else ""


# How long an identifier reads on the page: 16 hex, enough to keep bug IDs
# useful as stable lookup keys while still keeping dense columns readable.
# Applied to the bug id, the report hash and the fix commit alike so the
# columns read as one kind of thing. Verified collision-free across
# the current set.
#
# Processing's bug id and Patched's commit are cut HERE, so what is published is
# what is shown. A Vulnerable row is the exception: it carries both values in
# full and the page cuts them for display. Those two fields are the entire row —
# with no title, no path and no description beside them, a truncated value is
# the only thing a reader has, and 12 hex is not enough to do the one check the
# fingerprint exists for (sha256 a report.md and compare) or to look an id up by
# anything but a prefix search. Publishing the full digest costs nothing the
# prefix did not already cost: both confirm a report you already hold, and
# neither yields one you do not.
ID_LEN = 16


def short(value: str) -> str:
    return (value or "")[:ID_LEN]


# Rank used to pick which member of a link group represents it: the furthest
# along the pipeline wins, since that is the row carrying the real outcome.
_STATE_RANK = {
    "Fixed": 6, "CVE Claimed": 5, "Reported": 4, SCOOPED_STATE: 3,
    "Exp Available": 2, "PoC Available": 1, "Crash Available": 0,
}


def collapse_link_groups(rows):
    """Collapse each link group to a single finding.

    `linked_ids` holds the other hash_ids a bug is linked to — the same defect
    reached more than once. Counting every member separately inflates the list:
    31 groups here, worth 37 extra rows. One row per group is the honest count.

    Returns (representative_rows, merged_away_count). The representative is the
    member furthest along the pipeline, breaking ties on the newest DB id, so a
    group that reached "CVE Claimed" is not represented by its "PoC Available"
    sibling.
    """
    by_hash = {r[1]: r for r in rows}

    # Union the groups transitively: A may name B while C names A.
    parent = {h: h for h in by_hash}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for r in rows:
        hash_id, linked = r[1], r[3]
        for other in (linked or "").split():
            if other in by_hash:          # ignore links to out-of-scope bugs
                union(hash_id, other)

    groups: dict[str, list] = {}
    for r in rows:
        groups.setdefault(find(r[1]), []).append(r)

    reps = []
    for members in groups.values():
        members.sort(key=lambda r: (_STATE_RANK.get(r[2], -1), r[0]), reverse=True)
        reps.append(members[0])
    reps.sort(key=lambda r: r[0], reverse=True)   # newest first, as before
    return reps, len(rows) - len(reps)


# What each view is allowed to publish, checked rather than trusted before
# anything is written. bugs.json is handed to the browser verbatim by
# /api/bugs, so a field added to the wrong branch is a disclosure the moment it
# lands — and the three branches that build these rows sit sixty lines apart,
# where nothing sees them together. This does.
PUBLISHED = {
    VIEW_VULNERABLE: {"view", "bug_id", "hash"},
    # Processing is Vulnerable's shape plus one field. It is not "posted to
    # the list, so title and patch are already public" any more — that reasoning
    # left with the state-based view — it is still a live, unfixed bug, and the
    # opaque check below now runs on it same as Vulnerable. `lore` is the one
    # addition, and it is not exempt from disclosing something: a link only
    # exists once a message is actually public, so pointing at it discloses
    # nothing the message itself has not already.
    VIEW_PROCESSING: {"view", "bug_id", "hash", "lore"},
    VIEW_PATCHED:    {"view", "bug_id", "cve", "commit", "title", "cvss"},
}

# A Vulnerable or Processing row names a live, unfixed bug, so every value on
# one has to be an opaque digest and nothing else: no path, no function, no
# crash text, no description — `lore` is the one named exception, checked for
# presence only (it is a lore message-id or a blank, never a digest). Patched
# describes a fix that already landed, which is why only these two are checked
# for shape as well as for shape's absence.
#
# The bound is a sha256's 64 hex, the longest digest either view carries, and
# not ID_LEN: these fields are published whole and cut by the page. It still
# does the job the check is here for, which is to catch a value that is not a
# digest at all — a title, a path, a sentence — rather than to measure one.
_OPAQUE = re.compile(r"[0-9a-f]{0,64}")
_OPAQUE_EXEMPT = {"view", "lore"}


def check_published(bugs: list) -> None:
    """Refuse to write a row carrying more than its view may publish."""
    for b in bugs:
        allowed = PUBLISHED.get(b.get("view"))
        if allowed is None:
            sys.exit(f"refusing to write: unknown view {b.get('view')!r}")
        extra = sorted(set(b) - allowed)
        if extra:
            sys.exit(f"refusing to write: a {b['view']} row carries {extra}, "
                     f"which that view does not publish")
        if b["view"] not in (VIEW_VULNERABLE, VIEW_PROCESSING):
            continue
        for k, v in b.items():
            if k not in _OPAQUE_EXEMPT and not _OPAQUE.fullmatch(str(v)):
                sys.exit(f"refusing to write: {k} on a {b['view']} row is not "
                         f"an opaque digest ({v!r}) — that view names live bugs")


def collect() -> dict:
    if not os.path.exists(DB):
        sys.exit(f"database not found: {DB}")

    # Lore discovery and database writes belong to claudeManager.  Run its
    # idempotent pre-extract reconciliation before this process opens the same
    # database read-only.  A standalone cedalion checkout may omit the hook;
    # in the integrated tree its failure is fatal so a publish cannot silently
    # drop a newly confirmed public link.
    manager = os.path.expanduser(os.environ.get(
        "CLAUDE_MANAGER_DIR", os.path.join(HERE, "..", "claudeManager")))
    reconcile = os.path.join(manager, "tools", "reconcile_lore_msgids.py")
    if os.path.isfile(reconcile):
        result = subprocess.run(
            [sys.executable, reconcile, "--db", DB, "--register", OUT],
            text=True, capture_output=True,
        )
        if result.returncode:
            sys.exit(
                "claudeManager lore reconciliation failed: "
                + (result.stderr.strip() or result.stdout.strip() or "unknown error")
            )

    conn = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
    placeholders = ",".join("?" for _ in EXCLUDED_STATES)
    patched_states = ",".join("?" for _ in PATCHED_STATES)
    allowed = load_disclose_allow()
    rows = conn.execute(
        f"""SELECT id, hash_id, state, linked_ids,
                   (lower(COALESCE(notes, '')) LIKE ?
                    AND lower(COALESCE(notes, '')) NOT LIKE ?
                    AND trim(COALESCE(cve_number, '')) = '') AS scooped,
                   cve_number, commit_link, report,
                   COALESCE(lore_msgid, '') AS lore_msgid
            FROM bugs
            WHERE ((hash_id NOT LIKE ? AND length(hash_id) != ?)
                   OR (state IN ({patched_states})
                       AND trim(COALESCE(cve_number, '')) != ''))
              AND COALESCE(project_type, 'kernel') = ?
              AND state NOT IN ({placeholders})
            ORDER BY id DESC""",
        (SCOOPED_NOTE, SCOOPED_MAYBE, MANUAL_ID_PREFIX + "%", SYZBOT_ID_LEN,
         *PATCHED_STATES, PROJECT_TYPE, *EXCLUDED_STATES),
    ).fetchall()

    # Printed rather than published: these are numbers about what is NOT on the
    # register, and an aggregate no page draws is still served to anyone who
    # fetches the JSON. Both halves are printed because the interesting one is
    # the second: a row kept for its CVE alone is the exception working.
    foreign = conn.execute(
        f"""SELECT (hash_id LIKE ?) AS by_hand,
                   trim(COALESCE(cve_number, '')) != '' AS has_cve,
                   COUNT(*)
              FROM bugs
             WHERE (hash_id LIKE ? OR length(hash_id) = ?)
               AND COALESCE(project_type, 'kernel') = ?
               AND state NOT IN ({placeholders})
             GROUP BY 1, 2""",
        (MANUAL_ID_PREFIX + "%", MANUAL_ID_PREFIX + "%", SYZBOT_ID_LEN,
         PROJECT_TYPE, *EXCLUDED_STATES)).fetchall()
    for by_hand, has_cve, n in sorted(foreign):
        kind = "hand-entered" if by_hand else "syzbot"
        why = "kept for its CVE" if has_cve else "left out"
        print(f"  {kind:12} : {n} {why}")

    # Scooped overrides whatever state the row was left in — it is the outcome
    # that actually happened. `notes` itself is never published; it is read here
    # only to classify.
    # collapse_link_groups() reads this tuple by position (id, hash_id, state,
    # linked_ids), so nothing may be inserted ahead of those four.
    rows = [(i, h, SCOOPED_STATE if sc else st, li, cv, cl, rp, lm)
            for i, h, st, li, sc, cv, cl, rp, lm in rows]

    conn.close()

    rows, merged = collapse_link_groups(rows)

    bugs = []
    states: dict[str, int] = {}
    missing_report = 0
    scooped = 0
    incomplete = 0
    cves_seen = set()
    fixes_seen = set()
    for (_id, hash_id, state, _linked, cve,
         commit_link, report, lore_msgid) in rows:
        # Taken for every row, not just the Vulnerable ones that publish the
        # fingerprint: `with a report` counts the whole register, so skipping
        # the others would report them all as missing.
        report_hash = report_hash_of(report)
        if not report_hash:
            missing_report += 1

        # Scooped findings are counted, not listed. Somebody upstream fixed the
        # same defect first, so the fix is not ours and neither is any CVE on it
        # — 133 of the 134 carry no CVE number, and listing them under Patched
        # inflated that tab from 88 to 212 with rows that had nothing to show.
        # The count is the honest thing to publish, and it keeps 124 rows out of
        # a document served without authentication.
        if state == SCOOPED_STATE:
            scooped += 1
            continue

        view = view_of(state, hash_id, allowed)
        s = STATE_ALIASES.get(state or "", state or "Unknown")
        states[s] = states.get(s, 0) + 1

        # A row carries EXACTLY the columns its own view draws, and nothing
        # else: bugs.json is handed to the browser verbatim by /api/bugs, so a
        # field is published whether or not the page paints it.
        #
        # Vulnerable and Processing are the same shape — a live, unfixed bug is
        # a live, unfixed bug whether or not co/disclose_allow.json names it —
        # plus the one field Processing adds: `lore`, a link to a message that
        # is already public wherever it lives, so pointing at it discloses
        # nothing the message itself has not already.
        #
        # The bug's own `description` from the database is not read at all. It
        # was written for triage, not for the list, and it says things no
        # published artifact does.
        if view == VIEW_VULNERABLE:
            # No date. `first_added_at` is when the row reached the triage tool,
            # not when the bug was found — it moves in scan-sized batches (605
            # rows share one month, 246 share five days), so an age computed
            # from it dated the scan and not the finding. There is no column in
            # the database that dates the finding itself, so rather than publish
            # a number that reads like one and is not, the view shows none.
            bugs.append({
                "view": view,
                "bug_id": hash_id,
                "hash": report_hash,
            })
        elif view == VIEW_PROCESSING:
            bugs.append({
                "view": view,
                # Full, same as Vulnerable — not cut with short(): a Processing
                # row is a Vulnerable row that happens to be on the allow list,
                # not a different kind of identity.
                "bug_id": hash_id,
                "hash": report_hash,
                # Discovery is performed and persisted by claudeManager before
                # extraction.  Cedalion publishes the canonical value only.
                "lore": lore_msgid,
            })
        else:
            cve_id = (cve or "").strip().upper()
            if cve_id:
                cves_seen.add(cve_id)
            fix = fix_commit_of(commit_link)
            # Every column in this view derives from the CVE or the commit, so a
            # row with neither draws four dashes and says nothing. Two records
            # are in that state: marked Fixed, with commit_link, cve_number and
            # description all empty and only "CVE Claimed" typed in the notes.
            # Filling in either field in the triage tool brings the row back.
            if not cve_id and not fix:
                incomplete += 1
                states[s] -= 1    # not listed, so not counted as fixed either
                continue

            # One row per FIX. A bug is what a row IS — that is why the id below
            # is on it, and why nothing here merges two rows for sharing a value
            # in general. But this tab answers "what got fixed", and a fix is one
            # fix however many findings reached it: two rows carrying the same
            # commit and the same CVE read as the register double-counting.
            #
            # Keyed on the CVE where there is one and the commit otherwise, not
            # on the CVE alone — 108 distinct commits are shared by 16 bug pairs
            # against the CVE's 15, and the extra pair landed without a number.
            # Neither key fires today: linked_ids already merges all 16 upstream
            # of here. This is the guard for the pair that is not linked yet.
            #
            # The survivor is the first seen under `ORDER BY id DESC`, the newest
            # row — the same tie-break collapse_link_groups() uses.
            fix_key = cve_id or fix
            if fix_key in fixes_seen:
                states[s] -= 1    # not listed, so not counted as fixed either
                continue
            fixes_seen.add(fix_key)

            bugs.append({
                "view": view,
                # The bug's own id, as on the other two tabs. The page does not
                # draw it here — a row that has a CVE is named by its CVE, which
                # is the name the rest of the world uses — but the row is still
                # a bug, and this is what says which one: it keys the artifacts
                # and it is the /b/<id> the mailed report points at.
                #
                # Empty on a row that is here for its CVE alone. Those 13 are
                # syzbot's findings and hand-entered numbers; the exception that
                # lets them in is that they contribute a CVE and nothing else,
                # and an id is something else.
                "bug_id": short(hash_id) if own_finding(hash_id) else "",
                "cve": cve_id,
                "commit": fix,
                "title": commit_title(fix),
                "cvss": cvss_score(cve_id),
            })

    # Aggregates only, and only for what the page actually shows: a count per
    # stage. Bug types are deliberately not emitted — the page dropped that
    # section, and an aggregate nobody displays is still published to anyone who
    # fetches the JSON.
    #
    # The CVE list went the same way. The Info page no longer carries a CVE
    # table — the numbers live on the rows they belong to, in the Patched view —
    # so the list of fixing commits and their subject lines is not published at
    # all any more. Only the count remains, and it now counts the CVEs actually
    # on the register's own rows.
    return {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "counts": {
            "bugs": len(bugs),
            "with_report": len(bugs) - missing_report,
            "fixed": states.get("Fixed", 0),
            # Everything that reached upstream. A fixed finding was necessarily
            # reported first, so counting only the rows still sitting in
            # "Reported" understates it — they are successive points on the same
            # road, not alternatives.
            "reported": states.get("Reported", 0) + states.get("Fixed", 0),
            "scooped": scooped,
            "incomplete": incomplete,
            "merged_links": merged,
            "cves": len(cves_seen),
        },
        "states": states,
        "views": {
            VIEW_VULNERABLE: sum(1 for b in bugs if b["view"] == VIEW_VULNERABLE),
            VIEW_PROCESSING: sum(1 for b in bugs if b["view"] == VIEW_PROCESSING),
            VIEW_PATCHED: sum(1 for b in bugs if b["view"] == VIEW_PATCHED),
        },
        "bugs": bugs,
    }


def main() -> None:
    data = collect()
    # Before the file exists, not after: the check is worth nothing if the
    # thing it guards has already been written where a server can serve it.
    check_published(data["bugs"])
    tmp = OUT + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=1)
    os.replace(tmp, OUT)  # atomic, so a reader never sees a half-written file
    c = data["counts"]
    print(f"{c['bugs']} bugs -> {OUT}")
    print(f"  with report.md : {c['with_report']}")
    # Not a published count — the page has no place for it — but the operator
    # needs it: a missing value means claudeManager has not yet persisted the
    # report's public Message-ID (or the row is a legacy report with no link).
    proc = [b for b in data["bugs"] if b["view"] == VIEW_PROCESSING]
    placed = sum(1 for b in proc if b["lore"])
    print(f"  on lore        : {placed}/{len(proc)} processing rows")


if __name__ == "__main__":
    main()
