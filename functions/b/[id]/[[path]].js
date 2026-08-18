// Artifact resolution for bug reports.
//
// Reports mailed to public lists are immutable -- whatever URL they carry is
// in the LKML archive forever. So they carry bugs.sh/b/<bug_id>/<artifact>
// and this function decides what that means today. Moving to a different
// storage provider later is a change to STORAGE_BASE, not to any URL that has
// already been published.
//
//   /b/<id>                 -> the bug's page on the site
//   /b/<id>/<artifact>      -> 302 to wherever the artifact currently lives
//
// Phase 1 (no storage yet): artifacts.json is absent or has no entry, and
// every artifact request answers "mail co@bugs.sh". Nothing else changes
// when storage arrives.

const CONTACT = "co@bugs.sh";

// 302, never 301. A permanent redirect is cached by browsers and
// intermediaries with no way to invalidate it, so a later provider move would
// strand every client that had cached the old target.
const REDIRECT = 302;

let manifestCache = null;

async function manifest(env) {
  if (manifestCache) return manifestCache;
  try {
    const res = await env.ASSETS.fetch(new URL("/artifacts.json", "https://bugs.sh"));
    manifestCache = res.ok ? await res.json() : {};
  } catch {
    manifestCache = {};
  }
  return manifestCache;
}

function page(id, entry) {
  // The page is the report. Anything that should read differently is a change
  // to the generator, not to this file.
  const has = entry && !entry.embargoed && "report.eml" in (entry.files || {});

  const body = has
    ? `<div id="report" data-src="/b/${id}/report.eml">loading…</div>
       <script src="/bugpage.js"></script>`
    : `<p class="none">The report for this bug is not public yet.</p>`;

  return new Response(
    `<!doctype html><meta charset="utf-8">
     <meta name="viewport" content="width=device-width,initial-scale=1">
     <title>${id} — cedalion</title>
     <link rel="stylesheet" href="/style.css">
     <link rel="icon" href="/favicon.svg">
     <body class="bug">
     <main class="bugpage">
       <p><a href="/#vulnerable">&larr; register</a></p>
       ${body}
     </main>`,
    { status: has ? 200 : 404,
      headers: { "content-type": "text/html; charset=utf-8" } });
}

const text = (body, status) =>
  new Response(body + "\n", {
    status,
    headers: { "content-type": "text/plain; charset=utf-8" },
  });

export async function onRequest({ params, env }) {
  const id = params.id;
  if (!/^[0-9a-f]{8,64}$/.test(id)) return text("bad bug id", 400);

  // Path segments after the id; absent for a bare /b/<id>.
  const parts = [].concat(params.path || []).filter(Boolean);

  const entry = (await manifest(env))[id];

  // A bare /b/<id> is where a mailed report points and where the register
  // links: it has to say something useful whether or not anything is public.
  if (parts.length === 0) return page(id, entry);

  const name = parts.join("/");

  if (!entry) {
    return text(
      `No artifacts published for ${id} yet.\n` +
        `Request them from ${CONTACT}, quoting the bug id.`,
      404,
    );
  }

  if (entry.embargoed) {
    return text(
      `Artifacts for ${id} are under embargo pending upstream fixes.\n` +
        `Request access from ${CONTACT}, quoting the bug id.`,
      403,
    );
  }

  const files = entry.files || {};

  // Named with no key: the artifact exists and is deliberately not disclosed
  // yet. Distinct from a name that is absent, which is "no such artifact" --
  // this one says the file is real and the answer is "not yet", so nobody has
  // to guess whether it is worth asking for.
  if (name in files && !files[name]) {
    return text(
      `"${name}" for ${id} is not public yet.\n` +
        `Request it from ${CONTACT}, quoting the bug id.`,
      403,
    );
  }

  const key = files[name];
  if (!key) {
    const have = Object.keys(files).sort().join(", ") || "none";
    return text(`No artifact "${name}" for ${id}. Available: ${have}`, 404);
  }

  // Until a storage provider exists, disclosed artifacts are served from the
  // site itself under /a/. When STORAGE_BASE is set they move there instead --
  // the URL a report carries does not change either way.
  const base = (env.STORAGE_BASE || "").replace(/\/+$/, "");
  if (base) return Response.redirect(`${base}/${key}`, REDIRECT);

  const res = await env.ASSETS.fetch(new URL(`/a/${key}`, "https://bugs.sh"));
  // An extensionless artifact is guessed as a binary stream and offered as a
  // download; these are text and worth reading in place.
  const ct = res.headers.get("content-type") || "";
  if (!ct || ct.startsWith("application/octet-stream")) {
    const out = new Response(res.body, res);
    out.headers.set("content-type", "text/plain; charset=utf-8");
    return out;
  }
  return res;
}
