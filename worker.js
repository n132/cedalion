// Artifact resolution for bug reports.
//
// Reports mailed to public lists are immutable -- whatever URL they carry is
// in the LKML archive forever. So they carry bugs.sh/b/<bug_id>/<artifact>
// and this Worker decides what that means today. Moving to a different
// storage provider later is a change to STORAGE_BASE, not to any URL that has
// already been published.
//
// A Worker, not a Pages Function, and the distinction is not cosmetic. This
// lived at functions/b/[id]/[[path]].js, which is Pages' file-based routing --
// and the site is deployed with `wrangler deploy`, which is Workers. Wrangler
// saw the directory, asked whether this was a Pages project, and answered its
// own question with the non-interactive default:
//
//     ? We have identified a `functions` directory ... Is this correct?
//     Using fallback value in non-interactive context: no
//
// So docs/ went up as static files and the routing was never compiled. Every
// /b/ URL 404ed with an empty body -- indistinguishable from a typo -- while
// the bytes sat reachable under /a/. The lesson is in wrangler.jsonc beside
// this: with no config committed, the deploy is whatever a robot guessed.
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

// The one route this Worker owns. Everything else on the site is a file and is
// answered by the asset store before this runs -- so /, /bugs.json, /style.css
// and the artifacts under /a/ never reach here.
//
// The id is read out of the path rather than handed over by the platform. On
// Pages the filename did it: functions/b/[id]/[[path]].js bound `params.id` and
// `params.path` by directory name. A Worker has no such routing, so the same
// two values come from one regex -- deliberately the one preview.py already
// uses, since the two have to agree about what a bug URL is.
const BUG_PATH = /^\/b\/([0-9a-f]{8,64})(?:\/(.+))?\/?$/;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const m = BUG_PATH.exec(url.pathname);
    // Not a bug URL. Assets are served ahead of the Worker, so arriving here
    // means no such file: hand it back for the asset store's own 404 rather
    // than inventing one, and keep this file to the one thing it is for.
    if (!m) return env.ASSETS.fetch(request);
    return bug(m[1], m[2], env);
  },
};

async function bug(id, rest, env) {
  if (!/^[0-9a-f]{8,64}$/.test(id)) return text("bad bug id", 400);

  // Path segments after the id; absent for a bare /b/<id>.
  const parts = (rest || "").split("/").filter(Boolean);

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

  // Older mailed reports used this URL before the public mail copy was named
  // report.eml. Keep those immutable links useful without ever serving the
  // private report.md contents.
  if (name === "report.md" && files["report.eml"]) {
    return Response.redirect(`https://bugs.sh/b/${id}/report.eml`, REDIRECT);
  }

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
