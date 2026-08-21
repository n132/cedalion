// The fetch, the formatting helpers and click-to-copy. The page defines its own
// render function and calls load() with it.

const esc = s => String(s ?? "").replace(/[&<>"]/g, c =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const num = n => Number(n || 0).toLocaleString("en-US");

// Identifiers read as 12 hex, the length the kernel cites a commit at. Most
// arrive that long already; a Vulnerable row's bug id and report hash arrive
// whole, because those two fields are the entire row and a reader who wants to
// check the fingerprint against a report.md needs all of it. So the cut happens
// here, and what is copied — and what the tooltip shows — is the full value
// rather than the shortened one on screen.
const SHOWN = 12;

function cell(v) {
  if (!v) return '<span class="none">—</span>';
  const s = String(v), cut = s.slice(0, SHOWN);
  const title = cut === s ? "click to copy" : `${s} — click to copy`;
  return `<span class="copy" title="${esc(title)}" data-full="${esc(s)}">${esc(cut)}</span>`;
}

// The clipboard write, by whichever route the page has. The Clipboard API is
// not merely blocked outside a secure context — navigator.clipboard is not
// defined at all — so on the register served over plain http by app.py the
// `?.` call used to evaluate to undefined and do nothing, which looked exactly
// like a copy that worked. Pages is https and had it; the LAN copy did not.
// Resolves to false only when nothing reached the clipboard.
function copyText(text) {
  if (navigator.clipboard?.writeText)
    return navigator.clipboard.writeText(text).then(() => true, () => selectionCopy(text));
  return Promise.resolve(selectionCopy(text));
}

// The pre-Clipboard-API way, and the only one that works on http: put the text
// in a field, select it, and let the browser copy the selection. Off-screen
// rather than hidden — display:none and visibility:hidden both leave nothing
// to select — and readonly so a phone does not raise its keyboard for it.
function selectionCopy(text) {
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.setAttribute("readonly", "");
  ta.style.cssText = "position:fixed;top:0;left:-9999px;opacity:0";
  document.body.appendChild(ta);
  ta.select();
  let ok = false;
  try { ok = document.execCommand("copy"); } catch { ok = false; }
  ta.remove();
  return ok;
}

// A hash is 12 identical-looking hex either way, so a copy that worked and a
// copy that did not look the same on screen unless the page says which. It
// says so by inverting the value for a moment, and says nothing at all when
// the clipboard refused — better a click that visibly did nothing than a
// confirmation of something that did not happen.
document.addEventListener("click", e => {
  const el = e.target.closest(".copy");
  if (!el) return;
  copyText(el.dataset.full).then(ok => {
    if (ok === false) return;
    el.classList.add("copied");
    setTimeout(() => el.classList.remove("copied"), 900);
  });
});

// One fetch of the one published document.
async function load(render) {
  // Relative, and a plain file rather than an endpoint: the same page has to
  // work served by app.py and served as static files by GitHub Pages, where
  // there is no server to answer /api/bugs. app.py routes /bugs.json to the
  // same document, so one fetch covers both.
  const d = await (await fetch("bugs.json")).json();
  // Which artifacts are disclosed, if any. Absent until the first bug is
  // published, and a 404 is the normal state rather than a fault -- every
  // column simply stays pending.
  try {
    const r = await fetch("artifacts.json");
    d.artifacts = r.ok ? await r.json() : {};
  } catch { d.artifacts = {}; }
  try {
    const r = await fetch("disclose_allow.json");
    d.disclose_allow = r.ok ? await r.json() : [];
  } catch { d.disclose_allow = []; }
  const foot = document.getElementById("foot");
  if (foot) foot.textContent = `Data extracted ${d.generated_at || "—"}`;
  render(d);
}
