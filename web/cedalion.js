// The fetch, the formatting helpers and click-to-copy. The page defines its own
// render function and calls load() with it.

const esc = s => String(s ?? "").replace(/[&<>"]/g, c =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const num = n => Number(n || 0).toLocaleString("en-US");

// Values arrive already cut to 12 by the extractor, so there is nothing to
// truncate here and the copied text is exactly what is on screen.
function cell(v) {
  if (!v) return '<span class="none">—</span>';
  return `<span class="copy" title="click to copy" data-full="${esc(v)}">${esc(v)}</span>`;
}

document.addEventListener("click", e => {
  const el = e.target.closest(".copy");
  if (el) navigator.clipboard?.writeText(el.dataset.full);
});

// One fetch of the one published document.
async function load(render) {
  // Relative, and a plain file rather than an endpoint: the same page has to
  // work served by app.py and served as static files by GitHub Pages, where
  // there is no server to answer /api/bugs. app.py routes /bugs.json to the
  // same document, so one fetch covers both.
  const d = await (await fetch("bugs.json")).json();
  const foot = document.getElementById("foot");
  if (foot) foot.textContent = `Data extracted ${d.generated_at || "—"}`;
  render(d);
}
