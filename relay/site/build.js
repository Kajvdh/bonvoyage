// Builds relay/public from site/index.html, ../SPEC.md and ../vectors.
//   npm run build:site
// The result is committed, so running a relay never needs a build step.
import { cpSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { marked } from "marked";

const here = new URL(".", import.meta.url);
const read = (path) => readFileSync(new URL(path, here), "utf8");
const out = (path) => new URL(`../public/${path}`, here);

const source = "https://github.com/Kajvdh/bonvoyage";
const index = read("index.html");
const css = /\/\*site-css\*\/([\s\S]*?)\/\*end-site-css\*\//.exec(index)[1];

const slug = (text) => text.toLowerCase().replace(/<[^>]+>/g, "").replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
const renderer = new marked.Renderer();
renderer.heading = function ({ tokens, depth }) {
  const html = this.parser.parseInline(tokens);
  return `<h${depth} id="${slug(html)}">${html}</h${depth}>\n`;
};
const spec = marked.parse(read("../../SPEC.md"), { renderer, gfm: true });

const specPage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bonvoyage protocol, version 1</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🧾</text></svg>">
<style>${css}
.doc { max-width:760px; padding:20px 0 80px; }
.doc h1 { font-size:clamp(32px, 5vw, 44px); margin:18px 0 20px; }
.doc h2 { font-size:27px; margin:56px 0 12px; padding-top:22px; border-top:1px solid var(--line); }
.doc h3 { font-size:19px; margin:32px 0 8px; }
.doc ul, .doc ol { padding-left:24px; margin:0 0 16px; }
.doc li { margin:5px 0; }
.doc pre { margin:0 0 18px; }
.doc table { width:100%; border-collapse:collapse; margin:0 0 20px; font-size:15.5px; display:block; overflow-x:auto; }
.doc th, .doc td { text-align:left; padding:9px 12px; border-bottom:1px solid var(--line); vertical-align:top; }
.doc th { font:600 12px var(--mono); letter-spacing:.1em; text-transform:uppercase; color:var(--soft); }
.doc td code { white-space:nowrap; }
</style>
</head>
<body>
<div class="wrap">
<header class="top">
  <a class="mark" href="/">BON<b>VOYAGE</b></a>
  <nav><a class="keep" href="/">&larr; Overview</a><a class="keep" href="/vectors/v1.json">Test vectors</a><a class="keep" href="${source}">GitHub</a></nav>
</header>
<main class="doc">
${spec}
</main>
<footer><span>BONVOYAGE</span><span>Protocol version 1, draft</span></footer>
</div>
</body>
</html>
`;

const notFound = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Not found | Bonvoyage</title>
<style>${css}</style>
</head>
<body>
<div class="wrap">
<header class="top"><a class="mark" href="/">BON<b>VOYAGE</b></a></header>
<main style="padding:70px 0 120px">
  <p class="eyebrow">404</p>
  <h1>This ticket got lost.</h1>
  <p class="lead">There is nothing at this address. The relay lives under <code>/v1</code>; everything else is on the <a href="/">front page</a>.</p>
</main>
</div>
</body>
</html>
`;

// A card wrapped in a web link, for phones: https://<relay>/card/#bonvoyage://...
// The part after # never leaves the browser, and this page sends nothing anywhere.
const cardPage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta name="robots" content="noindex">
<title>A Bonvoyage contact card</title>
<style>${css}
.cardtext { font:13px/1.5 var(--mono); word-break:break-all; background:var(--card); border:1px dashed var(--accent); border-radius:12px; padding:14px 16px; margin:18px 0; user-select:all; }
.facts { margin:18px 0; padding:0; list-style:none; }
.facts li { padding:8px 0; border-top:1px solid var(--line); }
.facts b { display:inline-block; min-width:7em; color:var(--soft); font-weight:600; }
button.btn { cursor:pointer; font:inherit; font-weight:600; }
</style>
</head>
<body>
<div class="wrap">
<header class="top"><a class="mark" href="/">BON<b>VOYAGE</b></a></header>
<main style="padding:30px 0 100px; max-width:640px">
  <p class="eyebrow">Contact card</p>
  <h1 id="title" style="font-size:clamp(30px,6vw,44px)">A Bonvoyage contact card</h1>
  <div id="ok" hidden>
    <p class="lead">This card lets a ticket printer send tickets to the person who gave it to you. Copy it and paste it into your own Bonvoyage client, where it asks for a card.</p>
    <ul class="facts"><li><b>From</b> <span id="name"></span></li><li><b>Relay</b> <span id="relay"></span></li><li id="untilRow"><b>Pair before</b> <span id="until"></span></li></ul>
    <div class="cardtext" id="card"></div>
    <button class="btn primary" id="copy">Copy the card</button>
    <p class="explain" style="margin-top:26px"><b>Keep it to yourself.</b> Whoever uses this card first is taken to be you. It was read from the link by your browser only: the part of a link after the # is never sent to a server, and this page sends nothing anywhere.</p>
  </div>
  <p class="lead" id="bad" hidden>This link does not contain a contact card. A card link looks like <code>/card/#bonvoyage://...</code> and is usually scanned from a QR code on a ticket.</p>
</main>
</div>
<script>
// The link may carry the card as it is, or percent-encoded once more (some QR apps do that).
let text = location.hash.slice(1);
if (!text.startsWith("bonvoyage:")) { try { text = decodeURIComponent(text); } catch { text = ""; } }
const card = /^bonvoyage:\\/\\/([a-z0-9.-]+(?::[0-9]{1,5})?)\\/[A-Za-z0-9_-]{43}\\?[A-Za-z0-9_.~%&=-]+$/.exec(text);
if (card) {
  const params = new URLSearchParams(text.slice(text.indexOf("?") + 1).replace(/\\+/g, "%2B"));
  document.getElementById("card").textContent = text;
  document.getElementById("name").textContent = params.get("n") || "(no name given)";
  document.getElementById("relay").textContent = card[1];
  const until = Number(params.get("e"));
  if (until) document.getElementById("until").textContent = new Date(until * 1000).toLocaleDateString(undefined, { weekday: "long", day: "numeric", month: "long", year: "numeric" });
  else document.getElementById("untilRow").hidden = true;
  document.getElementById("ok").hidden = false;
  const button = document.getElementById("copy");
  button.onclick = async () => {
    try { await navigator.clipboard.writeText(text); button.textContent = "Copied"; }
    catch { const r = document.createRange(); r.selectNodeContents(document.getElementById("card")); getSelection().removeAllRanges(); getSelection().addRange(r); button.textContent = "Selected: now copy it"; }
  };
} else {
  document.getElementById("bad").hidden = false;
}
</script>
</body>
</html>
`;

mkdirSync(out("spec/"), { recursive: true });
mkdirSync(out("card/"), { recursive: true });
mkdirSync(out("vectors/"), { recursive: true });
writeFileSync(out("index.html"), index);
writeFileSync(out("spec/index.html"), specPage);
writeFileSync(out("404.html"), notFound);
writeFileSync(out("card/index.html"), cardPage);
cpSync(new URL("../../vectors/v1.json", here), out("vectors/v1.json"));
cpSync(new URL("../../SPEC.md", here), out("SPEC.md"));
console.log("built public/: index.html, spec/index.html, vectors/v1.json, SPEC.md");
