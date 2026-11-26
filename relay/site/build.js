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

mkdirSync(out("spec/"), { recursive: true });
mkdirSync(out("vectors/"), { recursive: true });
writeFileSync(out("index.html"), index);
writeFileSync(out("spec/index.html"), specPage);
cpSync(new URL("../../vectors/v1.json", here), out("vectors/v1.json"));
cpSync(new URL("../../SPEC.md", here), out("SPEC.md"));
console.log("built public/: index.html, spec/index.html, vectors/v1.json, SPEC.md");
