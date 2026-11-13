// Deixa o app mais leve para baixar: minifica o JavaScript e o CSS que ficam dentro do
// public/index.html. Roda só no build do Netlify (o arquivo do repositório continua legível).
// Se qualquer coisa falhar, o build segue com o arquivo original (sem quebrar o site).
// Uso local para testar: node scripts/minificar.mjs <entrada.html> <saida.html>
import { readFileSync, writeFileSync } from "node:fs";

const [entrada = "public/index.html", saida] = process.argv.slice(2);
if (!saida && process.env.NETLIFY !== "true") {
  console.log("minificar: fora do Netlify, nada a fazer (passe entrada e saída para testar).");
  process.exit(0);
}
const { minify } = await import("terser");
const { minify: cssMin } = await import("csso");
const destino = saida || entrada;
const html = readFileSync(entrada, "utf8");
const antes = Buffer.byteLength(html);

const partes = [];
let ultimo = 0;
const re = /<(script|style)(\s[^>]*)?>([\s\S]*?)<\/\1>/g;
let m;
while ((m = re.exec(html))) {
  partes.push(html.slice(ultimo, m.index));
  const [tudo, tag, attrs = "", corpo] = m;
  ultimo = m.index + tudo.length;
  if (tag === "style") {
    partes.push(`<style${attrs}>${cssMin(corpo, { restructure: false }).css}</style>`);
  } else if (/\bsrc=/.test(attrs) || /type=["'](?!text\/javascript|module)/.test(attrs) || corpo.trim().length < 200) {
    partes.push(tudo);
  } else {
    const r = await minify(corpo, { compress: { passes: 1 }, mangle: true, format: { comments: false } });
    if (!r.code) throw new Error("terser não devolveu código");
    partes.push(`<script${attrs}>${r.code.replace(/<\/script/gi, "<\\/script")}</script>`);
  }
}
partes.push(html.slice(ultimo));
const out = partes.join("");
writeFileSync(destino, out);
console.log(`minificar: ${entrada} ${(antes / 1024).toFixed(0)} KB -> ${(Buffer.byteLength(out) / 1024).toFixed(0)} KB`);
