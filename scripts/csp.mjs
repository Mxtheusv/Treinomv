// Gera public/_headers com os cabeçalhos de segurança, incluindo a Content-Security-Policy (CSP).
// A CSP só deixa rodar os scripts que são deste site: os arquivos em /, e os scripts escritos dentro
// das páginas, identificados pelo "hash" (impressão digital) de cada um. Código injetado por alguém
// (por exemplo, num nome de aluno) não tem hash conhecido e o navegador se recusa a executar.
// Roda no build, DEPOIS da minificação (o hash tem que ser do arquivo final).
// Se falhar, o build segue sem a CSP (o site nunca cai por causa disso).
import { readFileSync, writeFileSync, readdirSync } from "node:fs";
import { createHash } from "node:crypto";

const dir = process.argv[2] || "public";
const paginas = readdirSync(dir).filter((f) => f.endsWith(".html"));
const hashes = new Set();
for (const f of paginas) {
  const html = readFileSync(`${dir}/${f}`, "utf8");
  for (const m of html.matchAll(/<script(\s[^>]*)?>([\s\S]*?)<\/script>/gi)) {
    const attrs = m[1] || "", corpo = m[2];
    if (/\bsrc=/i.test(attrs)) continue;
    const tipo = (/\btype=["']?([^"'\s>]+)/i.exec(attrs) || [])[1];
    if (tipo && !/^(text\/javascript|module|application\/javascript)$/i.test(tipo)) continue; // JSON e afins não executam
    if (!corpo.trim()) continue;
    hashes.add("'sha256-" + createHash("sha256").update(corpo, "utf8").digest("base64") + "'");
  }
}
const csp = [
  "default-src 'self'",
  "script-src 'self' " + [...hashes].join(" "),
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com data:",
  "img-src 'self' data: blob: https:",
  "media-src 'self' blob: https:",
  "connect-src 'self'",
  "frame-src https://www.youtube.com https://www.youtube-nocookie.com https://player.vimeo.com https://drive.google.com",
  "worker-src 'self'",
  "manifest-src 'self'",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join("; ");
const headers = `/*
  Content-Security-Policy: ${csp}
  X-Frame-Options: DENY
  X-Content-Type-Options: nosniff
  Referrer-Policy: strict-origin-when-cross-origin
  Permissions-Policy: camera=(self), microphone=(self), geolocation=(self), payment=(), usb=(), interest-cohort=()
  Strict-Transport-Security: max-age=31536000; includeSubDomains
  Cross-Origin-Opener-Policy: same-origin
`;
writeFileSync(`${dir}/_headers`, headers);
console.log(`csp: ${paginas.length} páginas, ${hashes.size} scripts internos liberados`);
