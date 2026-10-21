// Notificações push (Web Push, RFC 8030/8291/8292) sem dependências: só WebCrypto.
// - As chaves VAPID são geradas na primeira vez e ficam guardadas no servidor (a privada nunca sai daqui).
// - Cada aparelho que aceita avisos vira uma "inscrição" (endpoint + chaves), guardada por dono:
//   o código do aluno ou "trainer".
// - O envio nunca derruba a operação principal: qualquer falha é engolida.
import type { KV } from "./core.mts";

const SUBS_KEY = "push-subs";
const VAPID_KEY = "push-vapid";
const HOSTS_OK = [/\.googleapis\.com$/, /\.push\.services\.mozilla\.com$/, /\.push\.apple\.com$/, /\.notify\.windows\.com$/, /\.mozilla\.com$/, /\.mozaws\.net$/];
export const MAX_SUBS_POR_DONO = 5;

const enc = new TextEncoder();
export function b64u(buf: ArrayBuffer | Uint8Array): string {
  const u = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = ""; for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
export function unb64u(s: string): Uint8Array {
  const p = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  const b = atob(p); const u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u;
}
function cat(...a: Uint8Array[]): Uint8Array { const n = a.reduce((s, x) => s + x.length, 0); const o = new Uint8Array(n); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; }

export function endpointOk(ep: unknown): boolean {
  if (typeof ep !== "string" || ep.length > 700) return false;
  let u: URL; try { u = new URL(ep); } catch (e) { return false; }
  return u.protocol === "https:" && !u.port && HOSTS_OK.some((r) => r.test(u.hostname));
}

export async function vapid(kv: KV, store: string): Promise<{ pub: string; jwk: any }> {
  const cur = await kv.get(store, VAPID_KEY);
  if (cur && cur.pub && cur.jwk) return cur;
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const pub = b64u(await crypto.subtle.exportKey("raw", kp.publicKey));
  const jwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
  const v = { pub, jwk };
  await kv.set(store, VAPID_KEY, v);
  return v;
}

async function jwtVapid(v: { pub: string; jwk: any }, aud: string, now: number): Promise<string> {
  const head = b64u(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const body = b64u(enc.encode(JSON.stringify({ aud, exp: Math.floor(now / 1000) + 12 * 3600, sub: "https://treinomv.netlify.app" })));
  const key = await crypto.subtle.importKey("jwk", v.jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, enc.encode(head + "." + body));
  return head + "." + body + "." + b64u(sig);
}

// RFC 8291 (aes128gcm)
export async function cifra(p256dh: string, auth: string, texto: string): Promise<Uint8Array> {
  const ua = unb64u(p256dh), authSecret = unb64u(auth);
  if (ua.length !== 65 || authSecret.length < 8) throw new Error("sub_invalida");
  const eph = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPub = new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey));
  const uaKey = await crypto.subtle.importKey("raw", ua, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const ecdh = await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, eph.privateKey, 256);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hkdf = async (ikm: ArrayBuffer | Uint8Array, s: Uint8Array, info: Uint8Array, bits: number) => {
    const k = await crypto.subtle.importKey("raw", ikm as any, "HKDF", false, ["deriveBits"]);
    return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: s as any, info: info as any }, k, bits));
  };
  const ikm = await hkdf(ecdh, authSecret, cat(enc.encode("WebPush: info\0"), ua, asPub), 256);
  const cek = await hkdf(ikm, salt, enc.encode("Content-Encoding: aes128gcm\0"), 128);
  const nonce = await hkdf(ikm, salt, enc.encode("Content-Encoding: nonce\0"), 96);
  const aes = await crypto.subtle.importKey("raw", cek as any, "AES-GCM", false, ["encrypt"]);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce as any }, aes, cat(enc.encode(texto), new Uint8Array([2])) as any));
  const rs = new Uint8Array([0, 0, 16, 0]); // 4096
  return cat(salt, rs, new Uint8Array([asPub.length]), asPub, ct);
}

export interface Sub { endpoint: string; p256dh: string; auth: string; ts: number; url?: string }
export async function loadSubs(kv: KV, store: string): Promise<Record<string, Sub[]>> {
  const s = await kv.get(store, SUBS_KEY);
  return s && typeof s === "object" && s.subs && typeof s.subs === "object" ? s.subs : {};
}
export async function saveSubs(kv: KV, store: string, subs: Record<string, Sub[]>): Promise<void> { await kv.set(store, SUBS_KEY, { subs }); }

export interface Aviso { title: string; body: string; tag?: string; url?: string }

/** Envia para os donos indicados ("trainer" e/ou códigos de aluno). Nunca lança. Devolve quantos aparelhos receberam. */
export async function enviar(kv: KV, store: string, donos: string[] | "alunos", aviso: Aviso, now: number, f?: typeof fetch): Promise<number> {
  try {
    const subs = await loadSubs(kv, store);
    const alvo = donos === "alunos" ? Object.keys(subs).filter((k) => k !== "trainer") : donos;
    const lista: { dono: string; sub: Sub }[] = [];
    for (const d of new Set(alvo)) for (const s of subs[d] || []) lista.push({ dono: d, sub: s });
    if (!lista.length) return 0;
    const v = await vapid(kv, store);
    const doFetch = f || fetch;
    let ok = 0; const mortos: { dono: string; endpoint: string }[] = [];
    await Promise.race([
      Promise.allSettled(lista.slice(0, 200).map(async ({ dono, sub }) => {
        try {
          const corpo = await cifra(sub.p256dh, sub.auth, JSON.stringify({ title: aviso.title.slice(0, 80), body: aviso.body.slice(0, 160), tag: aviso.tag || "", url: sub.url || aviso.url || "/" }));
          const aud = new URL(sub.endpoint).origin;
          const res = await doFetch(sub.endpoint, { method: "POST", body: corpo as any, headers: { "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream", TTL: "86400", Urgency: "normal",
            Authorization: "vapid t=" + (await jwtVapid(v, aud, now)) + ", k=" + v.pub } });
          if (res.status === 404 || res.status === 410) mortos.push({ dono, endpoint: sub.endpoint });
          else if (res.status >= 200 && res.status < 300) ok++;
        } catch (e) { /* aparelho fora do ar: segue */ }
      })),
      new Promise((r) => setTimeout(r, 7000)),
    ]);
    if (mortos.length) {
      const atual = await loadSubs(kv, store);
      for (const m of mortos) if (atual[m.dono]) atual[m.dono] = atual[m.dono].filter((s) => s.endpoint !== m.endpoint);
      await saveSubs(kv, store, atual);
    }
    return ok;
  } catch (e) { return 0; }
}
