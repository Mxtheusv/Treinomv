// Núcleo de segurança do Treino Online (usado pelas funções do Netlify e pelo servidor de testes).
//
// Antes: GET /api/state devolvia o banco inteiro (PIN, dados de saúde de todos os alunos) para
// QUALQUER visitante, e o PIN era conferido só no navegador. Agora:
//   • o PIN fica no servidor (hash PBKDF2), nunca volta para o navegador;
//   • o personal troca o PIN por um token assinado (HMAC) com validade e usa o token nas chamadas;
//   • o aluno, sem token, só recebe/grava o PRÓPRIO registro (pelo código de acesso);
//   • quem não é nem uma coisa nem outra não recebe nada;
//   • tentativas erradas de PIN e de código de aluno são limitadas (bloqueio progressivo);
//   • o cadastro de novos alunos (formulário público) entra por /api/lead, só com os campos
//     esperados e com limite por IP;
//   • sem CORS aberto: o app só conversa com o próprio site.

import { SEEDS } from "./seeds.mts";
import * as PUSH from "./push.mts";
export interface KV {
  get(store: string, key: string): Promise<any | null>;
  set(store: string, key: string, value: any): Promise<void>;
}
/** Armazenamento de arquivos (fotos). Na função real é o Netlify Blobs; nos testes, um mapa em memória. */
export interface Blobs {
  get(id: string): Promise<{ data: ArrayBuffer; type: string } | null>;
  set(id: string, data: ArrayBuffer, type: string): Promise<void>;
}
export interface Deps {
  kv: KV;
  blobs?: Blobs;
  ip: string;
  now?: () => number;
  /** Somente testes: troca o fetch usado para falar com os serviços de push. */
  fetch?: typeof fetch;
  /** Somente testes: papel "admin" (lê/grava tudo, sem token). A função real nunca ativa isso. */
  admin?: boolean;
  /** Somente testes: com admin, exige a versão certa (409 igual ao personal). */
  strictAdmin?: boolean;
}

const STATE_STORE = "treino-online";
const STATE_KEY = "app-state";
const AUTH_STORE = "treino-online-auth";
const AUTH_KEY = "auth";
const THROTTLE_KEY = "throttle";
const FEED_STORE = "treino-online-feed";
const FEED_KEY = "feed";
const MAX_POSTS = 150;
const MAX_IMG = 400 * 1024;

const TOKEN_TTL_MS = 60 * 24 * 3600 * 1000; // sessão longa: o app renova a cada abertura ("refresh"), então quem usa sempre fica conectado
const PBKDF2_ITER = 120000;
const MIN_PIN = 6;
const MIN_PASS = 8; // senha do login novo (e-mail + senha)
const MAX_BODY_CHARS = 12_000_000;
const MAX_STUDENT_CHARS = 3_000_000;
const MAX_LEADS = 300;

const JSON_HEADERS = { "Content-Type": "application/json", "Cache-Control": "no-store" };
const enc = new TextEncoder();

function reply(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });
}

// ---------- utilitários de criptografia ----------
function b64(u8: Uint8Array): string {
  let s = ""; for (const b of u8) s += String.fromCharCode(b);
  return btoa(s);
}
function unb64(s: string): Uint8Array {
  const bin = atob(s); const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}
function b64u(u8: Uint8Array): string { return b64(u8).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
function unb64u(s: string): Uint8Array {
  s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "=";
  return unb64(s);
}
function randomBytes(n: number): Uint8Array { const u = new Uint8Array(n); crypto.getRandomValues(u); return u; }
function safeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let r = 0; for (let i = 0; i < a.length; i++) r |= a[i] ^ b[i];
  return r === 0;
}
async function pbkdf2(pin: string, salt: Uint8Array, iter: number): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", enc.encode(pin), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: iter }, key, 256);
  return new Uint8Array(bits);
}
async function hmacKey(secretB64: string, usage: "sign" | "verify") {
  return crypto.subtle.importKey("raw", unb64(secretB64), { name: "HMAC", hash: "SHA-256" }, false, [usage]);
}
async function sha256hex(s: string): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", enc.encode(s));
  return Array.from(new Uint8Array(d)).map((x) => x.toString(16).padStart(2, "0")).join("");
}

// ---------- autenticação ----------
interface AuthRec {
  salt: string; hash: string; iter: number; secret: string; epoch: number;
  fails: number[]; lockUntil: number; lockLevel: number;
  email?: string;                              // login novo: e-mail do personal (minúsculo)
  rk?: { salt: string; hash: string };         // chave de recuperação (só o hash fica guardado)
}
function normEmail(v: unknown): string { return String(v == null ? "" : v).trim().toLowerCase().slice(0, 120); }
function emailOk(e: string): boolean { return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e); }
const RK_ALPHA = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
function newRecoveryKey(): string {
  const r = randomBytes(24); let s = "";
  for (let i = 0; i < 24; i++) s += RK_ALPHA[r[i] % RK_ALPHA.length];
  return s.match(/.{4}/g)!.join("-");
}
function rkNorm(v: unknown): string { return String(v == null ? "" : v).toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 40); }
async function makeRk(key: string): Promise<{ salt: string; hash: string }> {
  const salt = randomBytes(16);
  return { salt: b64(salt), hash: b64(await pbkdf2(rkNorm(key), salt, PBKDF2_ITER)) };
}
async function makeAuth(pin: string, prev?: AuthRec | null): Promise<AuthRec> {
  const salt = randomBytes(16);
  const hash = await pbkdf2(pin, salt, PBKDF2_ITER);
  return {
    salt: b64(salt), hash: b64(hash), iter: PBKDF2_ITER,
    secret: prev?.secret || b64(randomBytes(32)),
    epoch: (prev?.epoch || 0) + (prev ? 1 : 0),
    fails: [], lockUntil: 0, lockLevel: 0,
    ...(prev?.email ? { email: prev.email } : {}),
    ...(prev?.rk ? { rk: prev.rk } : {}),
  };
}
async function signToken(auth: AuthRec, now: number): Promise<string> {
  const payload = b64u(enc.encode(JSON.stringify({ r: "t", e: now + TOKEN_TTL_MS, v: auth.epoch })));
  const sig = await crypto.subtle.sign("HMAC", await hmacKey(auth.secret, "sign"), enc.encode(payload));
  return payload + "." + b64u(new Uint8Array(sig));
}
async function tokenValid(token: unknown, auth: AuthRec | null, now: number): Promise<boolean> {
  if (!auth || typeof token !== "string" || token.length > 400) return false;
  const i = token.indexOf(".");
  if (i < 1) return false;
  const payload = token.slice(0, i);
  try {
    const ok = await crypto.subtle.verify("HMAC", await hmacKey(auth.secret, "verify"), unb64u(token.slice(i + 1)), enc.encode(payload));
    if (!ok) return false;
    const p = JSON.parse(new TextDecoder().decode(unb64u(payload)));
    return p && p.r === "t" && typeof p.e === "number" && p.e > now && p.v === auth.epoch;
  } catch { return false; }
}
function bearer(req: Request, body?: any): string | null {
  const h = req.headers.get("authorization");
  if (h && /^Bearer\s+/i.test(h)) return h.replace(/^Bearer\s+/i, "").trim();
  if (body && typeof body.token === "string") return body.token;
  return null;
}

async function loadState(deps: Deps): Promise<any> {
  return (await deps.kv.get(STATE_STORE, STATE_KEY)) || { version: 0, data: { students: {}, templates: [], leads: [], alertaCheckinDias: 7 }, catalog: [] };
}
async function loadAuth(deps: Deps): Promise<AuthRec | null> {
  const auth = await deps.kv.get(AUTH_STORE, AUTH_KEY);
  if (auth) return auth;
  // Migração: o PIN antigo estava em texto dentro do banco. Vira hash no servidor e sai do banco.
  const st = await deps.kv.get(STATE_STORE, STATE_KEY);
  const oldPin = st?.data?.pin;
  if (typeof oldPin === "string" && oldPin.trim().length > 0) {
    const created = await makeAuth(oldPin.trim());
    await deps.kv.set(AUTH_STORE, AUTH_KEY, created);
    delete st.data.pin;
    await deps.kv.set(STATE_STORE, STATE_KEY, st);
    return created;
  }
  return null;
}

// ---------- limite de tentativas por IP ----------
async function throttleKey(deps: Deps): Promise<string> { return (await sha256hex("ip:" + deps.ip)).slice(0, 16); }
async function throttleLoad(deps: Deps): Promise<Record<string, any>> {
  const t = (await deps.kv.get(AUTH_STORE, THROTTLE_KEY)) || {};
  const now = (deps.now || Date.now)();
  Object.keys(t).forEach((k) => {
    t[k].miss = (t[k].miss || []).filter((x: number) => now - x < 3600_000);
    t[k].leads = (t[k].leads || []).filter((x: number) => now - x < 3600_000);
    t[k].ups = (t[k].ups || []).filter((x: number) => now - x < 3600_000);
    if (!t[k].miss.length && !t[k].leads.length && !t[k].ups.length) delete t[k];
  });
  const keys = Object.keys(t);
  if (keys.length > 500) keys.slice(0, keys.length - 500).forEach((k) => delete t[k]);
  return t;
}
const MISS_LIMIT = 20; // códigos de aluno errados por hora, por IP
const LEAD_LIMIT = 6;  // cadastros por hora, por IP

// ---------- rotas ----------
export async function handleApi(req: Request, deps: Deps): Promise<Response | null> {
  const now = (deps.now || Date.now)();
  const url = new URL(req.url);
  const path = url.pathname;
  if (path === "/api/state") {
    if (req.method === "GET") return getState(req, url, deps, now);
    if (req.method === "POST") return postState(req, deps, now);
    return reply(405, { error: "method" });
  }
  if (path === "/api/auth" && req.method === "POST") return postAuth(req, deps, now);
  if (path === "/api/push") return pushRoute(req, url, deps, now);
  if (path === "/api/lead" && req.method === "POST") return postLead(req, deps, now);
  if (path === "/api/comunidade" && req.method === "GET") return getComunidade(req, url, deps, now);
  if (path === "/api/feed") {
    if (req.method === "GET") return getFeed(req, url, deps, now);
    if (req.method === "POST") return postFeed(req, deps, now);
    return reply(405, { error: "method" });
  }
  if (path === "/api/turma") {
    if (req.method === "GET") return getTurma(req, url, deps, now);
    if (req.method === "POST") return postTurma(req, deps, now);
    return reply(405, { error: "method" });
  }
  if (path === "/api/img" && req.method === "POST") return postImg(req, deps, now);
  if (path.startsWith("/api/img/") && req.method === "GET") return getImg(path.slice("/api/img/".length), deps);
  return null;
}

/** Usado também pela função de vídeo: confere se a chamada vem do personal. */
export async function requestIsTrainer(req: Request, deps: Deps): Promise<boolean> {
  if (deps.admin) return true;
  const now = (deps.now || Date.now)();
  return tokenValid(bearer(req), await loadAuth(deps), now);
}

function publicState(st: any) {
  const data = { ...(st.data || {}) };
  delete data.pin;
  return { version: st.version, data, catalog: st.catalog || [] };
}

// Cadastros prontos (ver seeds.mts): entram uma única vez, só quando o PERSONAL abre o app.
async function applySeeds(st: any, deps: Deps, now: number): Promise<any> {
  if (!st || !st.data || typeof st.data.students !== "object" || st.data.students === null) return st; // banco ainda vazio: nada a semear
  const feitos: string[] = Array.isArray(st.data.seedsFeitos) ? st.data.seedsFeitos : [];
  const pendentes = SEEDS.filter((x) => !feitos.includes(x.id));
  if (!pendentes.length) return st;
  const students = { ...st.data.students };
  const novos = [...feitos];
  for (const sd of pendentes) {
    if (!students[sd.slug]) students[sd.slug] = sd.build(now); // se já existe um aluno com esse código, não mexe
    novos.push(sd.id);
  }
  const next = { ...st, version: (st.version || 0) + 1, data: { ...st.data, students, seedsFeitos: novos } };
  await deps.kv.set(STATE_STORE, STATE_KEY, next);
  return next;
}

async function getState(req: Request, url: URL, deps: Deps, now: number): Promise<Response> {
  const auth = await loadAuth(deps);
  if (deps.admin || (await tokenValid(bearer(req), auth, now))) {
    let st = await loadState(deps);
    if (!deps.admin) st = await applySeeds(st, deps, now);
    return reply(200, { ...publicState(st), role: deps.admin ? "admin" : "trainer", email: auth?.email || "", hasLogin: !!auth?.email });
  }
  if (bearer(req)) return reply(401, { error: "token_invalido" }); // token vencido/inválido: o app volta para a tela do PIN

  const slug = url.searchParams.get("slug");
  if (slug) {
    const tk = await throttleKey(deps);
    const thr = await throttleLoad(deps);
    if ((thr[tk]?.miss?.length || 0) >= MISS_LIMIT) return reply(429, { error: "muitas_tentativas" });
    const st = await loadState(deps);
    const rec = typeof slug === "string" && slug.length <= 80 ? st.data?.students?.[slug] : null;
    if (!rec) {
      thr[tk] = thr[tk] || { miss: [], leads: [] };
      thr[tk].miss.push(now);
      await deps.kv.set(AUTH_STORE, THROTTLE_KEY, thr);
      return reply(404, { error: "codigo_nao_encontrado" });
    }
    return reply(200, {
      version: st.version, role: "student",
      data: { students: { [slug]: rec }, templates: [], leads: [], alertaCheckinDias: st.data?.alertaCheckinDias || 7 },
      catalog: st.catalog || [],
    });
  }
  // Visitante anônimo: não recebe dado nenhum, só se já existe PIN (para a tela de entrada).
  return reply(200, { locked: true, hasPin: !!auth, hasLogin: !!auth?.email, version: 0, data: { students: {}, templates: [], leads: [] }, catalog: [] });
}

async function readJson(req: Request): Promise<any | null> {
  try {
    const text = await req.text();
    if (text.length > MAX_BODY_CHARS) return null;
    return JSON.parse(text);
  } catch { return null; }
}

// Parabéns ao aluno quando o treino que ele acabou de terminar fecha a meta da semana ou acende o 🔥 (8 dias) / 👑 (20 dias) do mês.
async function parabensAluno(deps: Deps, now: number, slug: string, antes: any, depois: any): Promise<void> {
  try {
    const hoje = diaBR(now), segunda = semanaBR(now)[0], mes = hoje.slice(0, 7);
    const conta = (rec: any) => { const d = [...datasAtivas(rec)]; return { sem: d.filter((x) => x >= segunda && x <= hoje).length, mes: d.filter((x) => x.slice(0, 7) === mes).length }; };
    const a = conta(antes), b = conta(depois), meta = metaSemanal(depois);
    let t = "", c = "";
    if (a.mes < 20 && b.mes >= 20) { t = "👑 Você chegou a 20 dias de treino no mês!"; c = "Disciplina de verdade. Parabéns!"; }
    else if (a.mes < 8 && b.mes >= 8) { t = "🔥 Seu fogo do mês acendeu!"; c = "8 dias de treino neste mês. Continue assim!"; }
    else if (a.sem < meta && b.sem >= meta) { t = "🏆 Meta da semana batida!"; c = b.sem + " de " + meta + " treinos. Parabéns, " + (String(depois.nome || "").trim().split(/\s+/)[0] || "campeão(ã)") + "!"; }
    if (t) await avisa(deps, now, [slug], t, c, "parabens");
  } catch (e) { /* nunca derruba o salvamento */ }
}
// Aluno salvou o próprio registro: se há uma sessão nova (treino finalizado), avisa o personal (uma vez por sessão).
async function avisoTreinoFinalizado(deps: Deps, now: number, slug: string, antes: any, depois: any): Promise<void> {
  try {
    const jaTinha = new Set((Array.isArray(antes?.sessoes) ? antes.sessoes : []).map((x: any) => x && x.id));
    const novas = (Array.isArray(depois?.sessoes) ? depois.sessoes : []).filter((x: any) => x && x.id && !jaTinha.has(x.id) && (x.kind === "treino" || x.kind === "comp") && now - (Number(x.ts) || now) < 24 * 3600_000);
    if (!novas.length) return;
    await parabensAluno(deps, now, slug, antes, depois);
    const x = novas[novas.length - 1];
    const min = Math.max(1, Math.round((Number(x.duracaoSeg) || 0) / 60));
    const pse = typeof x.pse === "number" ? " · PSE " + x.pse : "";
    await avisa(deps, now, ["trainer"], nomeCurto(depois.nome) + " terminou o treino", limpaTexto(x.nome || "Treino", 50) + (x.duracaoSeg ? " · " + min + " min" : "") + pse, "treino-fim");
  } catch (e) { /* nunca derruba o salvamento */ }
}
// Compara o banco antes/depois do salvamento do personal e avisa o aluno: nova meta ou treino atualizado.
async function avisosDeCadastro(deps: Deps, now: number, antes: Record<string, any>, depois: Record<string, any>): Promise<void> {
  try {
    for (const slug of Object.keys(depois)) {
      const a = antes[slug], d = depois[slug];
      if (!a || !d) continue; // aluno novo: ainda não tem o que avisar
      const idsAntes = new Set((Array.isArray(a.metas) ? a.metas : []).map((m: any) => m && m.id));
      const nova = (Array.isArray(d.metas) ? d.metas : []).filter((m: any) => m && m.porPersonal && !idsAntes.has(m.id));
      if (nova.length) await avisa(deps, now, [slug], "Nova meta: " + limpaTexto(nova[0].nome, 60), nova.length > 1 ? "e mais " + (nova.length - 1) + (nova.length === 2 ? " meta" : " metas") + ". Veja na aba Comunidade." : "Acompanhe o progresso na aba Comunidade.", "meta");
      // Treino novo: plano novo (ex.: modelo enviado) ou treino novo dentro do plano ativo. Tem prioridade sobre o aviso
      // genérico de treino atualizado, para o aluno não receber dois avisos pelo mesmo salvamento.
      const planosAntes = new Set((Array.isArray(a.plans) ? a.plans : []).map((p: any) => p && p.id));
      const planosNovos = (Array.isArray(d.plans) ? d.plans : []).filter((p: any) => p && !p.archived && !planosAntes.has(p.id));
      const treinosNovos: string[] = [];
      for (const p of Array.isArray(d.plans) ? d.plans : []) {
        if (!p || p.archived || !planosAntes.has(p.id)) continue;
        const antesIds = new Set((Array.isArray((a.plans || []).find((x: any) => x && x.id === p.id)?.treinos) ? a.plans.find((x: any) => x && x.id === p.id).treinos : []).map((t: any) => t && t.id));
        for (const t of Array.isArray(p.treinos) ? p.treinos : []) if (t && !antesIds.has(t.id)) treinosNovos.push(limpaTexto(t.nome || "Treino", 40));
      }
      if (planosNovos.length) {
        const p = planosNovos[0];
        const n = Array.isArray(p.treinos) ? p.treinos.length : 0;
        await avisa(deps, now, [slug], "Você tem treino novo", limpaTexto((p.microciclo || p.label || "Novo plano") + " · " + n + (n === 1 ? " treino" : " treinos") + ". Bora treinar! 💪", 160), "treino-novo");
      } else if (treinosNovos.length) {
        await avisa(deps, now, [slug], "Você tem treino novo", "Novo treino: " + treinosNovos.slice(0, 2).join(" e ") + (treinosNovos.length > 2 ? " e mais " + (treinosNovos.length - 2) : "") + ". Bora! 💪", "treino-novo");
      } else if ((Number(d.treinoAtualizadoEm) || 0) > (Number(a.treinoAtualizadoEm) || 0)) await avisa(deps, now, [slug], "Seu treino foi atualizado", "Dê uma olhada nas mudanças.", "treino");
    }
  } catch (e) { /* nunca derruba o salvamento */ }
}
// Histórico do aluno: sessão nova entra junto com o que o servidor já tem, e só sai quando alguém a apaga de
// propósito (fica registrada em sessoesApagadas). Assim, um salvamento feito por uma cópia antiga do app
// (outro aparelho ou aba) não apaga o que outro aparelho acabou de salvar, nem traz de volta um treino apagado.
// Mesma sessão salva duas vezes (mesmo início) entra uma vez só.
function mesclaSessoesAluno(antes: any, depois: any): void {
  if (!depois || typeof depois !== "object") return;
  const apagadas = new Set<string>(
    [...(Array.isArray(antes?.sessoesApagadas) ? antes.sessoesApagadas : []), ...(Array.isArray(depois.sessoesApagadas) ? depois.sessoesApagadas : [])]
      .filter((x: any) => typeof x === "string" && x.length <= 80)
  );
  const lista = [...(Array.isArray(depois.sessoes) ? depois.sessoes : []), ...(Array.isArray(antes?.sessoes) ? antes.sessoes : [])];
  const chaves = new Set<string>();
  const inicios = new Set<string>();
  const out: any[] = [];
  for (const x of lista) {
    if (!x || typeof x !== "object") continue;
    if (x.id && apagadas.has(String(x.id))) continue;
    const k = x.id ? "id:" + String(x.id) : "k:" + String(x.ts) + "|" + String(x.date) + "|" + String(x.nome);
    if (chaves.has(k)) continue;
    if (x.inicio !== undefined && x.inicio !== null && inicios.has(String(x.inicio))) continue;
    chaves.add(k);
    if (x.inicio !== undefined && x.inicio !== null) inicios.add(String(x.inicio));
    out.push(x);
  }
  out.sort((a, b) => (Number(a.ts) || 0) - (Number(b.ts) || 0));
  depois.sessoes = out;
  depois.sessoesApagadas = [...apagadas].slice(-200);
}

async function postState(req: Request, deps: Deps, now: number): Promise<Response> {
  const body = await readJson(req);
  if (!body || typeof body !== "object") return reply(400, { error: "bad_json" });
  const auth = await loadAuth(deps);
  const isTrainer = deps.admin || (await tokenValid(bearer(req, body), auth, now));

  if (!isTrainer) {
    if (bearer(req, body)) return reply(401, { error: "token_invalido" });
    // Aluno: só grava o PRÓPRIO registro, identificado pelo código de acesso.
    const slug = typeof body.slug === "string" ? body.slug : "";
    const student = body.student;
    if (!slug || slug.length > 80 || !student || typeof student !== "object" || Array.isArray(student)) return reply(400, { error: "pedido_invalido" });
    if (JSON.stringify(student).length > MAX_STUDENT_CHARS) return reply(413, { error: "grande_demais" });
    const tk = await throttleKey(deps);
    const thr = await throttleLoad(deps);
    if ((thr[tk]?.miss?.length || 0) >= MISS_LIMIT) return reply(429, { error: "muitas_tentativas" });
    const st = await loadState(deps);
    if (!st.data?.students?.[slug]) {
      thr[tk] = thr[tk] || { miss: [], leads: [] };
      thr[tk].miss.push(now);
      await deps.kv.set(AUTH_STORE, THROTTLE_KEY, thr);
      return reply(404, { error: "removido" });
    }
    const antes = st.data.students[slug];
    mesclaSessoesAluno(antes, student);
    st.data.students[slug] = student;
    st.version = (st.version || 0) + 1;
    await deps.kv.set(STATE_STORE, STATE_KEY, st);
    await avisoTreinoFinalizado(deps, now, slug, antes, student);
    return reply(200, { version: st.version });
  }

  // Personal (ou teste): troca o banco inteiro, com controle de versão.
  if (!body.data || typeof body.data !== "object" || typeof body.data.students !== "object" || body.data.students === null) return reply(400, { error: "pedido_invalido" });
  const current = await loadState(deps);
  const clientVersion = typeof body.version === "number" ? body.version : 0;
  const enforce = !deps.admin || deps.strictAdmin;
  if (enforce && clientVersion !== current.version) return reply(409, { ...publicState(current) });
  const data = { ...body.data };
  const pinFromClient = typeof data.pin === "string" ? data.pin.trim() : "";
  delete data.pin; // o PIN nunca mais mora no banco
  if (deps.admin && pinFromClient && !auth) await deps.kv.set(AUTH_STORE, AUTH_KEY, await makeAuth(pinFromClient)); // só testes: semeia o PIN se ainda não existe
  const next = { version: (current.version || 0) + 1, data, catalog: Array.isArray(body.catalog) ? body.catalog : current.catalog };
  await deps.kv.set(STATE_STORE, STATE_KEY, next);
  await avisosDeCadastro(deps, now, current.data?.students || {}, data.students);
  return reply(200, { version: next.version });
}

async function postAuth(req: Request, deps: Deps, now: number): Promise<Response> {
  const body = await readJson(req);
  if (!body || typeof body !== "object") return reply(400, { error: "bad_json" });
  const action = String(body.action || "");
  const pin = typeof body.pin === "string" ? body.pin.trim() : "";
  let auth = await loadAuth(deps);

  if (action === "setup") {
    if (auth) return reply(409, { error: "pin_ja_existe" });
    const em = normEmail(body.email);
    if (em) { // instalação nova já com e-mail + senha
      if (!emailOk(em)) return reply(400, { error: "email_invalido" });
      if (pin.length < MIN_PASS || pin.length > 100) return reply(400, { error: "pin_curto", min: MIN_PASS });
      const key = newRecoveryKey();
      auth = { ...(await makeAuth(pin)), email: em, rk: await makeRk(key) };
      await deps.kv.set(AUTH_STORE, AUTH_KEY, auth);
      return reply(200, { token: await signToken(auth, now), recoveryKey: key });
    }
    if (pin.length < MIN_PIN || pin.length > 100) return reply(400, { error: "pin_curto", min: MIN_PIN });
    auth = await makeAuth(pin);
    await deps.kv.set(AUTH_STORE, AUTH_KEY, auth);
    return reply(200, { token: await signToken(auth, now) });
  }

  // Sessão longa: quem abre o app com um token ainda válido ganha outro de 60 dias.
  if (action === "refresh") {
    if (!(await tokenValid(bearer(req, body), auth, now))) return reply(401, { error: "token_invalido" });
    return reply(200, { token: await signToken(auth!, now) });
  }

  // Quem entrou com o PIN antigo cria o login (e-mail + senha) e recebe a chave de recuperação.
  if (action === "upgrade") {
    if (!(deps.admin || (await tokenValid(bearer(req, body), auth, now)))) return reply(401, { error: "token_invalido" });
    if (!auth) return reply(404, { error: "sem_pin" });
    const em = normEmail(body.email);
    if (!emailOk(em)) return reply(400, { error: "email_invalido" });
    if (pin.length < MIN_PASS || pin.length > 100) return reply(400, { error: "pin_curto", min: MIN_PASS });
    const key = newRecoveryKey();
    auth = { ...(await makeAuth(pin, auth)), email: em, rk: await makeRk(key) }; // epoch+1: derruba os outros acessos (e o PIN antigo)
    await deps.kv.set(AUTH_STORE, AUTH_KEY, auth);
    return reply(200, { token: await signToken(auth, now), recoveryKey: key, email: em });
  }

  // Chave de recuperação nova (a antiga deixa de valer).
  if (action === "newrecovery") {
    if (!(await tokenValid(bearer(req, body), auth, now)) || !auth) return reply(401, { error: "token_invalido" });
    if (!auth.email) return reply(400, { error: "sem_login" });
    const key = newRecoveryKey();
    auth = { ...auth, rk: await makeRk(key) };
    await deps.kv.set(AUTH_STORE, AUTH_KEY, auth);
    return reply(200, { recoveryKey: key });
  }

  // Esqueci a senha: e-mail + chave de recuperação + senha nova. Conta nas mesmas tentativas do login.
  if (action === "recover") {
    if (!auth || !auth.email || !auth.rk) return reply(404, { error: "sem_login" });
    if (auth.lockUntil > now) return reply(429, { error: "bloqueado", retryAfterSec: Math.ceil((auth.lockUntil - now) / 1000) });
    const okRk = safeEqual(await pbkdf2(rkNorm(body.recoveryKey), unb64(auth.rk.salt), auth.iter), unb64(auth.rk.hash));
    const ok = okRk && normEmail(body.email) === auth.email;
    if (!ok) {
      auth.fails = (auth.fails || []).filter((x) => now - x < 10 * 60_000).concat([now]);
      if (auth.fails.length >= 5) {
        auth.lockUntil = now + Math.min(15 * 60_000 * Math.pow(2, auth.lockLevel || 0), 24 * 3600_000);
        auth.lockLevel = (auth.lockLevel || 0) + 1;
        auth.fails = [];
      }
      await deps.kv.set(AUTH_STORE, AUTH_KEY, auth);
      return reply(401, { error: "recuperacao_incorreta", restantes: Math.max(0, 5 - auth.fails.length) });
    }
    if (pin.length < MIN_PASS || pin.length > 100) return reply(400, { error: "pin_curto", min: MIN_PASS });
    const key = newRecoveryKey();
    auth = { ...(await makeAuth(pin, auth)), email: auth.email, rk: await makeRk(key) };
    await deps.kv.set(AUTH_STORE, AUTH_KEY, auth);
    return reply(200, { token: await signToken(auth, now), recoveryKey: key });
  }

  if (action === "login") {
    if (!auth) return reply(404, { error: "sem_pin" });
    if (auth.lockUntil > now) return reply(429, { error: "bloqueado", retryAfterSec: Math.ceil((auth.lockUntil - now) / 1000) });
    const okPass = pin.length > 0 && pin.length <= 100 && safeEqual(await pbkdf2(pin, unb64(auth.salt), auth.iter), unb64(auth.hash));
    const ok = okPass && (!auth.email || normEmail(body.email) === auth.email);
    if (!ok) {
      auth.fails = (auth.fails || []).filter((x) => now - x < 10 * 60_000).concat([now]);
      if (auth.fails.length >= 5) {
        auth.lockUntil = now + Math.min(15 * 60_000 * Math.pow(2, auth.lockLevel || 0), 24 * 3600_000);
        auth.lockLevel = (auth.lockLevel || 0) + 1;
        auth.fails = [];
      }
      await deps.kv.set(AUTH_STORE, AUTH_KEY, auth);
      return reply(401, { error: "pin_incorreto", restantes: Math.max(0, 5 - auth.fails.length) });
    }
    auth.fails = []; auth.lockUntil = 0; auth.lockLevel = 0;
    await deps.kv.set(AUTH_STORE, AUTH_KEY, auth);
    return reply(200, { token: await signToken(auth, now) });
  }

  if (action === "change") {
    if (!(deps.admin || (await tokenValid(bearer(req, body), auth, now)))) return reply(401, { error: "token_invalido" });
    const minLen = auth?.email ? MIN_PASS : MIN_PIN;
    if (pin.length < minLen || pin.length > 100) return reply(400, { error: "pin_curto", min: minLen });
    auth = await makeAuth(pin, auth);   // epoch+1: derruba todos os outros acessos do personal
    await deps.kv.set(AUTH_STORE, AUTH_KEY, auth);
    return reply(200, { token: await signToken(auth, now) });
  }
  return reply(400, { error: "acao_invalida" });
}

const LEAD_FIELDS: Record<string, number> = {
  nome: 120, whats: 40, idade: 20, peso: 20, objetivo: 100, experiencia: 100, dias: 60, tempo: 100, local: 100, restricoes: 1500,
};
async function postLead(req: Request, deps: Deps, now: number): Promise<Response> {
  const body = await readJson(req);
  const raw = body && typeof body === "object" ? body.lead : null;
  if (!raw || typeof raw !== "object") return reply(400, { error: "pedido_invalido" });
  const lead: Record<string, unknown> = {};
  for (const k of Object.keys(LEAD_FIELDS)) {
    const v = raw[k];
    lead[k] = typeof v === "string" ? v.trim().slice(0, LEAD_FIELDS[k]) : "";
  }
  if (!lead.nome) return reply(400, { error: "nome_obrigatorio" });
  const tk = await throttleKey(deps);
  const thr = await throttleLoad(deps);
  if ((thr[tk]?.leads?.length || 0) >= LEAD_LIMIT) return reply(429, { error: "muitas_tentativas" });
  thr[tk] = thr[tk] || { miss: [], leads: [] };
  thr[tk].leads.push(now);
  await deps.kv.set(AUTH_STORE, THROTTLE_KEY, thr);
  const st = await loadState(deps);
  const leads = Array.isArray(st.data?.leads) ? st.data.leads : [];
  if (leads.length >= MAX_LEADS) return reply(429, { error: "caixa_cheia" });
  leads.push({ id: "lead" + now.toString(36) + Math.random().toString(36).slice(2, 6), criadoEm: now, ...lead });
  st.data = { ...(st.data || {}), leads };
  st.version = (st.version || 0) + 1;
  await deps.kv.set(STATE_STORE, STATE_KEY, st);
  await avisa(deps, now, ["trainer"], "Novo aluno interessado", String(lead.nome), "lead");
  return reply(200, { ok: true });
}


// ---------- avisos no celular (push) ----------
// Ver push.mts. Aqui ficam a rota (/api/push) e os atalhos usados pelos eventos do app.
async function avisa(deps: Deps, now: number, donos: string[] | "alunos", titulo: string, corpo: string, tag?: string): Promise<void> {
  try { await PUSH.enviar(deps.kv, AUTH_STORE, donos, { title: limpaTexto(titulo, 80), body: limpaTexto(corpo, 160), tag }, now, deps.fetch); } catch (e) { /* nunca derruba a operação */ }
}
async function pushRoute(req: Request, url: URL, deps: Deps, now: number): Promise<Response> {
  if (req.method === "GET") {
    const w = await who(req, deps, now, url.searchParams.get("slug"));
    if (w.err) return w.err;
    const v = await PUSH.vapid(deps.kv, AUTH_STORE);
    const out: Record<string, unknown> = { publicKey: v.pub };
    const cham = await chamadasLer(deps);
    if (w.trainer) out.chamadas = Object.fromEntries(Object.keys(cham).map((k) => [k, cham[k].ts]));
    if (w.slug && cham[w.slug]) out.chamada = { ts: cham[w.slug].ts, t: cham[w.slug].t, c: cham[w.slug].c };
    return reply(200, out);
  }
  if (req.method !== "POST") return reply(405, { error: "method" });
  const body = await readJson(req);
  if (!body || typeof body !== "object") return reply(400, { error: "bad_json" });
  const w = await who(req, deps, now, body.slug, body);
  if (w.err) return w.err;
  if (w.trainer && w.slug) return reply(403, { error: "sem_permissao" });
  const dono = w.trainer ? "trainer" : w.slug;
  if (!dono) return reply(403, { error: "sem_permissao" });
  const action = String(body.action || "");
  const subs = await PUSH.loadSubs(deps.kv, AUTH_STORE);
  if (action === "subscribe") {
    const s = body.sub && typeof body.sub === "object" ? body.sub : null;
    const ep = s && s.endpoint, p = s && s.keys && s.keys.p256dh, a = s && s.keys && s.keys.auth;
    if (!PUSH.endpointOk(ep) || typeof p !== "string" || typeof a !== "string" || p.length > 120 || a.length > 60) return reply(400, { error: "pedido_invalido" });
    try { if (PUSH.unb64u(p).length !== 65) throw new Error("x"); } catch (e) { return reply(400, { error: "pedido_invalido" }); }
    for (const k of Object.keys(subs)) subs[k] = subs[k].filter((x) => x.endpoint !== ep); // o aparelho muda de dono se trocar de aluno
    const lista = (subs[dono] || []).concat([{ endpoint: ep, p256dh: p, auth: a, ts: now, url: typeof body.url === "string" && /^\/[#?\/A-Za-z0-9_=.&%-]{0,120}$/.test(body.url) ? body.url : "/" }]);
    subs[dono] = lista.slice(-PUSH.MAX_SUBS_POR_DONO);
    for (const k of Object.keys(subs)) if (!subs[k].length) delete subs[k];
    await PUSH.saveSubs(deps.kv, AUTH_STORE, subs);
    return reply(200, { ok: true });
  }
  if (action === "unsubscribe") {
    const ep = typeof body.endpoint === "string" ? body.endpoint : "";
    if (subs[dono]) subs[dono] = subs[dono].filter((x) => x.endpoint !== ep);
    if (subs[dono] && !subs[dono].length) delete subs[dono];
    await PUSH.saveSubs(deps.kv, AUTH_STORE, subs);
    return reply(200, { ok: true });
  }
  if (action === "teste") {
    const n = await PUSH.enviar(deps.kv, AUTH_STORE, [dono], { title: "Treino Online", body: "Tudo certo! Os avisos vão chegar aqui. 💪", tag: "teste" }, now, deps.fetch);
    return reply(200, { ok: true, enviados: n });
  }
  if (action === "chamar") {
    if (!w.trainer) return reply(403, { error: "sem_permissao" });
    return reply(200, { ok: true, ...(await chamaAlunos(deps, now, body.slugs, { push: body.push !== false, forca: body.forca === true })) });
  }
  return reply(400, { error: "acao_invalida" });
}


// ---------- chamadas: o personal chama o aluno para treinar (botão "🔔 Chamar" no painel de alunos) ----------
// Cada chamada vira um aviso no celular (se o aluno ligou os avisos) e fica guardada aqui: ao abrir o app, o aluno vê a
// mesma mensagem num cartão "📣" até tocar em Entendi. A frase muda a cada chamada: há 5 a 6 variações por faixa de
// dias parado, e o mesmo aluno nunca recebe a mesma frase duas vezes seguidas. Um aluno só é chamado de novo depois de
// CHAMADA_INTERVALO_H horas, para não virar spam.
const CHAMADA_KEY = "chamadas";
const CHAMADA_INTERVALO_H = 20;
type Modelo = { t: string; c: string };
// {nome} = primeiro nome do aluno; {dias} = dias sem treinar.
const CHAMADA_LEVE: Modelo[] = [ // 3 a 6 dias
  { t: "{nome}, sentimos sua falta", c: "Faz {dias} dias sem treinar. Bora retomar hoje? 💪" },
  { t: "Seu treino está te esperando, {nome}", c: "Já deixei tudo pronto. Um treino curto hoje já faz diferença." },
  { t: "Bora voltar, {nome}?", c: "Faz {dias} dias desde o último treino. Qualquer treino conta." },
  { t: "Oi, {nome}! 👋", c: "Passando pra te chamar pra treinar. Qual horário dá pra você hoje?" },
  { t: "{nome}, cadê você?", c: "Faz {dias} dias sem aparecer. Vamos marcar o retorno?" },
  { t: "Constância, {nome}", c: "O que mais faz diferença é voltar com frequência. Bora de novo hoje? 💪" },
];
const CHAMADA_FIRME: Modelo[] = [ // 7 a 13 dias
  { t: "{nome}, faz uma semana", c: "Já são {dias} dias sem treinar. Volta hoje, mesmo que seja leve. 💪" },
  { t: "Estamos te esperando, {nome}", c: "{dias} dias sem check-in. Se a rotina mudou, me chama no WhatsApp que a gente ajusta o treino." },
  { t: "Vamos retomar, {nome}?", c: "Faz {dias} dias parado. Um treino hoje já quebra o gelo." },
  { t: "{nome}, não desiste agora", c: "Dar uma travada acontece. Bora voltar juntos esta semana? 💪" },
  { t: "Sentimos sua falta na academia", c: "Faz {dias} dias sem treinar. Se algo está pegando, me chama no WhatsApp." },
  { t: "Bora, {nome}!", c: "Seu treino está pronto e te esperando há {dias} dias. Vamos?" },
];
const CHAMADA_LONGA: Modelo[] = [ // 14 dias ou mais
  { t: "{nome}, tudo bem por aí?", c: "Faz {dias} dias sem treinar. Se estiver difícil, fala comigo no WhatsApp. A gente acha um jeito." },
  { t: "Saudade, {nome}", c: "{dias} dias longe do treino. Qualquer treino leve hoje já é um começo. 💪" },
  { t: "{nome}, vamos recomeçar?", c: "Você já mostrou que consegue. Bora reacender isso com um treino leve hoje?" },
  { t: "Passando pra te chamar, {nome}", c: "Faz {dias} dias sem check-in. Quer que eu monte um treino mais curto pra voltar?" },
  { t: "Você faz falta, {nome}", c: "Faz {dias} dias sem treinar. Volta hoje que a gente ajusta o resto juntos." },
];
function hashSlug(s: string): number { let h = 0; for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0; return h; }
async function chamadasLer(deps: Deps): Promise<Record<string, { ts: number; t: string; c: string; ix: number }>> {
  try { const v = await deps.kv.get(AUTH_STORE, CHAMADA_KEY); return v && typeof v === "object" ? v : {}; } catch (e) { return {}; }
}
function chamadaTexto(m: Modelo, nome: string, dias: number): Modelo {
  const sub = (s: string) => s.split("{nome}").join(nome).split("{dias}").join(String(dias));
  return { t: limpaTexto(sub(m.t), 80), c: limpaTexto(sub(m.c), 160) };
}
// Dispara as chamadas. Devolve quantas foram feitas, quantas já tinham sido feitas nas últimas horas e o horário de cada uma.
// opts.push: manda o aviso no celular (padrão). opts.forca: ignora a janela de 20 h (usado pelo botão do WhatsApp, que é ação deliberada do personal).
// Devolve também msgs: o texto de cada chamada, para o personal mandar pelo WhatsApp.
export async function chamaAlunos(deps: Deps, now: number, slugs: unknown, opts: { push?: boolean; forca?: boolean } = {}): Promise<{ chamados: number; comPush: number; pulados: number; ts: Record<string, number>; msgs: Record<string, string> }> {
  const out = { chamados: 0, comPush: 0, pulados: 0, ts: {} as Record<string, number>, msgs: {} as Record<string, string> };
  const comPush = opts.push !== false;
  const forca = opts.forca === true;
  try {
    const lista = [...new Set((Array.isArray(slugs) ? slugs : []).filter((x) => typeof x === "string" && x.length > 0 && x.length <= 80))].slice(0, 60) as string[];
    const st = await loadState(deps);
    const students: Record<string, any> = st.data?.students || {};
    const reg = await chamadasLer(deps);
    const hoje = diaBR(now);
    for (const slug of lista) {
      const rec = students[slug];
      if (!rec) continue;
      const prev = reg[slug];
      if (!forca && prev && now - Number(prev.ts) < CHAMADA_INTERVALO_H * 3600_000) { out.pulados++; continue; }
      const ord = [...datasAtivas(rec)].sort();
      const ultimo = ord.length ? ord[ord.length - 1] : "";
      const base = ultimo || (Number(rec.primeiroAcessoEm) ? diaBR(Number(rec.primeiroAcessoEm)) : hoje);
      const dias = Math.max(0, diasEntre(base, hoje));
      const modelos = dias >= 14 ? CHAMADA_LONGA : dias >= 7 ? CHAMADA_FIRME : CHAMADA_LEVE;
      const ix = (prev && Number.isInteger(prev.ix) ? prev.ix + 1 : hashSlug(slug)) % modelos.length;
      const primeiro = String(rec.nome || "").trim().split(/\s+/)[0] || "aluno";
      const msg = chamadaTexto(modelos[ix], primeiro, dias);
      let n = 0;
      if (comPush) { try { n = await PUSH.enviar(deps.kv, AUTH_STORE, [slug], { title: msg.t, body: msg.c, tag: "chamada" }, now, deps.fetch); } catch (e) { n = 0; } }
      reg[slug] = { ts: now, t: msg.t, c: msg.c, ix };
      out.chamados++;
      out.ts[slug] = now;
      out.msgs[slug] = msg.t + "\n" + msg.c;
      if (n) out.comPush++;
    }
    for (const k of Object.keys(reg)) if (!students[k]) delete reg[k];
    if (out.chamados) await deps.kv.set(AUTH_STORE, CHAMADA_KEY, reg);
  } catch (e) { /* nunca derruba o app: o personal tenta de novo */ }
  return out;
}


// ---------- alertas automáticos para o aluno ir treinar (tarefa agendada, ver functions/lembretes.mts) ----------
// Roda todo dia de manhã (8h de Brasília). Cada aluno com push ligado recebe NO MÁXIMO 1 aviso por dia, escolhido nesta ordem:
//   1) 14 dias parado  2) 7 dias parado  3) fogo do mês em risco  4) 3 dias parado  5) dia de treino habitual  6) meta da semana
// Cada aviso vale uma vez por situação (não insiste) e há um teto de 3 avisos a cada 7 dias (14 e 7 dias parado furam o teto).
// Aos 7 e 14 dias parado o PERSONAL também recebe um aviso (um só, juntando os nomes), mesmo se o aluno não tiver push.
// Tudo automático: nenhuma configuração por aluno.
const LEMB_KEY = "lembretes";
const ALERTA_TETO_7D = 3;
type RegAlerta = { ts: number; n: number; ultimo: string; hist: number[]; est: number; estPara: string; fogo: string; metaQui: string; metaDom: string; habDia: string; dia: string };
const DIA_MS = 86400_000;
function diasEntre(a: string, b: string): number { return Math.round((Date.parse(b + "T00:00:00Z") - Date.parse(a + "T00:00:00Z")) / DIA_MS); }
function dowBR(dia: string): number { return new Date(dia + "T00:00:00Z").getUTCDay(); } // 0=domingo
function diasNoMes(dia: string): number { const y = Number(dia.slice(0, 4)), m = Number(dia.slice(5, 7)); return new Date(Date.UTC(y, m, 0)).getUTCDate(); }
function planoAtivo(rec: any): any {
  const plans = Array.isArray(rec?.plans) ? rec.plans.filter((p: any) => p && !p.archived) : [];
  return plans.find((p: any) => p.id === rec?.activePlanId) || plans[0] || null;
}
// Meta da semana = quantos treinos o plano ativo tem (entre 2 e 5).
function metaSemanal(rec: any): number {
  const n = Array.isArray(planoAtivo(rec)?.treinos) ? planoAtivo(rec).treinos.length : 0;
  return Math.max(2, Math.min(5, n || 3));
}
function proximoTreinoNome(rec: any): string {
  const pl = planoAtivo(rec);
  const t = Array.isArray(pl?.treinos) ? pl.treinos : [];
  if (!t.length) return "";
  return limpaTexto(t[((Number(pl.rotationIdx) || 0) % t.length + t.length) % t.length]?.nome, 40);
}
// Dias da semana em que o aluno costuma treinar: nas últimas 8 semanas, o dia caiu em 3+ semanas diferentes (mín. 6 treinos no total).
function diasHabituais(datas: Set<string>, hoje: string): Set<number> {
  const cont: Record<number, number> = {};
  let total = 0;
  for (const d of datas) { const df = diasEntre(d, hoje); if (df < 1 || df > 56) continue; total++; cont[dowBR(d)] = (cont[dowBR(d)] || 0) + 1; }
  const out = new Set<number>();
  if (total < 6) return out;
  for (const k of Object.keys(cont)) if (cont[Number(k)] >= 3) out.add(Number(k));
  return out;
}
// Check-in automático no servidor: o treino que ficou parado SESSAO_CHECKIN_MIN minutos sem concluir
// marca o check-in do dia dele, mesmo que o aluno nunca mais abra o app. Mesma regra do app
// (saRegistraCheckinSessao em index.html); como o check-in é único por dia, rodar de novo não duplica.
const SESSAO_CHECKIN_MIN = 30;
export async function rodaCheckinAuto(deps: Deps, now: number): Promise<{ marcados: number; alunos: string[] }> {
  const out = { marcados: 0, alunos: [] as string[] };
  try {
    const st = await loadState(deps);
    const students: Record<string, any> = st.data?.students || {};
    let mudou = false;
    for (const slug of Object.keys(students)) {
      const rec = students[slug];
      const sess = rec && rec.sessaoEmAndamento;
      if (!sess || !sess.ultimaMudanca) continue;
      if (now - Number(sess.ultimaMudanca) < SESSAO_CHECKIN_MIN * 60_000) continue;
      const dia = typeof sess.date === "string" && /^\d{4}-\d{2}-\d{2}$/.test(sess.date) ? sess.date : diaBR(Number(sess.ultimaMudanca));
      if (!Array.isArray(rec.checkins)) rec.checkins = [];
      if (rec.checkins.indexOf(dia) !== -1) continue;
      rec.checkins.push(dia);
      rec.checkins.sort();
      out.marcados++;
      out.alunos.push(slug);
      mudou = true;
    }
    if (mudou) await deps.kv.set(STATE_STORE, STATE_KEY, { ...st, version: (st.version || 0) + 1, data: st.data });
  } catch (e) {}
  return out;
}
export async function rodaLembretes(deps: Deps, now: number): Promise<{ enviados: number; alunos: string[]; personal?: string[] }> {
  const out = { enviados: 0, alunos: [] as string[], personal: [] as string[] };
  try {
    const st = await loadState(deps);
    const students: Record<string, any> = st.data?.students || {};
    const subs = await PUSH.loadSubs(deps.kv, AUTH_STORE);
    const reg: Record<string, RegAlerta> = (await deps.kv.get(AUTH_STORE, LEMB_KEY)) || {};
    const hoje = diaBR(now);
    const dow = dowBR(hoje);
    const segunda = semanaBR(now)[0];
    const mes = hoje.slice(0, 7);
    const restamMes = diasNoMes(hoje) - Number(hoje.slice(8, 10)) + 1; // contando hoje
    const paraPersonal: { nome: string; dias: number }[] = [];
    for (const slug of Object.keys(students)) {
      const rec = students[slug];
      if (!rec) continue;
      const datas = datasAtivas(rec);
      const ord = [...datas].sort();
      const ultimo = ord.length ? ord[ord.length - 1] : "";
      const base = ultimo || (Number(rec.primeiroAcessoEm) ? diaBR(Number(rec.primeiroAcessoEm)) : "");
      if (!base) continue;
      const dias = diasEntre(base, hoje);
      const r0: any = reg[slug] || {};
      const r: RegAlerta = { ts: r0.ts || 0, n: r0.n || 0, ultimo: r0.ultimo || "", hist: Array.isArray(r0.hist) ? r0.hist.filter((t: number) => now - t < 7 * DIA_MS) : [], est: r0.est || 0, estPara: r0.estPara || "", fogo: r0.fogo || "", metaQui: r0.metaQui || "", metaDom: r0.metaDom || "", habDia: r0.habDia || "", dia: r0.dia || "" };
      reg[slug] = r;
      if (r.estPara !== base) { r.est = 0; r.estPara = base; } // treinou desde o último aviso: recomeça a escada de 3/7/14 dias
      const nome = String(rec.nome || "").trim().split(/\s+/)[0] || "";
      const comPush = (subs[slug] || []).length > 0;
      // Escada de dias parado (vale para o aviso do personal mesmo sem push do aluno)
      const degrau = dias >= 14 ? 14 : dias >= 7 ? 7 : dias >= 3 ? 3 : 0;
      const novoDegrau = degrau > r.est ? degrau : 0;
      if (novoDegrau >= 7) paraPersonal.push({ nome: nomeCurto(rec.nome), dias });
      if (!comPush || r.dia === hoje || datas.has(hoje)) { if (novoDegrau) r.est = novoDegrau; continue; }
      const noTeto = r.hist.length >= ALERTA_TETO_7D;
      let msg: { t: string; c: string; tag: string } | null = null;
      let marca: () => void = () => {};
      const parado = ultimo ? "Faz " + dias + " dias que você não treina." : "Seu primeiro treino está te esperando.";
      const diasMes = [...datas].filter((d) => d.slice(0, 7) === mes).length;
      const alvoFogo = diasMes < 8 ? 8 : diasMes < 20 ? 20 : 0;
      const faltaFogo = alvoFogo ? alvoFogo - diasMes : 0;
      const dentroSemana = ord.filter((d) => d >= segunda && d <= hoje).length;
      const meta = metaSemanal(rec);
      if (novoDegrau === 14) {
        msg = { t: (nome ? nome + ", " : "") + "estamos com saudade", c: parado + " Que tal um treino leve hoje? Qualquer treino já vale. 💪", tag: "lembrete" };
      } else if (novoDegrau === 7) {
        msg = { t: (nome ? nome + ", " : "") + "uma semana sem treinar", c: parado + " Volte hoje, mesmo que seja um treino curtinho. 💪", tag: "lembrete" };
      } else if (!noTeto && alvoFogo && faltaFogo >= 1 && faltaFogo <= 3 && restamMes <= 5 && faltaFogo <= restamMes && r.fogo !== mes + ":" + alvoFogo) {
        const sel = alvoFogo === 8 ? "🔥" : "👑";
        msg = { t: sel + " " + (faltaFogo === 1 ? "Falta 1 treino" : "Faltam " + faltaFogo + " treinos") + " para o seu " + sel + " do mês", c: "O mês termina em " + (restamMes === 1 ? "1 dia" : restamMes + " dias") + ". Treine hoje e garanta!", tag: "fogo" };
        marca = () => { r.fogo = mes + ":" + alvoFogo; };
      } else if (!noTeto && novoDegrau === 3) {
        msg = { t: (nome ? nome + ", " : "") + "sentimos sua falta", c: parado + " Bora retomar hoje? 💪", tag: "lembrete" };
      } else if (!noTeto && dias <= 2 && r.habDia !== hoje && diasHabituais(datas, hoje).has(dow)) {
        const prox = proximoTreinoNome(rec);
        msg = { t: "Hoje é dia de treino" + (nome ? ", " + nome : "") + "!", c: prox ? "Seu treino de hoje: " + prox + ". Bora? 💪" : "Seu treino está te esperando. Bora? 💪", tag: "dia-treino" };
        marca = () => { r.habDia = hoje; };
      } else if (!noTeto && dow === 4 && r.metaQui !== segunda && dentroSemana < meta && meta - dentroSemana <= 4 && datas.size > 0 && dias < 7) {
        const f = meta - dentroSemana;
        msg = { t: "Meta da semana: " + dentroSemana + " de " + meta + " treinos", c: (f === 1 ? "Falta 1 treino" : "Faltam " + f + " treinos") + " para fechar a semana. Ainda dá tempo! 💪", tag: "meta-semana" };
        marca = () => { r.metaQui = segunda; };
      } else if (!noTeto && dow === 0 && r.metaDom !== segunda && dentroSemana < meta && meta - dentroSemana <= 2 && dentroSemana >= 1) {
        const f = meta - dentroSemana;
        msg = { t: "Último dia da semana!", c: "Você fez " + dentroSemana + " de " + meta + " treinos. " + (f === 1 ? "Falta 1 pra bater a meta" : "Faltam " + f + " pra bater a meta") + ". Bora fechar? 💪", tag: "meta-semana" };
        marca = () => { r.metaDom = segunda; };
      }
      if (novoDegrau) r.est = novoDegrau;
      if (!msg) continue;
      const n = await PUSH.enviar(deps.kv, AUTH_STORE, [slug], { title: limpaTexto(msg.t, 80), body: limpaTexto(msg.c, 160), tag: msg.tag }, now, deps.fetch);
      marca();
      r.ts = now; r.n += 1; r.dia = hoje; r.hist.push(now); r.ultimo = ultimo;
      if (n) { out.enviados += n; out.alunos.push(slug); }
    }
    if (paraPersonal.length) {
      const ord = paraPersonal.sort((a, b) => b.dias - a.dias);
      const nomes = ord.slice(0, 4).map((x) => x.nome + " (" + x.dias + "d)").join(", ") + (ord.length > 4 ? " e mais " + (ord.length - 4) : "");
      await avisa(deps, now, ["trainer"], ord.length === 1 ? "1 aluno sem treinar há 7+ dias" : ord.length + " alunos sem treinar há 7+ dias", nomes, "alunos-parados");
      out.personal = ord.map((x) => x.nome);
    }
    for (const k of Object.keys(reg)) if (!students[k]) delete reg[k];
    await deps.kv.set(AUTH_STORE, LEMB_KEY, reg);
  } catch (e) { /* tarefa agendada: tenta de novo amanhã */ }
  return out;
}

// ---------- feed da galera + fotos ----------
// Quem pode ler/escrever o feed: o personal (token) ou um aluno que informa o próprio código.
// O código do aluno NUNCA é devolvido nas respostas (só o personal vê o código, para moderar).
async function who(req: Request, deps: Deps, now: number, slug: unknown, body?: any): Promise<{ err?: Response; trainer?: boolean; slug?: string | null; rec?: any; st?: any }> {
  const auth = await loadAuth(deps);
  const trainer = !!deps.admin || (await tokenValid(bearer(req, body), auth, now));
  if (!trainer && bearer(req, body)) return { err: reply(401, { error: "token_invalido" }) };
  const st = await loadState(deps);
  const tk = await throttleKey(deps);
  const thr = await throttleLoad(deps);
  if (!trainer && (thr[tk]?.miss?.length || 0) >= MISS_LIMIT) return { err: reply(429, { error: "muitas_tentativas" }) };
  const rec = typeof slug === "string" && slug && slug.length <= 80 ? st.data?.students?.[slug] || null : null;
  if (!trainer && !rec) {
    thr[tk] = thr[tk] || { miss: [], leads: [], ups: [] };
    thr[tk].miss.push(now);
    await deps.kv.set(AUTH_STORE, THROTTLE_KEY, thr);
    return { err: reply(404, { error: "codigo_nao_encontrado" }) };
  }
  return { trainer, slug: rec ? (slug as string) : null, rec, st };
}

const FOTO_URL = /^\/api\/img\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
function nomeCurto(nome: unknown): string {
  const parts = String(nome || "").trim().split(/\s+/).filter(Boolean);
  if (!parts.length) return "Aluno";
  const first = parts[0].slice(0, 24);
  const last = parts.length > 1 ? parts[parts.length - 1] : "";
  return last && last.toLowerCase() !== first.toLowerCase() ? first + " " + last.charAt(0).toUpperCase() + "." : first;
}
function limpaTexto(v: unknown, max: number): string {
  return String(v == null ? "" : v).replace(/[\u0000-\u001f\u007f]+/g, " ").replace(/\s+/g, " ").trim().slice(0, max);
}
function diaBR(now: number): string { return new Date(now - 3 * 3600_000).toISOString().slice(0, 10); }


// ---------- comunidade: ranking da semana, fogo do mês e emojis ao lado do nome ----------
// Tudo é calculado aqui, a partir dos registros dos alunos que já estão no banco, para o app
// nunca precisar baixar o registro de outra pessoa. O que sai daqui: primeiro nome + inicial,
// foto de perfil, dias treinados e emojis. Nada de cargas, saúde ou código de acesso.
const ISO_DIA = /^\d{4}-\d\d-\d\d$/;
function datasAtivas(rec: any): Set<string> {
  const set = new Set<string>();
  for (const ss of Array.isArray(rec?.sessoes) ? rec.sessoes : []) if (typeof ss?.date === "string" && ISO_DIA.test(ss.date)) set.add(ss.date);
  for (const c of Array.isArray(rec?.checkins) ? rec.checkins : []) if (typeof c === "string" && ISO_DIA.test(c)) set.add(c);
  return set;
}
function semanaBR(now: number): string[] {
  const d = new Date(diaBR(now) + "T00:00:00Z");
  d.setUTCDate(d.getUTCDate() - ((d.getUTCDay() + 6) % 7)); // segunda-feira
  const out: string[] = [];
  for (let i = 0; i < 7; i++) { out.push(d.toISOString().slice(0, 10)); d.setUTCDate(d.getUTCDate() + 1); }
  return out;
}
// Mesma regra do app (ver comEmojis no index.html): 👑 20+ dias no mês, 🔥 8+, 💪 5+ recordes,
// 🏋️ 12+ dias, 🏆 1+ meta batida; no máximo 3 emojis.
function emojisDe(diasMes: number, prs: number, metas: number): string {
  const e: string[] = [];
  if (diasMes >= 20) e.push("👑"); else if (diasMes >= 8) e.push("🔥");
  if (metas >= 1) e.push("🏆");
  if (prs >= 5) e.push("💪");
  if (diasMes >= 12) e.push("🏋️");
  return e.slice(0, 3).join("");
}
function resumoAluno(rec: any, now: number) {
  const datas = datasAtivas(rec);
  const mes = diaBR(now).slice(0, 7);
  let diasMes = 0;
  for (const d of datas) if (d.slice(0, 7) === mes) diasMes++;
  const semana = semanaBR(now);
  const dots = semana.map((d) => datas.has(d));
  const prs = Math.max(0, Math.min(9999, Number(rec?.prTotal) || 0));
  const metas = Math.max(0, Math.min(99, Number(rec?.comMetasFeitas) || 0));
  return { diasMes, dots, dias: dots.filter(Boolean).length, emojis: emojisDe(diasMes, prs, metas) };
}
function fotoDe(rec: any): string { return typeof rec?.fotoUrl === "string" && FOTO_URL.test(rec.fotoUrl) ? rec.fotoUrl : ""; }

async function getComunidade(req: Request, url: URL, deps: Deps, now: number): Promise<Response> {
  const w = await who(req, deps, now, url.searchParams.get("slug"));
  if (w.err) return w.err;
  const students = w.st.data?.students || {};
  const rows: any[] = [];
  for (const slug of Object.keys(students)) {
    const rec = students[slug];
    if (!rec || rec.feedOff || rec.rankOff) continue;
    const r = resumoAluno(rec, now);
    rows.push({ nome: nomeCurto(rec.nome), avatar: fotoDe(rec), dias: r.dias, dots: r.dots, diasMes: r.diasMes, emojis: r.emojis, me: !!w.slug && slug === w.slug, ...(w.trainer ? { slug } : {}) });
  }
  rows.sort((a, b) => b.dias - a.dias || b.diasMes - a.diasMes || a.nome.localeCompare(b.nome));
  const top = rows.slice(0, 15);
  const meu = rows.find((r) => r.me);
  if (meu && !top.includes(meu)) top.push(meu);
  const eu = w.rec ? resumoAluno(w.rec, now) : null;
  const janela = janelaRankingMes(now);
  const rankingMes = janela ? { ...rankingMesDe(students, janela.mes, w.slug || null, !!w.trainer), fechado: janela.fechado, diasParaFechar: janela.diasParaFechar } : null;
  return reply(200, { hoje: diaBR(now), semana: semanaBR(now), ranking: top, total: rows.length, eu: eu ? { diasMes: eu.diasMes, dias: eu.dias, emojis: eu.emojis, participando: !w.rec.rankOff && !w.rec.feedOff } : null, rankingMes });
}

// ---------- ranking do mês (aba Turma) ----------
// Aparece do dia 24 ao último dia do mês (mês em andamento, "fecha em X dias") e nos dias 1 a 7 do mês seguinte (mês que fechou).
const MESES_PT = ["janeiro", "fevereiro", "março", "abril", "maio", "junho", "julho", "agosto", "setembro", "outubro", "novembro", "dezembro"];
export function janelaRankingMes(now: number): { mes: string; fechado: boolean; diasParaFechar: number } | null {
  const hoje = diaBR(now);
  const dia = Number(hoje.slice(8, 10));
  const mes = hoje.slice(0, 7);
  if (dia >= 24) return { mes, fechado: false, diasParaFechar: diasNoMes(hoje) - dia };
  if (dia <= 7) {
    const y = Number(mes.slice(0, 4)), m = Number(mes.slice(5, 7));
    const anterior = m === 1 ? (y - 1) + "-12" : y + "-" + String(m - 1).padStart(2, "0");
    return { mes: anterior, fechado: true, diasParaFechar: 0 };
  }
  return null;
}
// Números de um aluno no mês. Evolução é só porcentagem (sem kg), igual à regra de privacidade da comunidade.
function metricasMes(rec: any, mes: string): { dias: number; sequencia: number; evolucao: number | null; semanasMeta: number } {
  const datas = [...datasAtivas(rec)].filter((d) => d.slice(0, 7) === mes).sort();
  let seq = 0, atual = 0, prev = "";
  for (const d of datas) { atual = prev && diasEntre(prev, d) === 1 ? atual + 1 : 1; if (atual > seq) seq = atual; prev = d; }
  // Evolução: para cada exercício com registro em 2 dias ou mais no mês, compara a maior carga do primeiro dia com a do último (em %).
  const porEx = new Map<string, { d: string; v: number }[]>();
  for (const ss of Array.isArray(rec?.sessoes) ? rec.sessoes : []) {
    if (!ss || typeof ss.date !== "string" || ss.date.slice(0, 7) !== mes || !Array.isArray(ss.cargasLog)) continue;
    for (const c of ss.cargasLog) {
      const v = parseFloat(String(c?.valor ?? "").replace(",", "."));
      if (!c || !c.exercicio || !(v > 0) || v > 1000) continue;
      const k = String(c.exercicio).trim().toUpperCase();
      if (!porEx.has(k)) porEx.set(k, []);
      porEx.get(k)!.push({ d: ss.date, v });
    }
  }
  const pcts: number[] = [];
  for (const arr of porEx.values()) {
    const dias = [...new Set(arr.map((x) => x.d))].sort();
    if (dias.length < 2) continue;
    const ini = Math.max(...arr.filter((x) => x.d === dias[0]).map((x) => x.v));
    const fim = Math.max(...arr.filter((x) => x.d === dias[dias.length - 1]).map((x) => x.v));
    pcts.push(Math.min(100, ((fim - ini) / ini) * 100));
  }
  const evolucao = pcts.length ? Math.round((pcts.reduce((a, b) => a + b, 0) / pcts.length) * 10) / 10 : null;
  // Constância: semanas (segunda a domingo) em que o aluno bateu a meta semanal.
  const meta = metaSemanal(rec);
  const porSemana = new Map<string, number>();
  for (const d of datas) {
    const dt = new Date(d + "T00:00:00Z");
    dt.setUTCDate(dt.getUTCDate() - ((dt.getUTCDay() + 6) % 7));
    const seg = dt.toISOString().slice(0, 10);
    porSemana.set(seg, (porSemana.get(seg) || 0) + 1);
  }
  let semanasMeta = 0;
  for (const n of porSemana.values()) if (n >= meta) semanasMeta++;
  return { dias: datas.length, sequencia: seq, evolucao, semanasMeta };
}
function rankingMesDe(students: Record<string, any>, mes: string, meuSlug: string | null, trainer: boolean) {
  const linhas: any[] = [];
  for (const slug of Object.keys(students)) {
    const rec = students[slug];
    if (!rec || rec.feedOff || rec.rankOff) continue;
    const m = metricasMes(rec, mes);
    if (!m.dias) continue;
    linhas.push({ slug, nome: nomeCurto(rec.nome), avatar: fotoDe(rec), me: slug === meuSlug, ...m });
  }
  const categoria = (key: string, label: string, emoji: string, unidade: string, valorDe: (l: any) => number | null, desempate: (a: any, b: any) => number, filtro: (l: any) => boolean) => {
    const ord = linhas.filter((l) => valorDe(l) != null && filtro(l))
      .sort((a, b) => (valorDe(b)! - valorDe(a)!) || desempate(b, a) || a.nome.localeCompare(b.nome));
    const idxMeu = ord.findIndex((l) => l.me);
    const pt = (l: any, pos: number) => ({ pos, nome: l.nome, avatar: l.avatar, valor: valorDe(l), me: l.me, ...(trainer ? { slug: l.slug } : {}) });
    return {
      key, label, emoji, unidade,
      top: ord.slice(0, 3).map((l, i) => pt(l, i + 1)),
      minha: idxMeu >= 3 ? pt(ord[idxMeu], idxMeu + 1) : null,
      total: ord.length
    };
  };
  const cats = [
    categoria("treinou", "Mais treinou", "🏋️", "dias", (l) => l.dias, (a, b) => a.sequencia - b.sequencia, () => true),
    categoria("disciplina", "Mais disciplinado", "🔥", "dias seguidos", (l) => l.sequencia, (a, b) => a.dias - b.dias, (l) => l.sequencia >= 2),
    categoria("evolucao", "Mais evoluiu", "📈", "% de carga", (l) => l.evolucao, (a, b) => a.dias - b.dias, (l) => l.evolucao != null && l.evolucao > 0),
    categoria("constancia", "Mais constante", "🎯", "semanas com meta", (l) => l.semanasMeta, (a, b) => a.dias - b.dias, (l) => l.semanasMeta >= 1),
  ];
  const [a, m] = mes.split("-").map(Number);
  return { mes, label: MESES_PT[(m || 1) - 1] + " de " + a, total: linhas.length, categorias: cats };
}

async function loadFeed(deps: Deps): Promise<{ posts: any[]; personalFoto?: string }> {
  const f = await deps.kv.get(FEED_STORE, FEED_KEY);
  return f && Array.isArray(f.posts) ? f : { posts: [] };
}

const REACOES = ["💪", "🔥", "👏"];
function reacOut(p: any, slug: string | null | undefined) {
  const r = p && typeof p.reacoes === "object" && p.reacoes ? p.reacoes : {};
  const reacoes: Record<string, number> = {}; const minhas: string[] = [];
  for (const e of REACOES) { const l = Array.isArray(r[e]) ? r[e] : []; reacoes[e] = l.length; if (slug && l.includes(slug)) minhas.push(e); }
  return { reacoes, minhas };
}

async function getFeed(req: Request, url: URL, deps: Deps, now: number): Promise<Response> {
  const w = await who(req, deps, now, url.searchParams.get("slug"));
  if (w.err) return w.err;
  const feed = await loadFeed(deps);
  const students = w.st.data?.students || {};
  const posts: any[] = [];
  for (const p of feed.posts) {
    const likes: string[] = Array.isArray(p.likes) ? p.likes : [];
    if (p.tipo === "personal") { // post do próprio personal: vai para a turma toda ou só para alguns alunos
      const para: string[] | null = Array.isArray(p.para) && p.para.length ? p.para : null;
      if (!w.trainer && para && !(w.slug && para.includes(w.slug))) continue;
      posts.push({
        id: p.id, tipo: "personal", texto: p.texto, foto: p.foto || "", ts: p.ts,
        nome: TRAINER_NOME, avatar: feed.personalFoto && FOTO_URL.test(feed.personalFoto) ? feed.personalFoto : "", emojis: "", treino: "", pr: null, cargas: [], meta: "", personal: "", personalTs: 0, fixado: !!p.fixado,
        likes: likes.length, liked: !!w.slug && likes.includes(w.slug), mine: false, ...reacOut(p, w.slug),
        ...(w.trainer ? { slug: "", para } : {}),
      });
      if (posts.length >= 40) break;
      continue;
    }
    const rec = students[p.slug];
    if (!rec || rec.feedOff) continue; // aluno removido ou que pediu para não aparecer
    posts.push({
      id: p.id, tipo: p.tipo, texto: p.texto, foto: p.foto || "", ts: p.ts,
      nome: nomeCurto(rec.nome),
      avatar: fotoDe(rec),
      emojis: resumoAluno(rec, now).emojis,
      treino: p.treino || "", pr: p.pr || null, cargas: Array.isArray(p.cargas) ? p.cargas : [], meta: p.meta || "", personal: p.personal || "", personalTs: p.personalTs || 0, fixado: !!p.fixado,
      likes: likes.length, liked: !!w.slug && likes.includes(w.slug), mine: !!w.slug && p.slug === w.slug, ...reacOut(p, w.slug),
      ...(p.colab ? { colab: TRAINER_NOME, colabAvatar: feed.personalFoto && FOTO_URL.test(feed.personalFoto) ? feed.personalFoto : "" } : {}),
      ...(w.trainer ? { slug: p.slug } : {}),
    });
    if (posts.length >= 40) break;
  }
  posts.sort((a, b) => (b.fixado ? 1 : 0) - (a.fixado ? 1 : 0)); // fixados pelo personal primeiro (ordem estável)
  return reply(200, { posts, personalFoto: feed.personalFoto && FOTO_URL.test(feed.personalFoto) ? feed.personalFoto : "" });
}


// ---------- turma: pertencimento (meta coletiva, desafios, aluno da semana, encontros, celebrações, dica) ----------
// Tudo é calculado a partir dos registros dos alunos (dias treinados) e do que o personal cadastra.
// Só aparece gente que não saiu do feed; os outros alunos só veem primeiro nome + inicial e a foto.
const TURMA_KEY = "turma";
const MARCOS_TREINOS = [10, 25, 50, 100, 150, 200, 300, 500];
const MARCOS_MESES = [1, 3, 6, 12];
const DT_LOCAL = /^\d{4}-\d\d-\d\dT\d\d:\d\d$/;
async function loadTurma(deps: Deps): Promise<any> {
  const t = await deps.kv.get(FEED_STORE, TURMA_KEY);
  return { nome: "", meta: null, desafios: [], eventos: [], destaques: [], dica: null, parabens: {}, ...(t && typeof t === "object" ? t : {}) };
}
function isoDia(v: unknown): string { return typeof v === "string" && ISO_DIA.test(v) ? v : ""; }
function addDias(dia: string, n: number): string { const d = new Date(dia + "T00:00:00Z"); d.setUTCDate(d.getUTCDate() + n); return d.toISOString().slice(0, 10); }
function contaNoPeriodo(datas: Set<string>, de: string, ate: string): number { let n = 0; for (const d of datas) if (d >= de && d <= ate) n++; return n; }
function inteiro(v: unknown, min: number, max: number): number | null { const n = Math.round(Number(v)); return Number.isFinite(n) && n >= min && n <= max ? n : null; }

function marcosDe(students: Record<string, any>, now: number): any[] {
  const hoje = diaBR(now), lim = addDias(hoje, -14), out: any[] = [];
  for (const slug of Object.keys(students)) {
    const rec = students[slug];
    if (!rec || rec.feedOff) continue;
    const datas = [...datasAtivas(rec)].sort();
    for (const m of MARCOS_TREINOS) if (datas.length >= m && datas[m - 1] >= lim && datas[m - 1] <= hoje) out.push({ slug, tipo: "treinos", valor: m, dia: datas[m - 1] });
    const base = Number(rec.primeiroAcessoEm) || 0;
    if (base > 0) {
      const dia0 = diaBR(base);
      if (dia0 >= addDias(hoje, -7) && dia0 <= hoje) out.push({ slug, tipo: "entrou", valor: 0, dia: dia0 });
      for (const mm of MARCOS_MESES) { const dia = addDias(dia0, mm * 30); if (dia <= hoje && dia >= lim) out.push({ slug, tipo: "meses", valor: mm, dia }); }
    }
  }
  out.sort((a, b) => b.dia.localeCompare(a.dia) || a.slug.localeCompare(b.slug));
  return out.slice(0, 30).map((m) => ({ ...m, id: m.slug + ":" + m.tipo + ":" + m.valor }));
}

async function getTurma(req: Request, url: URL, deps: Deps, now: number): Promise<Response> {
  const w = await who(req, deps, now, url.searchParams.get("slug"));
  if (w.err) return w.err;
  const students: Record<string, any> = w.st.data?.students || {};
  const T = await loadTurma(deps);
  const hoje = diaBR(now), semana = semanaBR(now), semPrev = semana.map((d) => addDias(d, -7));
  const vis = Object.keys(students).filter((k) => students[k] && !students[k].feedOff);
  const datas: Record<string, Set<string>> = {};
  for (const k of vis) datas[k] = datasAtivas(students[k]);
  let treinosSem = 0, treinosPrev = 0, ativosSem = 0, treinouHoje = 0;
  for (const k of vis) {
    const a = semana.filter((d) => datas[k].has(d)).length;
    treinosSem += a; if (a) ativosSem++;
    treinosPrev += semPrev.filter((d) => datas[k].has(d)).length;
    if (datas[k].has(hoje)) treinouHoje++;
  }
  const quem = (k: string) => ({ nome: nomeCurto(students[k].nome), avatar: fotoDe(students[k]) });

  let meta: any = null;
  if (T.meta && T.meta.ate && addDias(T.meta.ate, 7) >= hoje) {
    const feito = vis.reduce((s, k) => s + contaNoPeriodo(datas[k], T.meta.de, T.meta.ate), 0);
    meta = { titulo: T.meta.titulo || "Meta da turma", alvo: T.meta.alvo, feito, de: T.meta.de, ate: T.meta.ate, ativa: hoje <= T.meta.ate, bateu: feito >= T.meta.alvo,
      diasRestantes: Math.max(0, Math.round((Date.parse(T.meta.ate + "T00:00:00Z") - Date.parse(hoje + "T00:00:00Z")) / 86400000)) };
  }

  const desafios = (T.desafios as any[]).filter((d) => addDias(d.ate, 45) >= hoje).map((d) => {
    const part = Object.keys(d.entrou || {}).filter((k) => datas[k]);
    const rows = part.map((k) => { const feito = contaNoPeriodo(datas[k], d.de, d.ate); return { slug: k, ...quem(k), feito, concluiu: feito >= d.alvo }; });
    const meu = w.slug ? { entrou: !!(d.entrou && d.entrou[w.slug]), feito: datas[w.slug] ? contaNoPeriodo(datas[w.slug], d.de, d.ate) : 0 } : null;
    return {
      id: d.id, nome: d.nome, emoji: d.emoji, de: d.de, ate: d.ate, alvo: d.alvo, criadoEm: d.criadoEm || 0,
      ativo: hoje <= d.ate && !d.encerrado, futuro: hoje < d.de, participantes: rows.length, concluiram: rows.filter((r) => r.concluiu).length,
      meu: meu ? { ...meu, concluiu: meu.entrou && meu.feito >= d.alvo } : null,
      quem: rows.filter((r) => r.concluiu).slice(0, 10).map((r) => r.nome),
      ...(w.trainer ? { rows: rows.sort((a, b) => b.feito - a.feito || a.nome.localeCompare(b.nome)) } : {}),
    };
  }).sort((a, b) => (Number(b.ativo) - Number(a.ativo)) || (a.ativo ? a.ate.localeCompare(b.ate) : b.ate.localeCompare(a.ate))).slice(0, 8);

  const agoraLocal = new Date(now - 3 * 3600_000).toISOString().slice(0, 16);
  const eventos = (T.eventos as any[]).filter((e) => e.quando >= addDias(hoje, -1) + "T00:00").sort((a: any, b: any) => a.quando.localeCompare(b.quando)).slice(0, 8).map((e: any) => {
    const ids = Object.keys(e.rsvp || {}).filter((k) => students[k] && !students[k].feedOff);
    return { id: e.id, titulo: e.titulo, quando: e.quando, local: e.local || "", texto: e.texto || "", criadoEm: e.criadoEm || 0, passou: e.quando < agoraLocal,
      vou: ids.length, vouEu: !!(w.slug && e.rsvp && e.rsvp[w.slug]), quem: ids.slice(0, 8).map((k) => nomeCurto(students[k].nome)) };
  });

  const dst = (T.destaques as any[])[0];
  let destaque: any = null;
  if (dst && students[dst.slug] && !students[dst.slug].feedOff && now - dst.ts < 8 * 86400_000) destaque = { ...quem(dst.slug), frase: dst.frase || "", ts: dst.ts, eu: !!w.slug && dst.slug === w.slug, ...(w.trainer ? { slug: dst.slug } : {}) };

  const dica = T.dica && T.dica.texto && T.dica.dia >= addDias(hoje, -1) ? { texto: T.dica.texto, dia: T.dica.dia, ts: T.dica.ts || 0 } : null;

  const marcos = marcosDe(students, now).map((m) => {
    const par: string[] = (T.parabens[m.id] && Array.isArray(T.parabens[m.id].s)) ? T.parabens[m.id].s : [];
    return { id: m.id, ...quem(m.slug), tipo: m.tipo, valor: m.valor, dia: m.dia, parabens: par.length, parabenizei: !!w.slug && par.includes(w.slug), meu: !!w.slug && m.slug === w.slug, ...(w.trainer ? { slug: m.slug } : {}) };
  });

  let selos: any[] = [];
  if (w.slug && students[w.slug]) {
    const ds = datasAtivas(students[w.slug]);
    for (const d of T.desafios as any[]) if (d.entrou && d.entrou[w.slug] && contaNoPeriodo(ds, d.de, d.ate) >= d.alvo) selos.push({ tipo: "desafio", nome: d.nome, emoji: d.emoji, dia: d.ate });
    for (const x of T.destaques as any[]) if (x.slug === w.slug) selos.push({ tipo: "destaque", nome: "Aluno da semana", emoji: "🏅", dia: x.semana });
    for (const m of MARCOS_TREINOS) if (ds.size >= m) selos.push({ tipo: "treinos", nome: m + " treinos", emoji: "💯", valor: m });
    selos = selos.slice(0, 60);
  }

  return reply(200, {
    hoje, nome: T.nome || "", total: vis.length, ativosSemana: ativosSem, treinosSemana: treinosSem, treinosSemanaPassada: treinosPrev, treinouHoje,
    meta, desafios, eventos, destaque, dica, marcos, selos, eu: w.slug || null,
  });
}

async function postTurma(req: Request, deps: Deps, now: number): Promise<Response> {
  const body = await readJson(req);
  if (!body || typeof body !== "object") return reply(400, { error: "bad_json" });
  const w = await who(req, deps, now, body.slug, body);
  if (w.err) return w.err;
  const action = String(body.action || "");
  const students: Record<string, any> = w.st.data?.students || {};
  const T = await loadTurma(deps);
  const hoje = diaBR(now);
  const save = async () => {
    T.eventos = (T.eventos as any[]).filter((e) => e.quando >= addDias(hoje, -14) + "T00:00").slice(0, 40);
    T.desafios = (T.desafios as any[]).filter((d) => addDias(d.ate, 60) >= hoje).slice(0, 20);
    for (const id of Object.keys(T.parabens)) if (!T.parabens[id] || now - (T.parabens[id].ts || 0) > 30 * 86400_000) delete T.parabens[id];
    await deps.kv.set(FEED_STORE, TURMA_KEY, T);
  };
  const novoId = (p: string) => p + now.toString(36) + Math.random().toString(36).slice(2, 6);

  // ----- ações do personal -----
  const soPersonal = ["turma_nome", "meta_set", "meta_clear", "desafio_criar", "desafio_encerrar", "destaque_set", "destaque_clear", "evento_criar", "evento_apagar", "dica_set"];
  if (soPersonal.includes(action)) {
    if (!w.trainer || w.slug) return reply(403, { error: "sem_permissao" });
    if (action === "turma_nome") { T.nome = limpaTexto(body.nome, 40); await save(); return reply(200, { ok: true }); }
    if (action === "meta_clear") { T.meta = null; await save(); return reply(200, { ok: true }); }
    if (action === "meta_set") {
      const alvo = inteiro(body.alvo, 5, 5000), ate = isoDia(body.ate);
      if (alvo === null || !ate || ate < hoje || ate > addDias(hoje, 120)) return reply(400, { error: "pedido_invalido" });
      const de = body.inicioMes ? hoje.slice(0, 7) + "-01" : hoje;
      T.meta = { titulo: limpaTexto(body.titulo, 60), alvo, de, ate, criadaEm: now };
      await save(); return reply(200, { ok: true });
    }
    if (action === "desafio_criar") {
      const nome = limpaTexto(body.nome, 40), dias = inteiro(body.dias, 3, 60);
      if (!nome || dias === null) return reply(400, { error: "pedido_invalido" });
      const alvo = inteiro(body.alvo, 1, dias);
      if (alvo === null) return reply(400, { error: "pedido_invalido" });
      const de = isoDia(body.de) || hoje;
      if (de < hoje || de > addDias(hoje, 60)) return reply(400, { error: "pedido_invalido" });
      if ((T.desafios as any[]).filter((d) => hoje <= d.ate && !d.encerrado).length >= 6) return reply(409, { error: "limite_desafios" });
      const emoji = [...limpaTexto(body.emoji, 8)].slice(0, 2).join("") || "🏆";
      T.desafios.unshift({ id: novoId("d"), nome, emoji, de, ate: addDias(de, dias - 1), alvo, entrou: {}, criadoEm: now });
      await save();
      await avisa(deps, now, Object.keys(students).filter((k) => !students[k]?.feedOff), "Novo desafio: " + nome, "Treinar " + alvo + " de " + dias + " dias. Toque para entrar.", "desafio");
      return reply(200, { ok: true });
    }
    if (action === "desafio_encerrar") {
      const d = (T.desafios as any[]).find((x) => x.id === body.id);
      if (!d) return reply(404, { error: "nao_encontrado" });
      d.encerrado = true; if (d.ate >= hoje) d.ate = addDias(hoje, -1) < d.de ? d.de : addDias(hoje, -1);
      await save(); return reply(200, { ok: true });
    }
    if (action === "destaque_clear") { T.destaques = []; await save(); return reply(200, { ok: true }); }
    if (action === "destaque_set") {
      const slug = typeof body.aluno === "string" ? body.aluno : "";
      const rec = students[slug];
      if (!rec) return reply(404, { error: "nao_encontrado" });
      if (rec.feedOff) return reply(400, { error: "aluno_fora_do_feed" });
      const frase = limpaTexto(body.frase, 140);
      const semana = semanaBR(now)[0];
      T.destaques = (T.destaques as any[]).filter((x) => x.semana !== semana);
      T.destaques.unshift({ semana, slug, frase, ts: now });
      T.destaques = T.destaques.slice(0, 40);
      if (body.postar !== false) { // avisa a turma no feed, com a foto do aluno
        const feed = await loadFeed(deps);
        const nome = nomeCurto(rec.nome);
        const post: any = { id: novoId("p"), slug: "", tipo: "personal", texto: ("🏅 Aluno da semana: " + nome + (frase ? " — " + frase : "")).slice(0, 280), foto: fotoDe(rec), ts: now, dia: hoje, likes: [] as string[] };
        feed.posts.unshift(post);
        feed.posts = feed.posts.filter((p) => p.fixado || now - p.ts < 45 * 24 * 3600_000).slice(0, MAX_POSTS);
        await deps.kv.set(FEED_STORE, FEED_KEY, feed);
      }
      await save();
      await avisa(deps, now, [slug], "🏅 Você é o aluno da semana!", frase || "Parabéns pela dedicação, " + nomeCurto(rec.nome) + "!", "destaque");
      return reply(200, { ok: true });
    }
    if (action === "evento_criar") {
      const titulo = limpaTexto(body.titulo, 60), quando = typeof body.quando === "string" ? body.quando : "";
      if (!titulo || !DT_LOCAL.test(quando) || isNaN(Date.parse(quando + ":00Z"))) return reply(400, { error: "pedido_invalido" });
      if (quando < new Date(now - 3 * 3600_000 - 3600_000).toISOString().slice(0, 16)) return reply(400, { error: "no_passado" });
      if ((T.eventos as any[]).length >= 30) return reply(409, { error: "limite_eventos" });
      T.eventos.push({ id: novoId("e"), titulo, quando, local: limpaTexto(body.local, 80), texto: limpaTexto(body.texto, 200), rsvp: {}, criadoEm: now });
      await save();
      const ev = T.eventos[T.eventos.length - 1];
      await avisa(deps, now, Object.keys(students).filter((k) => !students[k]?.feedOff), "Novo encontro: " + titulo, quando.slice(8, 10) + "/" + quando.slice(5, 7) + " às " + quando.slice(11, 16).replace(":", "h") + (ev.local ? " · " + ev.local : "") + ". Confirme sua presença.", "evento");
      return reply(200, { ok: true });
    }
    if (action === "evento_apagar") { T.eventos = (T.eventos as any[]).filter((e) => e.id !== body.id); await save(); return reply(200, { ok: true }); }
    if (action === "dica_set") {
      const texto = limpaTexto(body.texto, 200);
      T.dica = texto ? { texto, dia: hoje, ts: now } : null;
      await save();
      if (texto) await avisa(deps, now, Object.keys(students).filter((k) => !students[k]?.feedOff), "💡 Dica do dia", texto, "dica");
      return reply(200, { ok: true });
    }
  }

  // ----- ações do aluno -----
  if (!w.slug || !students[w.slug]) return reply(403, { error: "sem_permissao" });
  if (students[w.slug].feedOff) return reply(400, { error: "fora_do_feed" });
  if (action === "desafio_entrar") {
    const d = (T.desafios as any[]).find((x) => x.id === body.id);
    if (!d || d.encerrado || hoje > d.ate) return reply(404, { error: "nao_encontrado" });
    d.entrou = d.entrou && typeof d.entrou === "object" ? d.entrou : {};
    if (body.sair) delete d.entrou[w.slug]; else d.entrou[w.slug] = now;
    await save(); return reply(200, { ok: true, entrou: !body.sair });
  }
  if (action === "evento_rsvp") {
    const e = (T.eventos as any[]).find((x) => x.id === body.id);
    if (!e) return reply(404, { error: "nao_encontrado" });
    e.rsvp = e.rsvp && typeof e.rsvp === "object" ? e.rsvp : {};
    if (body.vou === false) delete e.rsvp[w.slug]; else e.rsvp[w.slug] = now;
    await save(); return reply(200, { ok: true, vou: body.vou !== false });
  }
  if (action === "parabenizar") {
    const m = marcosDe(students, now).find((x) => x.id === body.id);
    if (!m || m.slug === w.slug) return reply(404, { error: "nao_encontrado" });
    const cur = T.parabens[m.id] && Array.isArray(T.parabens[m.id].s) ? T.parabens[m.id] : { s: [] as string[], ts: now };
    const i = cur.s.indexOf(w.slug);
    if (i >= 0) cur.s.splice(i, 1); else cur.s.push(w.slug);
    cur.ts = now; T.parabens[m.id] = cur;
    await save(); return reply(200, { ok: true, parabenizei: i < 0, parabens: cur.s.length });
  }
  return reply(400, { error: "acao_invalida" });
}

const FEED_TIPOS = ["treino", "recorde", "sequencia", "livre"];
const TRAINER_NOME = "Matheus";
async function postFeed(req: Request, deps: Deps, now: number): Promise<Response> {
  const body = await readJson(req);
  if (!body || typeof body !== "object") return reply(400, { error: "bad_json" });
  const w = await who(req, deps, now, body.slug, body);
  if (w.err) return w.err;
  const action = String(body.action || "");
  const feed = await loadFeed(deps);
  const save = async () => { await deps.kv.set(FEED_STORE, FEED_KEY, feed); };

  if (action === "personalfoto") { // foto de perfil do personal (aparece nos posts dele)
    if (!w.trainer || w.slug) return reply(403, { error: "sem_permissao" });
    const f = typeof body.foto === "string" ? body.foto : "";
    if (f && !FOTO_URL.test(f)) return reply(400, { error: "pedido_invalido" });
    if (f) feed.personalFoto = f; else delete feed.personalFoto;
    await save();
    return reply(200, { ok: true, personalFoto: f });
  }
  if (action === "post" && w.trainer && !w.slug && String(body.tipo || "") === "personal") {
    const texto = limpaTexto(body.texto, 280);
    const foto = typeof body.foto === "string" && FOTO_URL.test(body.foto) ? body.foto : "";
    if (!texto && !foto) return reply(400, { error: "vazio" });
    const dia = diaBR(now);
    if (feed.posts.filter((p) => p.tipo === "personal" && p.dia === dia).length >= 20) return reply(429, { error: "limite_diario" });
    const students = w.st.data?.students || {};
    const para = Array.isArray(body.para) ? [...new Set<string>(body.para.filter((x: any) => typeof x === "string" && x.length <= 80 && students[x]))].slice(0, 300) : [];
    if (body.fixar && feed.posts.filter((p) => p.fixado).length >= 3) return reply(409, { error: "limite_fixados" });
    const post: any = { id: "p" + now.toString(36) + Math.random().toString(36).slice(2, 6), slug: "", tipo: "personal", texto, foto, ts: now, dia, likes: [] as string[] };
    if (para.length) post.para = para;
    if (body.fixar) post.fixado = true;
    feed.posts.unshift(post);
    feed.posts = feed.posts.filter((p) => p.fixado || now - p.ts < 45 * 24 * 3600_000).slice(0, MAX_POSTS);
    await save();
    const alvos: string[] = post.para ? post.para : Object.keys(students).filter((k) => !students[k]?.feedOff);
    await avisa(deps, now, alvos, "Matheus postou no feed", texto || "Nova foto", "feed-personal");
    return reply(200, { ok: true, id: post.id });
  }
  if (action === "post" && w.trainer && !w.slug && String(body.tipo || "") === "colab") {
    // Foto do personal com o aluno, publicada na conta do aluno (estilo colaboração do Instagram).
    const students = w.st.data?.students || {};
    const alvo = typeof body.aluno === "string" ? body.aluno : "";
    const rec = students[alvo];
    if (!rec) return reply(404, { error: "nao_encontrado" });
    if (rec.feedOff) return reply(400, { error: "aluno_fora_do_feed" });
    const foto = typeof body.foto === "string" && FOTO_URL.test(body.foto) ? body.foto : "";
    if (!foto) return reply(400, { error: "vazio" });
    const texto = limpaTexto(body.texto, 280);
    const dia = diaBR(now);
    if (feed.posts.filter((p) => p.colab && p.dia === dia).length >= 15) return reply(429, { error: "limite_diario" });
    const post: any = { id: "p" + now.toString(36) + Math.random().toString(36).slice(2, 6), slug: alvo, tipo: "livre", texto, foto, ts: now, dia, likes: [] as string[], colab: true };
    feed.posts.unshift(post);
    feed.posts = feed.posts.filter((p) => p.fixado || now - p.ts < 45 * 24 * 3600_000).slice(0, MAX_POSTS);
    await save();
    await avisa(deps, now, [alvo], "Matheus postou uma foto com você", texto || "Veja no feed da turma", "colab");
    return reply(200, { ok: true, id: post.id });
  }
  if (action === "post") {
    if (!w.slug) return reply(400, { error: "pedido_invalido" });
    const tipo = String(body.tipo || "");
    if (!FEED_TIPOS.includes(tipo)) return reply(400, { error: "tipo_invalido" });
    if (w.rec.feedOff) return reply(200, { ok: true, skipped: "oculto" });
    const texto = limpaTexto(body.texto, tipo === "livre" ? 280 : 140);
    const foto = typeof body.foto === "string" && FOTO_URL.test(body.foto) ? body.foto : "";
    if (tipo === "livre" && !texto && !foto) return reply(400, { error: "vazio" });
    if (tipo !== "livre" && !texto) return reply(400, { error: "vazio" });
    const dia = diaBR(now);
    const hoje = feed.posts.filter((p) => p.slug === w.slug && p.dia === dia);
    if ((tipo === "treino" || tipo === "sequencia") && hoje.some((p) => p.tipo === tipo)) return reply(200, { ok: true, skipped: "ja_postado" });
    if (tipo === "recorde" && (hoje.filter((p) => p.tipo === "recorde").length >= 6 || hoje.some((p) => p.tipo === "recorde" && p.texto === texto))) return reply(200, { ok: true, skipped: "limite" });
    if (tipo === "livre" && hoje.filter((p) => p.tipo === "livre").length >= 10) return reply(429, { error: "limite_diario" });
    const post: any = { id: "p" + now.toString(36) + Math.random().toString(36).slice(2, 6), slug: w.slug, tipo, texto, foto, ts: now, dia, likes: [] as string[] };
    const treino = limpaTexto(body.treino, 60);
    if (treino) post.treino = treino;
    const pr = body.pr && typeof body.pr === "object" ? { ex: limpaTexto(body.pr.ex, 60), antes: limpaTexto(body.pr.antes, 14), agora: limpaTexto(body.pr.agora, 14) } : null;
    if (pr && pr.ex && pr.agora) post.pr = pr;
    if (Array.isArray(body.cargas)) {
      const cs = body.cargas.slice(0, 5).map((c: any) => ({ ex: limpaTexto(c?.ex, 40), v: limpaTexto(c?.v, 28) })).filter((c: any) => c.ex && c.v);
      if (cs.length) post.cargas = cs;
    }
    const meta = limpaTexto(body.meta, 120);
    if (meta) post.meta = meta;
    feed.posts.unshift(post);
    feed.posts = feed.posts.filter((p) => p.fixado || now - p.ts < 45 * 24 * 3600_000).slice(0, MAX_POSTS);
    await save();
    if (tipo === "livre" || tipo === "recorde") await avisa(deps, now, ["trainer"], nomeCurto(w.rec?.nome) + " postou no feed", tipo === "recorde" ? "Novo recorde: " + (post.pr?.ex || texto) : (texto || "Nova foto"), "feed-aluno");
    return reply(200, { ok: true, id: post.id });
  }

  const id = typeof body.id === "string" ? body.id : "";
  const post = feed.posts.find((p) => p.id === id);
  if (!post) return reply(404, { error: "post_nao_encontrado" });

  if (action === "like") {
    if (!w.slug) return reply(400, { error: "pedido_invalido" });
    post.likes = Array.isArray(post.likes) ? post.likes : [];
    const i = post.likes.indexOf(w.slug);
    if (i >= 0) post.likes.splice(i, 1); else post.likes.push(w.slug);
    await save();
    return reply(200, { likes: post.likes.length, liked: i < 0 });
  }
  if (action === "reagir") { // 💪 🔥 👏 (um de cada por aluno)
    const e = String(body.emoji || "");
    if (!w.slug || !REACOES.includes(e)) return reply(400, { error: "pedido_invalido" });
    post.reacoes = post.reacoes && typeof post.reacoes === "object" ? post.reacoes : {};
    const l: string[] = Array.isArray(post.reacoes[e]) ? post.reacoes[e] : [];
    const i = l.indexOf(w.slug);
    if (i >= 0) l.splice(i, 1); else l.push(w.slug);
    post.reacoes[e] = l;
    await save();
    return reply(200, { ok: true, ...reacOut(post, w.slug) });
  }
  if (action === "comentar") {
    if (!w.trainer) return reply(403, { error: "sem_permissao" }); // só o personal comenta nos posts
    const texto = limpaTexto(body.texto, 200);
    if (post.tipo === "personal") return reply(400, { error: "pedido_invalido" });
    if (texto) { post.personal = texto; post.personalTs = now; } else { delete post.personal; delete post.personalTs; }
    await save();
    if (texto && post.slug) await avisa(deps, now, [post.slug], "Matheus respondeu seu post", texto, "resposta");
    return reply(200, { ok: true, personal: texto });
  }
  if (action === "fixar") {
    if (!w.trainer) return reply(403, { error: "sem_permissao" });
    if (post.fixado) delete post.fixado;
    else {
      if (feed.posts.filter((p) => p.fixado).length >= 3) return reply(409, { error: "limite_fixados" });
      post.fixado = true;
    }
    await save();
    return reply(200, { ok: true, fixado: !!post.fixado });
  }
  if (action === "delete") {
    if (!w.trainer && post.slug !== w.slug) return reply(403, { error: "sem_permissao" });
    feed.posts = feed.posts.filter((p) => p.id !== id);
    await save();
    return reply(200, { ok: true });
  }
  return reply(400, { error: "acao_invalida" });
}

function detectaImagem(u: Uint8Array): string | null {
  if (u.length > 12 && u[0] === 0xff && u[1] === 0xd8 && u[2] === 0xff) return "image/jpeg";
  if (u.length > 12 && u[0] === 0x89 && u[1] === 0x50 && u[2] === 0x4e && u[3] === 0x47) return "image/png";
  if (u.length > 12 && u[0] === 0x52 && u[1] === 0x49 && u[2] === 0x46 && u[3] === 0x46 && u[8] === 0x57 && u[9] === 0x45 && u[10] === 0x42 && u[11] === 0x50) return "image/webp";
  return null;
}
async function postImg(req: Request, deps: Deps, now: number): Promise<Response> {
  if (!deps.blobs) return reply(501, { error: "sem_armazenamento" });
  const w = await who(req, deps, now, req.headers.get("x-slug"));
  if (w.err) return w.err;
  const buf = await req.arrayBuffer();
  if (!buf.byteLength) return reply(400, { error: "vazio" });
  if (buf.byteLength > MAX_IMG) return reply(413, { error: "grande_demais" });
  const type = detectaImagem(new Uint8Array(buf));
  if (!type) return reply(415, { error: "formato_invalido" });
  if (!w.trainer) {
    const tk = await throttleKey(deps);
    const thr = await throttleLoad(deps);
    thr[tk] = thr[tk] || { miss: [], leads: [], ups: [] };
    if ((thr[tk].ups || []).length >= 30) return reply(429, { error: "muitas_tentativas" });
    thr[tk].ups = (thr[tk].ups || []).concat([now]);
    await deps.kv.set(AUTH_STORE, THROTTLE_KEY, thr);
  }
  const id = crypto.randomUUID();
  await deps.blobs.set(id, buf, type);
  return reply(200, { id, url: "/api/img/" + id });
}
async function getImg(id: string, deps: Deps): Promise<Response> {
  if (!deps.blobs || !/^[0-9a-f-]{36}$/.test(id)) return new Response("Not found", { status: 404 });
  const f = await deps.blobs.get(id);
  if (!f) return new Response("Not found", { status: 404 });
  return new Response(f.data, { headers: { "Content-Type": f.type, "Cache-Control": "public, max-age=31536000, immutable", "X-Content-Type-Options": "nosniff" } });
}
