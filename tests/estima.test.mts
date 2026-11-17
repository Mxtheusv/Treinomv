import { test } from "node:test";
import assert from "node:assert/strict";
import { cria } from "./ajuda.mts";

const IMG = "11111111-1111-1111-1111-111111111111";
function base() {
  const s = cria({ version: 1, data: { students: { ana: { nome: "Ana" } }, templates: [], leads: [] }, catalog: [] });
  s.files[IMG] = { data: new Uint8Array([0xff, 0xd8, 0xff, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]).buffer, type: "image/jpeg" };
  return s;
}
const corpo = { slug: "ana", fotos: ["/api/img/" + IMG], sexo: "F", idade: 28, altura: 165, peso: 64, cintura: 74 };
const ok = (txt = '{"min":18,"max":22,"confianca":"media","obs":"ok"}') => new Response(JSON.stringify({ content: [{ type: "text", text: txt }] }), { status: 200 });

test("sem chave da IA: 503", async () => {
  const r = await base().post("/api/estima", corpo);
  assert.equal(r.status, 503);
});

test("estimativa ok: faixa, centro, modelo e imagem enviados, sem temperature", async () => {
  let enviado: any = null;
  const r = await base().post("/api/estima", corpo, {}, { iaKey: "k", fetch: async (_u: string, i: any) => { enviado = JSON.parse(i.body); return ok('Aqui: {"min":18,"max":22,"confianca":"media","obs":"ok"}'); } });
  assert.equal(r.status, 200);
  assert.equal(r.body.min, 18);
  assert.equal(r.body.max, 22);
  assert.equal(r.body.centro, 20);
  assert.equal(enviado.model, "claude-haiku-5-5");
  assert.equal(enviado.temperature, undefined);
  assert.ok(enviado.max_tokens >= 1024);
  assert.equal(enviado.messages[0].content.filter((c: any) => c.type === "image").length, 1);
});

test("faixa invertida e valores absurdos são corrigidos", async () => {
  const r = await base().post("/api/estima", corpo, {}, { iaKey: "k", fetch: async () => ok('{"min":80,"max":1,"confianca":"xyz"}') });
  assert.equal(r.body.min, 3);
  assert.equal(r.body.max, 60);
  assert.equal(r.body.confianca, "baixa");
});

test("menor de idade, sem foto e código errado são recusados", async () => {
  const opts = { iaKey: "k", fetch: async () => ok() };
  assert.equal((await base().post("/api/estima", { ...corpo, idade: 15 }, {}, opts)).status, 400);
  assert.equal((await base().post("/api/estima", { ...corpo, fotos: ["http://mal.com/x.jpg"] }, {}, opts)).status, 400);
  assert.equal((await base().post("/api/estima", { ...corpo, slug: "nao-existe" }, {}, opts)).status, 404);
});

test("limite de 4 por aluno por dia", async () => {
  const s = base(); const opts = { iaKey: "k", fetch: async () => ok() };
  for (let i = 0; i < 4; i++) assert.equal((await s.post("/api/estima", corpo, {}, opts)).status, 200);
  const r = await s.post("/api/estima", corpo, {}, opts);
  assert.equal(r.status, 429);
  assert.equal(r.body.error, "limite_aluno");
});

test("erros da IA viram mensagens claras", async () => {
  const caso = async (resp: () => Response) => (await base().post("/api/estima", corpo, {}, { iaKey: "k", fetch: async () => resp() })).body;
  assert.equal((await caso(() => new Response("{}", { status: 401 }))).error, "ia_chave");
  assert.equal((await caso(() => new Response('{"error":{"message":"Your credit balance is too low"}}', { status: 400 }))).error, "ia_credito");
  assert.equal((await caso(() => new Response("{}", { status: 429 }))).error, "ia_limite");
  assert.equal((await caso(() => new Response(JSON.stringify({ stop_reason: "refusal", content: [] }), { status: 200 }))).ok, false);
  assert.equal((await caso(() => new Response(JSON.stringify({ stop_reason: "max_tokens", content: [] }), { status: 200 }))).error, "ia_resposta");
});

test("modelo indisponível: tenta o próximo", async () => {
  const usados: string[] = [];
  const r = await base().post("/api/estima", corpo, {}, { iaKey: "k", fetch: async (_u: string, i: any) => { const m = JSON.parse(i.body).model; usados.push(m); return m === "claude-haiku-5-5" ? new Response("{}", { status: 404 }) : ok(); } });
  assert.equal(r.status, 200);
  assert.deepEqual(usados, ["claude-haiku-5-5", "claude-sonnet-5-5"]);
});

test("a chave nunca aparece na resposta de erro", async () => {
  const r = await base().post("/api/estima", corpo, {}, { iaKey: "sk-ant-segredo123", fetch: async () => new Response("bad key sk-ant-segredo123", { status: 400 }) });
  assert.ok(!JSON.stringify(r.body).includes("segredo123"));
});
