import { test } from "node:test";
import assert from "node:assert/strict";
import { cria, personal } from "./ajuda.mts";

const auth = (t: string) => ({ Authorization: "Bearer " + t });
function base() { return cria({ version: 1, data: { students: { ana: { nome: "Ana Souza", sessoes: [] }, bia: { nome: "Bia", sessoes: [] } }, templates: [], leads: [] }, catalog: [] }); }

test("aluno pergunta, personal vê na lista com não lida, lê e responde; aluno vê a resposta como não lida", async () => {
  const s = base(); const tok = await personal(s);
  const p1 = await s.post("/api/chat", { slug: "ana", txt: "  Posso trocar o leg press pelo hack?  ", tipo: "exercicio", ref: "COXA LEG PRESS 45°" });
  assert.equal(p1.status, 200);
  assert.equal(p1.body.msg.de, "aluno");
  assert.equal(p1.body.msg.txt, "Posso trocar o leg press pelo hack?");
  const l = await s.chama("/api/chat?lista=1", { headers: auth(tok) });
  assert.equal(l.body.naoLidas, 1);
  assert.equal(l.body.conversas[0].slug, "ana");
  assert.equal(l.body.conversas[0].nome, "Ana Souza");
  s.relogio.now += 1000;
  const g = await s.chama("/api/chat?slug=ana&ler=1", { headers: auth(tok) });
  assert.equal(g.body.msgs.length, 1);
  assert.equal(g.body.msgs[0].ref, "COXA LEG PRESS 45°");
  assert.equal((await s.chama("/api/chat?lista=1", { headers: auth(tok) })).body.naoLidas, 0);
  s.relogio.now += 1000;
  const r = await s.post("/api/chat", { slug: "ana", txt: "Pode sim, mesma carga relativa." }, auth(tok));
  assert.equal(r.body.msg.de, "personal");
  assert.equal((await s.chama("/api/chat?slug=ana&contar=1")).body.naoLidas, 1);
  await s.chama("/api/chat?slug=ana&ler=1");
  assert.equal((await s.chama("/api/chat?slug=ana&contar=1")).body.naoLidas, 0);
});

test("lista é só do personal; aluno não lê a conversa de outro; mensagem vazia é recusada", async () => {
  const s = base();
  assert.notEqual((await s.chama("/api/chat?lista=1")).status, 200);
  assert.equal((await s.chama("/api/chat?slug=nao-existe")).status, 404);
  assert.equal((await s.post("/api/chat", { slug: "ana", txt: "   " })).status, 400);
  await s.post("/api/chat", { slug: "ana", txt: "oi" });
  const b = await s.chama("/api/chat?slug=bia");
  assert.equal(b.body.msgs.length, 0);
});

test("limite de 40 mensagens por dia para o aluno e corte em 1000 caracteres", async () => {
  const s = base();
  const r0 = await s.post("/api/chat", { slug: "ana", txt: "x".repeat(1500) });
  assert.equal(r0.body.msg.txt.length, 1000);
  for (let i = 1; i < 40; i++) { s.relogio.now += 10; assert.equal((await s.post("/api/chat", { slug: "ana", txt: "m" + i })).status, 200); }
  assert.equal((await s.post("/api/chat", { slug: "ana", txt: "mais uma" })).status, 429);
});
