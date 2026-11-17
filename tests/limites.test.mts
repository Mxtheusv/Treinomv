// Testes que fecham buracos achados pelo Stryker (teste de mutação): cada um deixava passar uma sabotagem.
import { test } from "node:test";
import assert from "node:assert/strict";
import { cria, estadoExemplo, personal } from "./ajuda.mts";

const auth = (t: string) => ({ Authorization: "Bearer " + t });
const UUID = "0123abcd-4567-89ab-cdef-0123456789ab";

async function migrado() {
  const s = cria(estadoExemplo());
  const tok = await personal(s);
  const cod = (await s.chama("/api/state", { headers: auth(tok) })).body.data.students["ana-souza"].codigo;
  await s.chama("/api/state?slug=" + cod); // aluna usou o código: o nome antigo deixa de valer
  return { s, tok, cod };
}

test("feed e comunidade: códigos errados contam e bloqueiam o IP", async () => {
  const { s, cod } = await migrado();
  const extra = { ip: "8.8.8.8" };
  for (let i = 0; i < 20; i++) assert.equal((await s.chama("/api/feed?slug=chute-" + i, {}, extra)).status, 404);
  assert.equal((await s.chama("/api/feed?slug=" + cod, {}, extra)).status, 429);
  assert.equal((await s.chama("/api/comunidade?slug=" + cod, {}, extra)).status, 429);
  assert.equal((await s.chama("/api/feed?slug=" + cod, {}, { ip: "8.8.4.4" })).status, 200); // outro IP segue normal
});

test("foto: só aceita endereço de imagem deste site, inteiro", async () => {
  const { s, tok } = await migrado();
  const foto = (f: string) => s.post("/api/feed", { action: "personalfoto", foto: f }, auth(tok));
  for (const f of ["https://outro.site/api/img/" + UUID, "/x/api/img/" + UUID, "/api/img/" + UUID + ".svg", "/api/img/" + UUID + "?a=1"]) {
    assert.equal((await foto(f)).status, 400, f);
  }
  const ok = await foto("/api/img/" + UUID);
  assert.equal(ok.status, 200);
  assert.equal(ok.body.personalFoto, "/api/img/" + UUID);
});

test("código também vale quando vem no corpo do pedido (envio em segundo plano)", async () => {
  const { s, cod } = await migrado();
  const antes = s.estado().data.students["ana-souza"];
  const r = await s.post("/api/state", { slug: "ana-souza", acesso: cod, student: { ...antes, sessoes: [{ id: "s9", date: "2026-11-12" }] } });
  assert.equal(r.status, 200);
  assert.equal(s.estado().data.students["ana-souza"].sessoes.length, 1);
  assert.equal((await s.post("/api/state", { slug: "ana-souza", acesso: cod + "x", student: antes })).status, 404);
});
