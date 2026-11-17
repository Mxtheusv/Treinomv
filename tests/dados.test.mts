import { test } from "node:test";
import assert from "node:assert/strict";
import { cria, estadoExemplo, personal } from "./ajuda.mts";

const auth = (t: string) => ({ Authorization: "Bearer " + t });

async function comCodigos(estado: any = estadoExemplo()) {
  const s = cria(estado);
  const tok = await personal(s);
  const g = await s.chama("/api/state", { headers: auth(tok) });
  return { s, tok, g };
}

test("personal: resposta completa, códigos só mudam a versão uma vez, aluno pronto (seed) entra uma vez", async () => {
  const { s, tok, g } = await comCodigos();
  assert.equal(g.body.role, "trainer"); assert.equal(g.body.email, ""); assert.equal(g.body.hasLogin, false);
  assert.ok(g.body.data.students["mariah-machado"], "cadastro pronto entrou");
  assert.equal(g.body.data.pin, undefined);
  const v = g.body.version;
  const g2 = await s.chama("/api/state", { headers: auth(tok) });
  assert.equal(g2.body.version, v, "segunda abertura não muda nada");
  assert.deepEqual(g2.body.catalog, []);
});

test("aluno pronto (seed) não sobrescreve aluno com o mesmo código", async () => {
  const e = estadoExemplo(); (e.data.students as any)["mariah-machado"] = { nome: "Outra Mariáh", sessoes: [] };
  const { g } = await comCodigos(e);
  assert.equal(g.body.data.students["mariah-machado"].nome, "Outra Mariáh");
});

test("aluno recebe só o próprio registro e nada do personal", async () => {
  const e: any = estadoExemplo();
  e.data.leads = [{ nome: "Lead secreto" }]; e.data.templates = [{ id: "t", nome: "Modelo" }]; e.data.planosVenda = { planos: [{ nome: "Mensal" }] }; e.data.alertaCheckinDias = 5; e.catalog = [{ nome: "SUPINO" }];
  const s = cria(e);
  const r = await s.chama("/api/state?slug=ana-souza");
  assert.deepEqual(Object.keys(r.body.data.students), ["ana-souza"]);
  assert.deepEqual(r.body.data.leads, []); assert.deepEqual(r.body.data.templates, []);
  assert.equal(r.body.data.planosVenda.planos[0].nome, "Mensal");
  assert.equal(r.body.data.alertaCheckinDias, 5);
  assert.equal(r.body.catalog[0].nome, "SUPINO");
  assert.equal(r.body.version, 1);
  assert.equal(s.estado().data.students["ana-souza"].notas, "Hipertensa", "tirar as anotações da resposta não apaga do banco");
});

test("códigos: acento, nome vazio e nomes iguais", async () => {
  const e: any = estadoExemplo();
  e.data.students = { a: { nome: "Érica Ávila" }, b: { nome: "" }, c: { nome: "Ana Lima" }, d: { nome: "Ana Paula" }, x: { nome: "123" } };
  const { g } = await comCodigos(e);
  const c = (k: string) => g.body.data.students[k].codigo;
  assert.match(c("a"), /^erica-/); assert.match(c("b"), /^b-/); assert.match(c("x"), /^aluno-/);
  assert.match(c("c"), /^ana-/); assert.match(c("d"), /^ana-/); assert.notEqual(c("c"), c("d"));
  for (const k of ["a", "b", "c", "d", "x"]) assert.equal(c(k).split("-")[1].length, 6);
});

test("códigos: espaços e maiúsculas no código digitado; nome muito longo não é aceito", async () => {
  const { s, g } = await comCodigos();
  const cod = g.body.data.students.joao.codigo;
  assert.equal((await s.chama("/api/state?slug=" + encodeURIComponent("  " + cod.toUpperCase() + " "))).status, 200);
  assert.equal((await s.chama("/api/state?slug=" + "a".repeat(81))).status, 404);
});

test("prazo do nome antigo: vale até o último milissegundo", async () => {
  const { s, g } = await comCodigos();
  const ate = g.body.data.codigoLegadoAte;
  s.relogio.now = ate - 1;
  assert.equal((await s.chama("/api/state?slug=joao")).status, 200);
  s.relogio.now = ate;
  assert.equal((await s.chama("/api/state?slug=joao")).status, 404);
});

test("migração marcada só uma vez; personal salvando sem o campo não reabre o nome antigo", async () => {
  const { s, tok, g } = await comCodigos();
  const cod = g.body.data.students["ana-souza"].codigo;
  await s.chama("/api/state?slug=" + cod);
  const quando = s.estado().data.students["ana-souza"].codigoUsadoEm;
  s.relogio.now += 5000;
  await s.chama("/api/state?slug=" + cod);
  assert.equal(s.estado().data.students["ana-souza"].codigoUsadoEm, quando);
  const g2 = await s.chama("/api/state", { headers: auth(tok) });
  const dados = g2.body.data; delete dados.students["ana-souza"].codigoUsadoEm;
  await s.post("/api/state", { data: dados, version: g2.body.version }, auth(tok));
  assert.equal(s.estado().data.students["ana-souza"].codigoUsadoEm, quando);
  assert.equal((await s.chama("/api/state?slug=ana-souza")).status, 404);
});

test("aluno salvando: validações do pedido", async () => {
  const s = cria(estadoExemplo());
  const st = s.estado().data.students.joao;
  assert.equal((await s.chama("/api/state", { method: "POST", body: "nada" })).status, 400);
  assert.equal((await s.post("/api/state", { student: st })).status, 400);
  assert.equal((await s.post("/api/state", { slug: "joao" })).status, 400);
  assert.equal((await s.post("/api/state", { slug: "joao", student: [1] })).status, 400);
  assert.equal((await s.post("/api/state", { slug: "a".repeat(81), student: st })).status, 400);
  assert.equal((await s.post("/api/state", { slug: "joao", student: { ...st, x: "a".repeat(3_000_001) } })).status, 413);
  assert.equal((await s.post("/api/state", { slug: "joao", student: st }, auth("x.y"))).status, 401);
  const r = await s.post("/api/state", { slug: "joao", student: { ...st, novidadesVistas: 3 } });
  assert.equal(r.status, 200); assert.equal(r.body.version, 2); assert.equal(s.estado().version, 2);
  assert.equal(s.estado().data.students.joao.novidadesVistas, 3);
});

test("aluno salvando: sem avaliações não cria o campo; entradas vazias somem; o aluno apaga as próprias", async () => {
  const s = cria(estadoExemplo());
  await s.post("/api/state", { slug: "joao", student: { nome: "João", sessoes: [] } });
  assert.equal(s.estado().data.students.joao.avaliacoes, undefined);
  await s.post("/api/state", { slug: "joao", student: { nome: "João", sessoes: [], avaliacoes: [null, { id: 5, por: "personal" }] } });
  assert.deepEqual(s.estado().data.students.joao.avaliacoes, [{ id: 5, por: "aluno" }]);
  await s.post("/api/state", { slug: "joao", student: { nome: "João", sessoes: [] } });
  assert.deepEqual(s.estado().data.students.joao.avaliacoes, []);
});

test("muitos códigos errados também bloqueiam a gravação", async () => {
  const s = cria(estadoExemplo()); const extra = { ip: "7.7.7.7" };
  for (let i = 0; i < 20; i++) await s.post("/api/state", { slug: "x" + i, student: {} }, {}, extra);
  assert.equal((await s.post("/api/state", { slug: "joao", student: { nome: "João" } }, {}, extra)).status, 429);
  assert.equal((await s.chama("/api/comunidade?slug=joao", {}, extra)).status, 429);
});

test("personal salvando: validações, PIN nunca gravado, catálogo preservado", async () => {
  const { s, tok, g } = await comCodigos({ ...estadoExemplo(), catalog: [{ nome: "SUPINO" }] });
  assert.equal((await s.post("/api/state", { version: g.body.version }, auth(tok))).status, 400);
  assert.equal((await s.post("/api/state", { data: { students: null }, version: g.body.version }, auth(tok))).status, 400);
  const r = await s.post("/api/state", { data: { ...g.body.data, pin: "1234" }, version: g.body.version, catalog: "x" }, auth(tok));
  assert.equal(r.status, 200); assert.equal(r.body.version, g.body.version + 1);
  assert.equal(s.estado().data.pin, undefined);
  assert.deepEqual(s.estado().catalog, [{ nome: "SUPINO" }]);
  assert.equal(r.body.codigoLegadoAte, g.body.data.codigoLegadoAte);
  const r2 = await s.post("/api/state", { data: g.body.data, version: r.body.version, catalog: [{ nome: "B" }] }, auth(tok));
  assert.equal(r2.status, 200); assert.deepEqual(s.estado().catalog, [{ nome: "B" }]);
  const conflito = await s.post("/api/state", { data: g.body.data, version: 1 }, auth(tok));
  assert.equal(conflito.status, 409); assert.equal(conflito.body.version, r2.body.version); assert.equal(conflito.body.data.pin, undefined);
});

test("rotas do aluno: token inválido 401, personal acessa sem código", async () => {
  const { s, tok } = await comCodigos();
  assert.equal((await s.chama("/api/comunidade?slug=joao", { headers: auth("x.y") })).status, 401);
  assert.equal((await s.chama("/api/comunidade", { headers: auth(tok) })).status, 200);
  assert.equal((await s.chama("/api/comunidade?slug=nao-existe", { headers: auth(tok) })).status, 200);
  assert.equal((await s.chama("/api/comunidade")).status, 404);
});

test("backup: índice com versão e número de alunos, lista em ordem, download com nome de arquivo", async () => {
  const { s, tok } = await comCodigos();
  for (let h = 0; h < 3; h++) {
    const g = await s.chama("/api/state", { headers: auth(tok) });
    await s.post("/api/state", { data: g.body.data, version: g.body.version }, auth(tok));
    s.relogio.now += 3_600_000;
  }
  const lista = (await s.chama("/api/backup", { headers: auth(tok) })).body.copias;
  assert.equal(lista.length, 3);
  assert.ok(lista[0].ts > lista[1].ts && lista[1].ts > lista[2].ts);
  assert.equal(lista[0].alunos, 3); assert.ok(lista[0].version > lista[2].version);
  assert.match(lista[0].key, /^hora-\d+$/);
  const n = Math.floor((s.relogio.now - 3_600_000) / 3_600_000) % 48;
  assert.equal(lista[0].key, "hora-" + n);
  const d = await s.chama("/api/backup?k=" + lista[0].key, { headers: auth(tok) });
  assert.match(d.headers.get("content-disposition") || "", /^attachment; filename="treino-online-backup-\d{4}-\d\d-\d\d-\d\d-\d\d\.json"$/);
  assert.equal(d.headers.get("content-type"), "application/json");
  assert.equal(d.headers.get("cache-control"), "no-store");
  assert.equal(d.body.ts, lista[0].ts);
  assert.equal((await s.chama("/api/backup", { headers: auth("x.y") })).status, 401);
});

test("backup: 48 gavetas por hora se revezam", async () => {
  const { s, tok } = await comCodigos();
  for (let h = 0; h < 50; h++) {
    const g = await s.chama("/api/state", { headers: auth(tok) });
    await s.post("/api/state", { data: g.body.data, version: g.body.version }, auth(tok));
    s.relogio.now += 3_600_000;
  }
  assert.equal(Object.keys(s.mem["treino-online-backup/indice"]).length, 48);
});

test("backup diário devolve resumo", async () => {
  const s = cria(estadoExemplo());
  const { rodaBackupDiario } = await import("../netlify/lib/core.mts");
  const r = await rodaBackupDiario({ kv: s.kv, ip: "x" } as any, s.relogio.now);
  assert.deepEqual(r, { ok: true, alunos: 2, version: 1 });
  const idx = s.mem["treino-online-backup/indice"];
  const k = Object.keys(idx)[0];
  assert.equal(k, "dia-" + (Math.floor(s.relogio.now / 86_400_000) % 30));
  assert.deepEqual({ v: idx[k].version, a: idx[k].alunos }, { v: 1, a: 2 });
  assert.equal(s.mem["treino-online-backup/" + k].state.data.students.joao.nome, "João");
});
