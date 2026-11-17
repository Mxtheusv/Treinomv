import { test } from "node:test";
import assert from "node:assert/strict";
import { cria, estadoExemplo, personal } from "./ajuda.mts";
import { rodaBackupDiario } from "../netlify/lib/core.mts";

const auth = (t: string) => ({ Authorization: "Bearer " + t });
const DIA = 86_400_000;

test("visitante sem código não recebe dado nenhum", async () => {
  const s = cria(estadoExemplo());
  await personal(s);
  const r = await s.chama("/api/state");
  assert.equal(r.status, 200);
  assert.deepEqual(r.body.data.students, {});
  assert.equal(r.body.locked, true);
  assert.equal(r.body.hasPin, true);
});

test("PIN: errado não entra, 5 erros bloqueiam, certo entra", async () => {
  const s = cria(estadoExemplo());
  await personal(s);
  for (let i = 0; i < 4; i++) assert.equal((await s.post("/api/auth", { action: "login", pin: "000000" })).status, 401);
  const quinto = await s.post("/api/auth", { action: "login", pin: "000000" });
  assert.equal(quinto.status, 401);
  const bloqueado = await s.post("/api/auth", { action: "login", pin: "123456" });
  assert.equal(bloqueado.status, 429);
  s.relogio.now += 16 * 60_000;
  assert.equal((await s.post("/api/auth", { action: "login", pin: "123456" })).status, 200);
});

test("token falso ou vencido é recusado", async () => {
  const s = cria(estadoExemplo());
  const tok = await personal(s);
  assert.equal((await s.chama("/api/state", { headers: auth(tok.slice(0, -2) + "xx") })).status, 401);
  assert.equal((await s.chama("/api/state", { headers: auth("abc.def") })).status, 401);
  s.relogio.now += 61 * DIA;
  assert.equal((await s.chama("/api/state", { headers: auth(tok) })).status, 401);
});

test("trocar o PIN derruba as sessões antigas", async () => {
  const s = cria(estadoExemplo());
  const tok = await personal(s);
  const novo = await s.post("/api/auth", { action: "change", pin: "654321" }, auth(tok));
  assert.equal(novo.status, 200);
  assert.equal((await s.chama("/api/state", { headers: auth(tok) })).status, 401);
  assert.equal((await s.chama("/api/state", { headers: auth(novo.body.token) })).status, 200);
});

test("hash: PIN novo com 600 mil rodadas; hash antigo é refeito no login sem perder a chave de recuperação", async () => {
  const s = cria(estadoExemplo());
  await personal(s);
  const au = s.mem["treino-online-auth/auth"];
  assert.equal(au.iter, 600000);
  const { webcrypto } = await import("node:crypto");
  const pb = async (pin: string, salt: Uint8Array, it: number) => {
    const k = await webcrypto.subtle.importKey("raw", new TextEncoder().encode(pin), "PBKDF2", false, ["deriveBits"]);
    return Buffer.from(new Uint8Array(await webcrypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: it }, k, 256))).toString("base64");
  };
  const salt = new Uint8Array(16).fill(1), rks = new Uint8Array(16).fill(2);
  Object.assign(au, { salt: Buffer.from(salt).toString("base64"), hash: await pb("123456", salt, 120000), iter: 120000, email: "m@x.com",
    rk: { salt: Buffer.from(rks).toString("base64"), hash: await pb("ABCDEFGHJKLMNPQR", rks, 120000) } });
  s.mem["treino-online-auth/auth"] = au;
  assert.equal((await s.post("/api/auth", { action: "login", pin: "123456", email: "m@x.com" })).status, 200);
  assert.equal(s.mem["treino-online-auth/auth"].iter, 600000);
  assert.equal((await s.post("/api/auth", { action: "login", pin: "123456", email: "m@x.com" })).status, 200);
  assert.equal((await s.post("/api/auth", { action: "login", pin: "123456", email: "outro@x.com" })).status, 401);
  const rec = await s.post("/api/auth", { action: "recover", email: "m@x.com", recoveryKey: "ABCD-EFGH-JKLM-NPQR", pin: "nova-senha-1" });
  assert.equal(rec.status, 200);
});

test("códigos: personal abre e cada aluno ganha código com parte aleatória", async () => {
  const s = cria(estadoExemplo());
  const tok = await personal(s);
  const r = await s.chama("/api/state", { headers: auth(tok) });
  const a = r.body.data.students["ana-souza"].codigo, j = r.body.data.students.joao.codigo;
  assert.match(a, /^ana-[a-hjkmnp-z2-9]{6}$/);
  assert.match(j, /^joao-[a-hjkmnp-z2-9]{6}$/);
  assert.notEqual(a, j);
  assert.ok(r.body.data.codigoLegadoAte > s.relogio.now);
  assert.equal(r.body.data.students["ana-souza"].notas, "Hipertensa");
});

test("códigos: transição do nome antigo para o código novo", async () => {
  const s = cria(estadoExemplo());
  const tok = await personal(s);
  const cod = (await s.chama("/api/state", { headers: auth(tok) })).body.data.students["ana-souza"].codigo;
  // no prazo, o nome ainda abre e já entrega o código
  let r = await s.chama("/api/state?slug=ana-souza");
  assert.equal(r.status, 200);
  assert.equal(r.body.acesso, cod);
  assert.equal(r.body.slugReal, "ana-souza");
  assert.equal(r.body.role, "student");
  assert.deepEqual(Object.keys(r.body.data.students), ["ana-souza"]);
  // abrir pelo código marca a migração e fecha o nome
  r = await s.chama("/api/state?slug=" + cod);
  assert.equal(r.status, 200);
  assert.ok(s.estado().data.students["ana-souza"].codigoUsadoEm);
  assert.equal((await s.chama("/api/state?slug=ana-souza")).status, 404);
  assert.equal((await s.chama("/api/state?slug=ana-souza", { headers: { "X-Acesso": cod } })).status, 200);
  assert.equal((await s.chama("/api/state?slug=ana-souza", { headers: { "X-Acesso": cod.slice(0, -1) + "x" } })).status, 404);
  assert.equal((await s.chama("/api/state?slug=" + cod.toUpperCase())).status, 200);
  assert.equal((await s.chama("/api/state?slug=ana-zzzzzz")).status, 404);
  // prazo acabou: nome de quem não migrou também fecha
  assert.equal((await s.chama("/api/state?slug=joao")).status, 200);
  s.relogio.now = s.estado().data.codigoLegadoAte + 1;
  assert.equal((await s.chama("/api/state?slug=joao")).status, 404);
});

test("antes de existir código, o nome continua funcionando (instalação antiga)", async () => {
  const s = cria(estadoExemplo());
  const r = await s.chama("/api/state?slug=joao");
  assert.equal(r.status, 200);
  assert.equal(r.body.acesso, "");
});

test("o aluno não recebe as anotações do personal", async () => {
  const s = cria(estadoExemplo());
  const r = await s.chama("/api/state?slug=ana-souza");
  assert.equal(r.body.data.students["ana-souza"].notas, undefined);
  assert.equal(r.body.data.students["ana-souza"].nome, "Ana Souza");
});

test("aluno salvando: campos do personal ficam como estavam", async () => {
  const s = cria(estadoExemplo());
  const tok = await personal(s);
  const cod = (await s.chama("/api/state", { headers: auth(tok) })).body.data.students["ana-souza"].codigo;
  const antes = JSON.parse(JSON.stringify(s.estado().data.students["ana-souza"]));
  const hack = { ...antes, nome: "X", notas: "apagado", mesGratisEm: "2030-01-01", codigo: "x", codigoUsadoEm: 1, presencial: true, online: true, ofertaPlanos: true, criadoEm: 1,
    avaliacoes: [{ id: "av1", date: "2026-10-01", por: "aluno", peso: "1", ia: { min: 10, max: 14 } }, { id: "av2", date: "2026-11-01", por: "personal", peso: "59" }],
    sessoes: [{ id: "s1", date: "2026-11-10" }] };
  const r = await s.post("/api/state", { slug: "ana-souza", student: hack }, { "X-Acesso": cod });
  assert.equal(r.status, 200);
  const st = s.estado().data.students["ana-souza"];
  for (const k of ["nome", "notas", "mesGratisEm", "codigo"]) assert.deepEqual(st[k], antes[k], k);
  for (const k of ["presencial", "online", "ofertaPlanos", "criadoEm"]) assert.equal(st[k], undefined, k);
  const a1 = st.avaliacoes.find((a: any) => a.id === "av1"), a2 = st.avaliacoes.find((a: any) => a.id === "av2");
  assert.equal(a1.por, "personal");
  assert.equal(a1.peso, "60");
  assert.equal(a1.ia.min, 10);
  assert.equal(a2.por, "aluno");
  assert.equal(st.sessoes.length, 1);
  assert.deepEqual(st.avaliacoes.map((a: any) => a.id), ["av1", "av2"]);
});

test("aluno não apaga avaliação do personal", async () => {
  const s = cria(estadoExemplo());
  const r = await s.post("/api/state", { slug: "ana-souza", student: { ...s.estado().data.students["ana-souza"], avaliacoes: [] } });
  assert.equal(r.status, 200);
  assert.equal(s.estado().data.students["ana-souza"].avaliacoes.length, 1);
});

test("sem o código ninguém grava no lugar do aluno migrado", async () => {
  const s = cria(estadoExemplo());
  const tok = await personal(s);
  const cod = (await s.chama("/api/state", { headers: auth(tok) })).body.data.students["ana-souza"].codigo;
  await s.chama("/api/state?slug=" + cod);
  const r = await s.post("/api/state", { slug: "ana-souza", student: { nome: "x", sessoes: [] } });
  assert.equal(r.status, 404);
  assert.equal(s.estado().data.students["ana-souza"].nome, "Ana Souza");
});

test("personal salvando: não apaga códigos, dá código a aluno novo e 'gerar novo código' troca na hora", async () => {
  const s = cria(estadoExemplo());
  const tok = await personal(s);
  const g = await s.chama("/api/state", { headers: auth(tok) });
  const cod = g.body.data.students["ana-souza"].codigo, codJ = g.body.data.students.joao.codigo;
  const dados = g.body.data;
  const prazo = dados.codigoLegadoAte;
  delete dados.students["ana-souza"].codigo;
  delete dados.codigoLegadoAte;
  dados.students.carla = { nome: "Carla Dias" };
  dados.students.joao.codigoReset = 1;
  const r = await s.post("/api/state", { data: dados, version: g.body.version, catalog: [] }, auth(tok));
  assert.equal(r.status, 200);
  assert.equal(r.body.codigos["ana-souza"], cod);
  assert.match(r.body.codigos.carla, /^carla-[a-z2-9]{6}$/);
  assert.notEqual(r.body.codigos.joao, codJ);
  assert.equal(s.estado().data.codigoLegadoAte, prazo);
  assert.equal(s.estado().data.students.joao.codigoReset, undefined);
  assert.equal((await s.chama("/api/state?slug=" + codJ)).status, 404);
  assert.equal((await s.chama("/api/state?slug=joao")).status, 404);
  assert.equal((await s.chama("/api/state?slug=" + r.body.codigos.joao)).status, 200);
});

test("personal com versão velha recebe 409 e nada é gravado", async () => {
  const s = cria(estadoExemplo());
  const tok = await personal(s);
  const g = await s.chama("/api/state", { headers: auth(tok) });
  const r = await s.post("/api/state", { data: { students: {} }, version: g.body.version - 1 }, auth(tok));
  assert.equal(r.status, 409);
  assert.ok(s.estado().data.students["ana-souza"]);
});

test("rotas do aluno (comunidade, feed) exigem o código depois da migração", async () => {
  const s = cria(estadoExemplo());
  const tok = await personal(s);
  const cod = (await s.chama("/api/state", { headers: auth(tok) })).body.data.students["ana-souza"].codigo;
  await s.chama("/api/state?slug=" + cod);
  assert.equal((await s.chama("/api/comunidade?slug=ana-souza", { headers: { "X-Acesso": cod } })).status, 200);
  assert.equal((await s.chama("/api/comunidade?slug=ana-souza")).status, 404);
  assert.equal((await s.chama("/api/feed?slug=" + cod)).status, 200);
});

test("muitos códigos errados bloqueiam o IP", async () => {
  const s = cria(estadoExemplo());
  const extra = { ip: "9.9.9.9" };
  for (let i = 0; i < 20; i++) await s.chama("/api/state?slug=nao-existe-" + i, {}, extra);
  assert.equal((await s.chama("/api/state?slug=joao", {}, extra)).status, 429);
});

test("backup: cópia antes da gravação do personal, só uma por hora, e download só para o personal", async () => {
  const s = cria(estadoExemplo());
  const tok = await personal(s);
  let g = await s.chama("/api/state", { headers: auth(tok) });
  await s.post("/api/state", { data: g.body.data, version: g.body.version, catalog: [] }, auth(tok));
  g = await s.chama("/api/state", { headers: auth(tok) });
  await s.post("/api/state", { data: g.body.data, version: g.body.version, catalog: [] }, auth(tok));
  const idx = s.mem["treino-online-backup/indice"];
  assert.equal(Object.keys(idx).length, 1);
  assert.equal((await s.chama("/api/backup")).status, 401);
  const lista = await s.chama("/api/backup", { headers: auth(tok) });
  assert.equal(lista.body.copias.length, 1);
  const c = await s.chama("/api/backup?k=" + lista.body.copias[0].key, { headers: auth(tok) });
  assert.ok(c.body.state.data.students["ana-souza"]);
  assert.equal((await s.chama("/api/backup?k=hora-999", { headers: auth(tok) })).status, 404);
  s.relogio.now += 3_600_000;
  g = await s.chama("/api/state", { headers: auth(tok) });
  await s.post("/api/state", { data: g.body.data, version: g.body.version, catalog: [] }, auth(tok));
  assert.equal(Object.keys(s.mem["treino-online-backup/indice"]).length, 2);
});

test("backup diário grava uma gaveta por dia", async () => {
  const s = cria(estadoExemplo());
  const deps = { kv: s.kv, ip: "x" } as any;
  await rodaBackupDiario(deps, s.relogio.now);
  await rodaBackupDiario(deps, s.relogio.now + 1000);
  await rodaBackupDiario(deps, s.relogio.now + DIA);
  const chaves = Object.keys(s.mem["treino-online-backup/indice"]).filter((k) => k.startsWith("dia-"));
  assert.equal(chaves.length, 2);
});
