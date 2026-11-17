import { test } from "node:test";
import assert from "node:assert/strict";
import { cria, estadoExemplo } from "./ajuda.mts";

const auth = (t: string) => ({ Authorization: "Bearer " + t });
const MIN = 60_000;

test("setup: tamanho mínimo, máximo e só uma vez", async () => {
  const s = cria(estadoExemplo());
  let r = await s.post("/api/auth", { action: "setup", pin: "12345" });
  assert.equal(r.status, 400); assert.equal(r.body.min, 6);
  r = await s.post("/api/auth", { action: "setup", pin: "1".repeat(101) });
  assert.equal(r.status, 400);
  r = await s.post("/api/auth", { action: "setup", pin: " 123456 " });
  assert.equal(r.status, 200);
  assert.equal(r.body.recoveryKey, undefined, "PIN simples não tem chave de recuperação");
  assert.equal((await s.chama("/api/state", { headers: auth(r.body.token) })).status, 200);
  assert.equal((await s.post("/api/auth", { action: "login", pin: "123456" })).status, 200, "PIN com espaços nas pontas é aparado");
  r = await s.post("/api/auth", { action: "setup", pin: "999999" });
  assert.equal(r.status, 409);
  assert.equal((await s.post("/api/auth", { action: "login", pin: "999999" })).status, 401);
});

test("setup com e-mail exige e-mail válido e senha de 8+", async () => {
  const s = cria(estadoExemplo());
  assert.equal((await s.post("/api/auth", { action: "setup", email: "a@b.c", pin: "12345678" })).status, 400);
  assert.equal((await s.post("/api/auth", { action: "setup", email: "a b@c.com", pin: "12345678" })).status, 400);
  const curta = await s.post("/api/auth", { action: "setup", email: "m@x.com", pin: "1234567" });
  assert.equal(curta.status, 400); assert.equal(curta.body.min, 8);
  assert.equal((await s.post("/api/auth", { action: "setup", email: "m@x.com", pin: "1".repeat(101) })).status, 400);
  const ok = await s.post("/api/auth", { action: "setup", email: " M@X.com ", pin: "12345678" });
  assert.equal(ok.status, 200); assert.match(ok.body.recoveryKey, /^[A-HJ-NP-Z2-9]{4}(-[A-HJ-NP-Z2-9]{4}){5}$/);
  const g = await s.chama("/api/state", { headers: auth(ok.body.token) });
  assert.equal(g.body.email, "m@x.com"); assert.equal(g.body.hasLogin, true);
  assert.equal((await s.post("/api/auth", { action: "login", pin: "12345678", email: "M@x.com" })).status, 200);
  assert.equal((await s.post("/api/auth", { action: "login", pin: "12345678" })).status, 401, "com login por e-mail, o e-mail é obrigatório");
  const anon = await s.chama("/api/state");
  assert.equal(anon.body.hasLogin, true); assert.equal(anon.body.hasPin, true);
});

test("visitante antes de existir PIN", async () => {
  const s = cria(estadoExemplo());
  const r = await s.chama("/api/state");
  assert.equal(r.body.hasPin, false); assert.equal(r.body.hasLogin, false); assert.equal(r.body.version, 0);
  assert.equal((await s.post("/api/auth", { action: "login", pin: "123456" })).status, 404);
  assert.equal((await s.post("/api/auth", { action: "xyz", pin: "123456" })).status, 400);
  assert.equal((await s.chama("/api/auth", { method: "POST", body: "isso não é json" })).status, 400);
});

test("refresh: renova com token válido (no cabeçalho ou no corpo) e recusa sem", async () => {
  const s = cria(estadoExemplo());
  const tok = (await s.post("/api/auth", { action: "setup", pin: "123456" })).body.token;
  assert.equal((await s.post("/api/auth", { action: "refresh" })).status, 401);
  assert.equal((await s.post("/api/auth", { action: "refresh" }, auth("x.y"))).status, 401);
  s.relogio.now += 59 * 86_400_000;
  const r = await s.post("/api/auth", { action: "refresh", token: tok });
  assert.equal(r.status, 200);
  s.relogio.now += 2 * 86_400_000;
  assert.equal((await s.chama("/api/state", { headers: auth(tok) })).status, 401, "token antigo venceu");
  assert.equal((await s.chama("/api/state", { headers: { Authorization: "bearer " + r.body.token } })).status, 200, "token renovado vale (Bearer em minúsculas também)");
});

test("token: formatos inválidos são recusados", async () => {
  const s = cria(estadoExemplo());
  const tok = (await s.post("/api/auth", { action: "setup", pin: "123456" })).body.token;
  for (const t of ["semponto", "." + tok.split(".")[1], tok + "a".repeat(400), tok.split(".")[0] + ".", "eyJyIjoidCJ9." + tok.split(".")[1]]) {
    assert.equal((await s.chama("/api/state", { headers: auth(t) })).status, 401, t.slice(0, 20));
  }
});

test("upgrade para e-mail + senha: troca a chave e derruba outros acessos", async () => {
  const s = cria(estadoExemplo());
  const tok = (await s.post("/api/auth", { action: "setup", pin: "123456" })).body.token;
  assert.equal((await s.post("/api/auth", { action: "upgrade", email: "m@x.com", pin: "12345678" })).status, 401);
  assert.equal((await s.post("/api/auth", { action: "upgrade", email: "ruim", pin: "12345678" }, auth(tok))).status, 400);
  assert.equal((await s.post("/api/auth", { action: "upgrade", email: "m@x.com", pin: "1234567" }, auth(tok))).status, 400);
  assert.equal((await s.post("/api/auth", { action: "upgrade", email: "m@x.com", pin: "1".repeat(101) }, auth(tok))).status, 400);
  const r = await s.post("/api/auth", { action: "upgrade", email: "M@x.com", pin: "12345678" }, auth(tok));
  assert.equal(r.status, 200); assert.equal(r.body.email, "m@x.com"); assert.ok(r.body.recoveryKey);
  assert.equal((await s.chama("/api/state", { headers: auth(tok) })).status, 401);
  assert.equal((await s.chama("/api/state", { headers: auth(r.body.token) })).status, 200);
  assert.equal((await s.post("/api/auth", { action: "login", email: "m@x.com", pin: "123456" })).status, 401);
  assert.equal((await s.post("/api/auth", { action: "login", email: "m@x.com", pin: "12345678" })).status, 200);
});

test("nova chave de recuperação: exige login, substitui a antiga", async () => {
  const s = cria(estadoExemplo());
  const tok0 = (await s.post("/api/auth", { action: "setup", pin: "123456" })).body.token;
  assert.equal((await s.post("/api/auth", { action: "newrecovery" }, auth(tok0))).status, 400, "sem e-mail não tem recuperação");
  const up = await s.post("/api/auth", { action: "upgrade", email: "m@x.com", pin: "12345678" }, auth(tok0));
  assert.equal((await s.post("/api/auth", { action: "newrecovery" })).status, 401);
  const nk = await s.post("/api/auth", { action: "newrecovery" }, auth(up.body.token));
  assert.equal(nk.status, 200); assert.notEqual(nk.body.recoveryKey, up.body.recoveryKey);
  assert.equal((await s.post("/api/auth", { action: "recover", email: "m@x.com", recoveryKey: up.body.recoveryKey, pin: "novasenha1" })).status, 401);
  assert.equal((await s.post("/api/auth", { action: "recover", email: "m@x.com", recoveryKey: nk.body.recoveryKey.toLowerCase(), pin: "novasenha1" })).status, 200);
});

test("recuperação: chave errada conta tentativas e bloqueia; senha nova exige 8+; depois a antiga não vale", async () => {
  const s = cria(estadoExemplo());
  const st = await s.post("/api/auth", { action: "setup", email: "m@x.com", pin: "12345678" });
  const rk = st.body.recoveryKey;
  assert.equal((await s.post("/api/auth", { action: "recover", email: "m@x.com", recoveryKey: rk, pin: "1234567" })).status, 400);
  let r = await s.post("/api/auth", { action: "recover", email: "outro@x.com", recoveryKey: rk, pin: "novasenha1" });
  assert.equal(r.status, 401); assert.equal(r.body.restantes, 4);
  for (let i = 0; i < 3; i++) r = await s.post("/api/auth", { action: "recover", email: "m@x.com", recoveryKey: "AAAA-BBBB", pin: "novasenha1" });
  assert.equal(r.body.restantes, 1);
  r = await s.post("/api/auth", { action: "recover", email: "m@x.com", recoveryKey: "AAAA-BBBB", pin: "novasenha1" });
  assert.equal(r.status, 401); assert.equal(r.body.restantes, 5, "bloqueou e zerou o contador");
  r = await s.post("/api/auth", { action: "recover", email: "m@x.com", recoveryKey: rk, pin: "novasenha1" });
  assert.equal(r.status, 429); assert.ok(r.body.retryAfterSec > 800 && r.body.retryAfterSec <= 900);
  s.relogio.now += 15 * MIN + 1000;
  r = await s.post("/api/auth", { action: "recover", email: "m@x.com", recoveryKey: rk, pin: "novasenha1" });
  assert.equal(r.status, 200); assert.ok(r.body.token); assert.notEqual(r.body.recoveryKey, rk);
  assert.equal((await s.chama("/api/state", { headers: auth(st.body.token) })).status, 401, "sessões antigas caíram");
  assert.equal((await s.post("/api/auth", { action: "login", email: "m@x.com", pin: "12345678" })).status, 401);
  assert.equal((await s.post("/api/auth", { action: "login", email: "m@x.com", pin: "novasenha1" })).status, 200);
});

test("recuperação sem login por e-mail: 404", async () => {
  const s = cria(estadoExemplo());
  await s.post("/api/auth", { action: "setup", pin: "123456" });
  assert.equal((await s.post("/api/auth", { action: "recover", email: "m@x.com", recoveryKey: "X", pin: "novasenha1" })).status, 404);
});

test("bloqueio do login dobra a cada vez e erros antigos expiram", async () => {
  const s = cria(estadoExemplo());
  await s.post("/api/auth", { action: "setup", pin: "123456" });
  const erra = () => s.post("/api/auth", { action: "login", pin: "000000" });
  // 4 erros, espera 11 min: o contador zera
  for (let i = 0; i < 4; i++) await erra();
  s.relogio.now += 11 * MIN;
  let r = await erra(); assert.equal(r.body.restantes, 4);
  for (let i = 0; i < 4; i++) r = await erra();
  r = await s.post("/api/auth", { action: "login", pin: "123456" });
  assert.equal(r.status, 429); assert.ok(r.body.retryAfterSec <= 900 && r.body.retryAfterSec > 850);
  s.relogio.now += 16 * MIN;
  for (let i = 0; i < 5; i++) await erra();
  r = await s.post("/api/auth", { action: "login", pin: "123456" });
  assert.equal(r.status, 429); assert.ok(r.body.retryAfterSec > 1700 && r.body.retryAfterSec <= 1800, "segundo bloqueio: 30 min");
  s.relogio.now += 31 * MIN;
  assert.equal((await s.post("/api/auth", { action: "login", pin: "123456" })).status, 200);
  for (let i = 0; i < 4; i++) await erra();
  assert.equal((await s.post("/api/auth", { action: "login", pin: "123456" })).status, 200, "acertar zera os erros");
  r = await erra(); assert.equal(r.body.restantes, 4);
});

test("trocar PIN: exige login e respeita o mínimo (6, ou 8 com e-mail)", async () => {
  const s = cria(estadoExemplo());
  const tok = (await s.post("/api/auth", { action: "setup", pin: "123456" })).body.token;
  assert.equal((await s.post("/api/auth", { action: "change", pin: "654321" })).status, 401);
  assert.equal((await s.post("/api/auth", { action: "change", pin: "12345" }, auth(tok))).status, 400);
  assert.equal((await s.post("/api/auth", { action: "change", pin: "1".repeat(101) }, auth(tok))).status, 400);
  const up = await s.post("/api/auth", { action: "upgrade", email: "m@x.com", pin: "12345678" }, auth(tok));
  const r = await s.post("/api/auth", { action: "change", pin: "1234567" }, auth(up.body.token));
  assert.equal(r.status, 400); assert.equal(r.body.min, 8);
  const ok = await s.post("/api/auth", { action: "change", pin: "abcdefgh" }, auth(up.body.token));
  assert.equal(ok.status, 200);
  assert.equal((await s.post("/api/auth", { action: "login", email: "m@x.com", pin: "abcdefgh" })).status, 200);
});
