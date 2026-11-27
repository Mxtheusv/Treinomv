import { test } from "node:test";
import assert from "node:assert/strict";
import { cria } from "./ajuda.mts";
import { mesStats } from "../netlify/lib/core.mts";

const ses = [
  { date: "2026-09-20", kind: "treino", cargasLog: [{ exercicio: "PEITO SUPINO BARRA", valor: "40" }], seriesLogadas: 3, volumeKg: 1200 },
  { date: "2026-10-02", kind: "treino", cargasLog: [{ exercicio: "PEITO SUPINO BARRA", valor: "42,5" }], seriesLogadas: 3, volumeKg: 1275 },
  { date: "2026-10-09", kind: "treino", cargasLog: [{ exercicio: "PEITO SUPINO BARRA", valor: "45" }, { exercicio: "COXA LEG PRESS 45°", valor: "100" }], seriesLogadas: 6, volumeKg: 2500 },
  { date: "2026-10-09", kind: "corrida", distanciaM: 5000 },
  { date: "2026-10-20", kind: "treino", cargasLog: [{ exercicio: "PEITO SUPINO BARRA", valor: "45" }], seriesLogadas: 3, volumeKg: 1350 },
  { date: "2026-11-03", kind: "treino", cargasLog: [{ exercicio: "PEITO SUPINO BARRA", valor: "50" }], seriesLogadas: 3, volumeKg: 1500 },
];
function base() { const x = cria({ version: 1, data: { students: { ana: { nome: "Ana Souza", sessoes: ses } }, templates: [], leads: [] }, catalog: [] }); x.relogio.now = Date.UTC(2026, 10, 27, 15); return x; }
const ok = (txt: string) => new Response(JSON.stringify({ content: [{ type: "text", text: txt }] }), { status: 200 });

test("mesStats: dias, treinos, recordes e maior evolução do mês", () => {
  const st = mesStats({ sessoes: ses }, "2026-10");
  assert.equal(st.dias, 3);
  assert.equal(st.diasAnt, 1);
  assert.equal(st.treinos, 3);
  assert.equal(st.series, 12);
  assert.equal(st.volume, 5125);
  assert.equal(st.km, 5);
  assert.equal(st.recordes, 2); // 42,5 e 45 no supino; leg press é a 1ª vez, não conta
  assert.deepEqual(st.evolucao, { ex: "PEITO SUPINO BARRA", de: 40, para: 45, pct: 13 });
});

test("mês atual ou futuro é recusado", async () => {
  const r = await base().post("/api/mes", { slug: "ana", mes: "2026-11" }, {}, { iaKey: "k" });
  assert.equal(r.status, 400);
});

test("texto da IA volta e fica guardado: segunda chamada não chama a IA", async () => {
  const s = base(); let chamadas = 0, enviado: any = null;
  const opts = { iaKey: "k", fetch: async (_u: string, i: any) => { chamadas++; enviado = JSON.parse(i.body); return ok("Ana, que mês! 3 dias treinados e supino de 40 para 45 kg."); } };
  const r1 = await s.post("/api/mes", { slug: "ana", mes: "2026-10" }, {}, opts);
  assert.equal(r1.body.ok, true);
  assert.match(r1.body.texto, /supino/);
  assert.equal(r1.body.stats.dias, 3);
  assert.match(enviado.messages[0].content, /"dias_treinados":3/);
  assert.doesNotMatch(enviado.messages[0].content, /Souza/); // só o primeiro nome vai para a IA
  const r2 = await s.post("/api/mes", { slug: "ana", mes: "2026-10" }, {}, opts);
  assert.equal(r2.body.texto, r1.body.texto);
  assert.equal(chamadas, 1);
});

test("sem chave: devolve os números sem texto; código errado: 404", async () => {
  const r = await base().post("/api/mes", { slug: "ana", mes: "2026-10" }, {}, {});
  assert.equal(r.body.ok, false);
  assert.equal(r.body.stats.treinos, 3);
  assert.equal((await base().post("/api/mes", { slug: "x", mes: "2026-10" }, {}, { iaKey: "k" })).status, 404);
});
