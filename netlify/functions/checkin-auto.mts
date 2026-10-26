import type { Config } from "@netlify/functions";
import { getStore } from "@netlify/blobs";
import { rodaCheckinAuto, type KV } from "../lib/core.mts";

// Tarefa agendada de hora em hora: marca o check-in de treinos parados há 30+ min sem conclusão,
// para o caso de o aluno não reabrir o app. A regra mora em ../lib/core.mts (rodaCheckinAuto).
const kv: KV = {
  async get(store, key) { return await getStore({ name: store, consistency: "strong" }).get(key, { type: "json" }); },
  async set(store, key, value) { await getStore({ name: store, consistency: "strong" }).setJSON(key, value); },
};

export default async () => {
  const r = await rodaCheckinAuto({ kv, ip: "agendado" }, Date.now());
  return new Response(JSON.stringify(r), { headers: { "Content-Type": "application/json" } });
};

export const config: Config = { schedule: "0 * * * *" };
