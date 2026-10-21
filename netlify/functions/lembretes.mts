import type { Config } from "@netlify/functions";
import { getStore } from "@netlify/blobs";
import { rodaLembretes, type KV } from "../lib/core.mts";

// Tarefa agendada: todo dia às 8h (horário de Brasília = 11h UTC) lembra quem passou 3+ dias sem treinar.
// A regra mora em ../lib/core.mts (rodaLembretes).
const kv: KV = {
  async get(store, key) { return await getStore({ name: store, consistency: "strong" }).get(key, { type: "json" }); },
  async set(store, key, value) { await getStore({ name: store, consistency: "strong" }).setJSON(key, value); },
};

export default async () => {
  const r = await rodaLembretes({ kv, ip: "agendado" }, Date.now());
  return new Response(JSON.stringify(r), { headers: { "Content-Type": "application/json" } });
};

export const config: Config = { schedule: "0 11 * * *" };
