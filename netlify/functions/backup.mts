import type { Config } from "@netlify/functions";
import { getStore } from "@netlify/blobs";
import { rodaBackupDiario, type KV } from "../lib/core.mts";

// Tarefa agendada: todo dia às 3h (Brasília = 6h UTC) guarda uma cópia de todos os dados (30 dias de histórico).
const kv: KV = {
  async get(store, key) { return await getStore({ name: store, consistency: "strong" }).get(key, { type: "json" }); },
  async set(store, key, value) { await getStore({ name: store, consistency: "strong" }).setJSON(key, value); },
};

export default async () => {
  const r = await rodaBackupDiario({ kv, ip: "agendado" }, Date.now());
  return new Response(JSON.stringify(r), { headers: { "Content-Type": "application/json" } });
};

export const config: Config = { schedule: "0 6 * * *" };
