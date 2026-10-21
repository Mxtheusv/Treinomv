import type { Context, Config } from "@netlify/functions";
import { getStore } from "@netlify/blobs";
import { handleApi, type KV, type Blobs } from "../lib/core.mts";

// Fonte única do app: um JSON no Netlify Blobs (alunos + catálogo + versão), agora protegido.
// Toda a regra de acesso mora em ../lib/core.mts (PIN no servidor, token do personal,
// aluno só vê o próprio registro, feed da galera, fotos). Ver comentários lá.
//
// "strong": lê sempre a versão mais recente. No modo padrão (eventual) uma leitura logo
// depois de salvar pode devolver o estado ANTERIOR por alguns segundos — o aluno
// removido "voltava" ao recarregar a página.
const kv: KV = {
  async get(store, key) { return await getStore({ name: store, consistency: "strong" }).get(key, { type: "json" }); },
  async set(store, key, value) { await getStore({ name: store, consistency: "strong" }).setJSON(key, value); },
};

// Fotos de perfil e do feed (já reduzidas no celular, poucas centenas de KB cada).
const blobs: Blobs = {
  async get(id) {
    const r = await getStore("treino-online-fotos").getWithMetadata(id, { type: "arrayBuffer" });
    if (!r) return null;
    return { data: r.data as ArrayBuffer, type: ((r.metadata as any) && (r.metadata as any).type) || "image/jpeg" };
  },
  async set(id, data, type) { await getStore("treino-online-fotos").set(id, data, { metadata: { type } }); },
};

export default async (req: Request, context: Context) => {
  const res = await handleApi(req, { kv, blobs, ip: context.ip || req.headers.get("x-nf-client-connection-ip") || "?" });
  return res || new Response("Not found", { status: 404 });
};

export const config: Config = {
  path: ["/api/state", "/api/auth", "/api/lead", "/api/feed", "/api/comunidade", "/api/turma", "/api/push", "/api/img", "/api/img/:id"],
};
