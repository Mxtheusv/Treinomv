// Servidor de mentira para os testes: o mesmo handleApi da função real, com armazenamento em memória.
import { handleApi } from "../netlify/lib/core.mts";

export function cria(estadoInicial?: any) {
  const mem: Record<string, any> = {};
  const files: Record<string, any> = {};
  const kv = {
    async get(s: string, k: string) { return mem[s + "/" + k] ?? null; },
    async set(s: string, k: string, v: any) { mem[s + "/" + k] = JSON.parse(JSON.stringify(v)); },
  };
  const blobs = {
    async get(id: string) { return files[id] || null; },
    async set(id: string, data: ArrayBuffer, type: string) { files[id] = { data, type }; },
  };
  if (estadoInicial) mem["treino-online/app-state"] = JSON.parse(JSON.stringify(estadoInicial));
  const relogio = { now: 1_800_000_000_000 };
  let ip = 0;
  const chama = async (path: string, init: any = {}, extra: any = {}) => {
    const r = await handleApi(new Request("http://x" + path, init), { kv, blobs, ip: "10.0.0." + (++ip % 250), now: () => relogio.now, ...extra } as any);
    if (!r) return { status: 0, body: null as any, headers: new Headers() };
    const t = await r.text();
    let body: any = t; try { body = JSON.parse(t); } catch { /* texto */ }
    return { status: r.status, body, headers: r.headers };
  };
  const post = (path: string, body: any, headers: Record<string, string> = {}, extra: any = {}) =>
    chama(path, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) }, extra);
  const estado = () => mem["treino-online/app-state"];
  return { mem, files, kv, blobs, relogio, chama, post, estado };
}

export function estadoExemplo() {
  return {
    version: 1,
    data: {
      students: {
        "ana-souza": { nome: "Ana Souza", notas: "Hipertensa", plans: [{ id: "p1" }], mesGratisEm: "2026-10-01", sessoes: [], avaliacoes: [{ id: "av1", date: "2026-10-01", por: "personal", peso: "60" }] },
        joao: { nome: "João", notas: "", sessoes: [] },
      },
      templates: [], leads: [],
    },
    catalog: [],
  };
}

export async function personal(s: ReturnType<typeof cria>, pin = "123456") {
  const r = await s.post("/api/auth", { action: "setup", pin });
  return r.body.token as string;
}
