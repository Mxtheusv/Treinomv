import type { Context, Config } from "@netlify/functions";
import { getStore } from "@netlify/blobs";
import { requestIsTrainer, type KV } from "../lib/core.mts";

// Stores exercise-demo video files the trainer uploads straight from the
// Acervo screen (client-side compressed in the browser first -- see
// compressVideoForUpload() in index.html), so adding a new exercise video no
// longer requires sending the raw clip out of the app to be hand-compressed
// and hard-coded into a deploy. Separate store/key-per-video (instead of
// folding the bytes into the main "app-state" blob) keeps GET /api/state
// small and fast for every student on every load -- it only ever carries a
// short "/api/video/<id>" reference string per exercise, never the video
// bytes themselves.
const STORE_NAME = "treino-online-videos";

// Client always compresses before uploading (targets a few hundred KB,
// matching what the manual ffmpeg pipeline has produced all along), so
// anything past this is almost certainly a raw/uncompressed clip that slipped
// through -- reject it instead of letting an oversized blob into storage.
const MAX_BYTES = 8 * 1024 * 1024;

// Sem CORS aberto: o app e a API ficam na mesma origem. O envio (POST) exige o token do
// personal; a leitura (GET) segue pública porque o <video> do aluno não envia cabeçalhos
// e os ids são UUIDs aleatórios (não listáveis).
const CORS_HEADERS: Record<string, string> = {};

const kv: KV = {
  async get(store, key) { return await getStore({ name: store, consistency: "strong" }).get(key, { type: "json" }); },
  async set(store, key, value) { await getStore({ name: store, consistency: "strong" }).setJSON(key, value); },
};

function jsonError(status: number, error: string) {
  return new Response(JSON.stringify({ error }), {
    status,
    headers: { "Content-Type": "application/json", ...CORS_HEADERS },
  });
}

export default async (req: Request, context: Context) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204 });
  }

  const store = getStore(STORE_NAME);

  if (req.method === "POST") {
    const ip = context.ip || req.headers.get("x-nf-client-connection-ip") || "?";
    if (!(await requestIsTrainer(req, { kv, ip }))) return jsonError(401, "nao_autorizado");
    const contentType = req.headers.get("Content-Type") || "video/mp4";
    if (contentType.indexOf("video/") !== 0) {
      return jsonError(400, "expected_video_content_type");
    }
    const bytes = await req.arrayBuffer();
    if (!bytes.byteLength) return jsonError(400, "empty_body");
    if (bytes.byteLength > MAX_BYTES) return jsonError(413, "too_large");

    const id = crypto.randomUUID();
    await store.set(id, bytes, { metadata: { contentType } });
    return new Response(JSON.stringify({ id, url: "/api/video/" + id }), {
      headers: { "Content-Type": "application/json", ...CORS_HEADERS },
    });
  }

  if (req.method === "GET") {
    const id = context.params.id;
    if (!id) return jsonError(400, "missing_id");

    const result = await store.getWithMetadata(id, { type: "arrayBuffer" });
    if (!result) return new Response("Not found", { status: 404, headers: CORS_HEADERS });

    const contentType = (result.metadata && (result.metadata as any).contentType) || "video/mp4";
    const data = result.data as ArrayBuffer;
    const total = data.byteLength;

    // iOS Safari in particular refuses to play a <video> that doesn't
    // respond to Range requests, so this mirrors what Netlify's own static
    // file server already does for the bundled /exercicios/*.mp4 files.
    const range = req.headers.get("range");
    if (range) {
      const match = /bytes=(\d*)-(\d*)/.exec(range);
      let start = match && match[1] ? parseInt(match[1], 10) : 0;
      let end = match && match[2] ? parseInt(match[2], 10) : total - 1;
      if (isNaN(start) || start < 0) start = 0;
      if (isNaN(end) || end >= total) end = total - 1;
      const chunk = data.slice(start, end + 1);
      return new Response(chunk, {
        status: 206,
        headers: {
          "Content-Type": contentType,
          "Content-Range": "bytes " + start + "-" + end + "/" + total,
          "Accept-Ranges": "bytes",
          "Content-Length": String(chunk.byteLength),
          "Cache-Control": "public, max-age=31536000, immutable",
          ...CORS_HEADERS,
        },
      });
    }

    return new Response(data, {
      headers: {
        "Content-Type": contentType,
        "Accept-Ranges": "bytes",
        "Content-Length": String(total),
        "Cache-Control": "public, max-age=31536000, immutable",
        ...CORS_HEADERS,
      },
    });
  }

  return new Response("Method not allowed", { status: 405, headers: CORS_HEADERS });
};

export const config: Config = {
  path: ["/api/video", "/api/video/:id"],
};
