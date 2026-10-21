import type { Context, Config } from "@netlify/functions";

// Ponte para a API do Intervals.icu (site gratuito que recebe as atividades do
// Garmin e de outros relógios). O aluno informa o ID e a chave dele no app; esta
// função só repassa o pedido ao Intervals.icu e devolve as atividades em formato
// simples. A chave NÃO é guardada em lugar nenhum do servidor.
//
// Existe como função (e não como chamada direta do navegador) porque o app não
// pode contar com o CORS do Intervals.icu e porque assim o endereço de destino
// fica fixo: esta função nunca chama nenhum outro site.
const BASE = "https://intervals.icu/api/v1/athlete/";
const JSON_HEADERS = { "Content-Type": "application/json" };

function reply(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });
}

function isDate(v: unknown): v is string {
  return typeof v === "string" && /^\d{4}-\d{2}-\d{2}$/.test(v);
}

export default async (req: Request, _context: Context) => {
  if (req.method !== "POST") return reply(405, { error: "Método não permitido." });

  let input: any;
  try { input = await req.json(); } catch { return reply(400, { error: "Pedido inválido." }); }

  const athleteId = String(input?.athleteId ?? "").trim();
  const apiKey = String(input?.apiKey ?? "").trim();
  if (!/^(0|i?\d{1,12})$/.test(athleteId)) return reply(400, { error: "ID do atleta inválido. Ele parece com i123456." });
  if (!apiKey || apiKey.length > 200 || /[\s\u0000-\u001f]/.test(apiKey)) return reply(400, { error: "Chave (API key) inválida." });

  // Modo "detalhe": pontos gravados de UMA atividade (tempo, distância, FC, altitude),
  // usados pelo app para montar pace por km, frequência cardíaca e altimetria.
  if (input?.activityId !== undefined) {
    const actId = String(input.activityId).trim();
    if (!/^[A-Za-z0-9_.-]{1,40}$/.test(actId)) return reply(400, { error: "Atividade inválida." });
    const sUrl = "https://intervals.icu/api/v1/activity/" + encodeURIComponent(actId) + "/streams.json?types=time&types=distance&types=heartrate&types=altitude&types=fixed_altitude";
    const sCtrl = new AbortController();
    const sTimer = setTimeout(() => sCtrl.abort(), 15000);
    try {
      const res = await fetch(sUrl, { headers: { Authorization: "Basic " + btoa("API_KEY:" + apiKey), Accept: "application/json" }, signal: sCtrl.signal });
      if (res.status === 401 || res.status === 403) return reply(401, { error: "O Intervals.icu recusou o ID ou a chave. Confira os dois." });
      if (res.status === 404) return reply(404, { error: "Atividade sem detalhes no Intervals.icu." });
      if (!res.ok) return reply(502, { error: "O Intervals.icu não respondeu direito (" + res.status + ")." });
      const raw = await res.json();
      const by: Record<string, any[]> = {};
      if (Array.isArray(raw)) for (const st of raw) if (st && typeof st.type === "string" && Array.isArray(st.data)) by[st.type] = st.data;
      const time = by.time || [];
      if (time.length < 20) return reply(200, { streams: null });
      // reduz para no máximo ~2500 pontos (resposta pequena, o app só precisa do formato geral)
      const stride = Math.max(1, Math.ceil(time.length / 2500));
      const pick = (arr?: any[]) => {
        if (!arr || !arr.length) return null;
        const out: (number | null)[] = [];
        for (let i = 0; i < time.length; i += stride) { const v = Number(arr[i]); out.push(Number.isFinite(v) ? v : null); }
        return out;
      };
      return reply(200, { streams: { time: pick(time), distance: pick(by.distance), heartrate: pick(by.heartrate), altitude: pick(by.altitude || by.fixed_altitude) } });
    } catch (err: any) {
      if (err?.name === "AbortError") return reply(504, { error: "O Intervals.icu demorou demais." });
      return reply(502, { error: "Não consegui falar com o Intervals.icu agora." });
    } finally {
      clearTimeout(sTimer);
    }
  }
  if (!isDate(input?.oldest) || !isDate(input?.newest)) return reply(400, { error: "Período inválido." });
  const span = (Date.parse(input.newest) - Date.parse(input.oldest)) / 86400000;
  if (!(span >= 0 && span <= 120)) return reply(400, { error: "Período inválido (máximo de 120 dias)." });

  const url = BASE + encodeURIComponent(athleteId) + "/activities?oldest=" + input.oldest + "&newest=" + input.newest;
  const auth = "Basic " + btoa("API_KEY:" + apiKey);
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 12000);
  try {
    const res = await fetch(url, { headers: { Authorization: auth, Accept: "application/json" }, signal: ctrl.signal });
    if (res.status === 401 || res.status === 403) return reply(401, { error: "O Intervals.icu recusou o ID ou a chave. Confira os dois." });
    if (res.status === 404) return reply(404, { error: "Atleta não encontrado no Intervals.icu." });
    if (!res.ok) return reply(502, { error: "O Intervals.icu não respondeu direito (" + res.status + "). Tente de novo." });
    const raw = await res.json();
    const lista = Array.isArray(raw) ? raw : [];
    const activities = lista.slice(0, 120).map((a: any) => ({
      id: String(a?.id ?? ""),
      startLocal: typeof a?.start_date_local === "string" ? a.start_date_local : "",
      type: typeof a?.type === "string" ? a.type : "",
      name: typeof a?.name === "string" ? a.name.slice(0, 80) : "",
      movingTime: Number(a?.moving_time ?? a?.elapsed_time) || 0,
      distance: Number(a?.distance) || 0,
      avgHr: Number(a?.average_heartrate) || null,
      maxHr: Number(a?.max_heartrate) || null,
      calories: Number(a?.calories) || null,
    }));
    return reply(200, { activities });
  } catch (err: any) {
    if (err?.name === "AbortError") return reply(504, { error: "O Intervals.icu demorou demais. Tente de novo." });
    return reply(502, { error: "Não consegui falar com o Intervals.icu agora." });
  } finally {
    clearTimeout(timer);
  }
};

export const config: Config = {
  path: "/api/intervals",
};
