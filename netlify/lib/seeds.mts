// Cadastros prontos que entram no banco UMA vez, no primeiro acesso do personal depois do deploy.
// Ficam aqui (no servidor), não em public/, para não aparecerem no código-fonte do site.
// O "id" marca que já foi aplicado: se o personal remover o aluno depois, ele não volta.

function rid(p: string): string { return p + Date.now().toString(36) + Math.random().toString(36).slice(2, 6); }
function exercicio(nome: string) {
  return { id: rid("e"), nome, series: "", reps: "", intervalo: "", obs: "", equipamento: "", cargas: { s1: "", s2: "", s3: "", s4: "" } };
}
function treino(nome: string, exercicios: string[]) {
  return { id: rid("t"), nome, aerobicos: [], blocos: [{ id: rid("b"), bloco: "A", exercicios: exercicios.map(exercicio) }] };
}
function iso(ms: number): string { return new Date(ms - 3 * 3600_000).toISOString().slice(0, 10); } // data de Brasília

export interface Seed { id: string; slug: string; build: (now: number) => any; }

export const SEEDS: Seed[] = [
  {
    id: "mariah-machado-2026-10",
    slug: "mariah-machado",
    build: (now: number) => {
      const plano = {
        id: rid("p"), label: "Força + corrida (1 mês grátis)", createdAt: now, archived: false,
        microciclo: "Força/fortalecimento para corrida",
        startDate: iso(now), endDate: iso(now + 30 * 24 * 3600_000),
        treinos: [
          treino("MEMBROS INFERIORES (ANTERIOR)", [
            "Mobilidade de Quadril II", "Mobilidade de Quadril VII", "Mobilidade de Quadril IX", "Mobilidade de Tornozelo",
            "Agachamento com Salto", "Agachamento com Halter na Frente", "Agachamento Livre com Barra no Suporte", "Cadeira Extensora",
          ]),
          treino("SUPERIORES", []),
          treino("POSTERIOR E PREVENTIVOS", []),
        ],
        complementar: { nome: "VELOCIDADE, AGILIDADE E POTÊNCIA", protocolos: [], grupos: [], nota: "" },
        complementarHidden: true, rotationIdx: 0,
      };
      // treinos sem exercício ganham uma linha em branco para o editor abrir normalmente
      for (const t of plano.treinos) if (!t.blocos[0].exercicios.length) t.blocos[0].exercicios.push(exercicio(""));
      return {
        nome: "Mariáh Machado",
        plans: [plano], activePlanId: plano.id,
        checkins: [], feedback: [],
        notas: "Veio do MFit (plano 'Treino Força/Fortalecimento Corrida', intermediário). " +
          "1 mês grátis, com planilha de corrida inclusa. " +
          "Treino 1: só entraram os exercícios que apareceram no vídeo, falta o restante, as séries/reps e as cargas atuais. " +
          "Treinos 2 e 3: só os nomes, falta montar os exercícios.",
        sessoes: [], humor: {}, sessaoEmAndamento: null, criadoEm: now, primeiroAcessoEm: null,
      };
    },
  },
];
