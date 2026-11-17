// Teste de mutação (Stryker): faz pequenas "sabotagens" no código de segurança do servidor
// (troca um > por >=, apaga um if, inverte um true...) e confere se algum teste percebe.
// Mutante que sobrevive = um erro que os testes deixariam passar.
// Rodar: npm run mutacao   (relatório em reports/mutation/index.html)
export default {
  testRunner: "command",
  commandRunner: { command: "node --experimental-strip-types --test tests/*.test.mts" },
  // Só as partes de segurança: login/sessão, código do aluno, campos protegidos, backup, leitura e gravação dos dados, IA.
  mutate: [
    "netlify/lib/core.mts:84-156",
    "netlify/lib/core.mts:238-418",
    "netlify/lib/core.mts:531-707",
    "netlify/lib/core.mts:1031-1050",
  ],
  ignorePatterns: ["public", "exercicios", "exercicios-foto", "lp", "index.html", "reports", ".stryker-tmp"],
  reporters: ["clear-text", "progress", "html", "json"],
  htmlReporter: { fileName: "reports/mutation/index.html" },
  jsonReporter: { fileName: "reports/mutation/mutation.json" },
  concurrency: 2,
  timeoutMS: 20000,
  thresholds: { high: 85, low: 70, break: null },
};
