/* Treino Online -- service worker mínimo.
 * Objetivo: deixar o site instalável como app. NÃO guarda nada em cache de propósito:
 * o app muda toda hora e os dados (treinos, cargas) precisam sempre vir do servidor --
 * um cache velho mostraria treino desatualizado ou travaria o aluno numa versão antiga.
 * Só intercepta a abertura de página (navegação) pra mostrar um aviso decente sem internet;
 * vídeos, /api/* e todo o resto passam direto pela rede (sem respondWith), do jeito de sempre. */
// Modo offline: guarda só a "casca" do app (o HTML, igual para todos) e os ícones.
// Dados de aluno NUNCA passam por aqui: /api/* vai sempre direto pela rede; o app guarda
// o treino do próprio aluno no aparelho (localStorage) e cuida da fila de envio.
var SHELL = "to-shell-v1";
self.addEventListener("install", function () { self.skipWaiting(); });
self.addEventListener("activate", function (event) {
  event.waitUntil(
    caches.keys().then(function (keys) { return Promise.all(keys.filter(function (k) { return k !== SHELL; }).map(function (k) { return caches.delete(k); })); })
      .then(function () { return self.clients.claim(); })
  );
});
function semInternet() {
  return new Response(
    '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<title>Sem internet</title><body style="margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;' +
    'background:#080d1a;color:#fff;font:16px -apple-system,BlinkMacSystemFont,sans-serif;text-align:center;padding:24px">' +
    '<div><div style="font-size:42px">📶</div><h1 style="font-size:20px;margin:12px 0 6px">Sem internet</h1>' +
    '<p style="color:#9aa4bd;margin:0 0 18px">Abra o app uma vez com internet para ele ficar disponível offline.</p>' +
    '<button onclick="location.reload()" style="background:#ffc220;color:#1a1400;border:0;border-radius:999px;padding:12px 24px;font-weight:800;font-size:15px">Tentar de novo</button></div></body>',
    { status: 503, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } }
  );
}
self.addEventListener("fetch", function (event) {
  var req = event.request;
  if (req.method !== "GET") return;
  var url = new URL(req.url);
  if (url.origin !== self.location.origin) return;
  // Páginas avulsas (landing e guia de instalação) passam direto pela rede: não podem entrar no "app guardado".
  if (req.mode === "navigate" && (/^\/(consultoria|instalar|privacidade)(\.html)?\/?$/.test(url.pathname) || /^\/i\//.test(url.pathname))) return;
  if (req.mode === "navigate") {
    // Sempre tenta a rede primeiro (o app muda toda hora); só cai no guardado se estiver sem sinal.
    event.respondWith(
      fetch(req).then(function (res) {
        if (res && res.status === 200) { var copia = res.clone(); caches.open(SHELL).then(function (c) { return c.put("/__shell", copia); }).catch(function () {}); }
        return res;
      }).catch(function () {
        return caches.open(SHELL).then(function (c) { return c.match("/__shell"); }).then(function (r) { return r || semInternet(); });
      })
    );
    return;
  }
  if (/^\/icons\//.test(url.pathname) || url.pathname === "/manifest.webmanifest") {
    event.respondWith(
      caches.open(SHELL).then(function (c) {
        return c.match(req).then(function (hit) {
          var rede = fetch(req).then(function (res) { if (res && res.status === 200) c.put(req, res.clone()); return res; }).catch(function () { return hit; });
          return hit || rede;
        });
      })
    );
  }
});

// ---- Avisos (push): o servidor manda um JSON {title, body, tag, url} criptografado ----
self.addEventListener("push", function (event) {
  var d = {};
  try { d = event.data ? event.data.json() : {}; } catch (e) { try { d = { body: event.data.text() }; } catch (e2) {} }
  event.waitUntil(self.registration.showNotification(d.title || "Treino Online", {
    body: d.body || "",
    icon: "/icons/icon-192.png",
    badge: "/icons/icon-192.png",
    tag: d.tag || undefined,
    renotify: !!d.tag,
    data: { url: d.url || "/" }
  }));
});
self.addEventListener("notificationclick", function (event) {
  event.notification.close();
  var url = (event.notification.data && event.notification.data.url) || "/";
  event.waitUntil(self.clients.matchAll({ type: "window", includeUncontrolled: true }).then(function (list) {
    for (var i = 0; i < list.length; i++) { if ("focus" in list[i]) return list[i].focus(); }
    return self.clients.openWindow(url);
  }));
});
