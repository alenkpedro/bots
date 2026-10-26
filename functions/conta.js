// /conta: soma uma visita do site para o Ao vivo do painel (Pedro, 26/10, fase 2). Cada página manda, uma vez, de
// que página é e de onde a pessoa veio (site.js); aqui entra o país, que o Cloudflare já sabe, e vai para o
// Supabase pela função site_hit (migração 60), que só sabe somar. Fica só o minuto, a página, o domínio de origem
// e o país: sem IP, sem cookie, sem nada que diga quem visitou. Robôs de busca e prévias de link não contam.
const OWN = /^(appbots\.pages\.dev|alenkpedro\.github\.io)$/;
const BOT = /bot|crawl|spider|slurp|preview|facebookexternalhit|embedly|headless|lighthouse|monitor/i;
let supabase = null;   // o endereço e a chave pública, lidos do supabase.js do próprio site (uma vez)

async function config(env, url) {
  if (supabase) return supabase;
  const r = await env.ASSETS.fetch(new URL("/supabase.js", url));
  const t = await r.text();
  const u = /url:\s*"([^"]+)"/.exec(t)?.[1], k = /key:\s*"([^"]+)"/.exec(t)?.[1];
  if (u && k) supabase = { url: u, key: k };
  return supabase;
}

// A página sem o /bots do github.io, sem .html e sem index; a origem só como domínio, e vazia quando é o próprio site.
export function clean(path, referrer) {
  let p = String(path || "/").split(/[?#]/)[0].replace(/^\/bots(?=\/|$)/, "").replace(/\.html$/, "").replace(/\/index$/, "/") || "/";
  if (!p.startsWith("/")) p = "/" + p;
  let r = "";
  try { const h = new URL(String(referrer || "")).hostname.replace(/^www\./, "").toLowerCase(); r = OWN.test(h) ? "" : h; } catch {}
  return { path: p.slice(0, 120), referrer: r.slice(0, 80) };
}

export async function onRequestPost({ request, env }) {
  const done = new Response(null, { status: 204, headers: { "access-control-allow-origin": "*", "cache-control": "no-store" } });
  if (BOT.test(request.headers.get("user-agent") || "")) return done;
  let input = {};
  try { input = JSON.parse((await request.text()).slice(0, 2000)); } catch { return done; }
  const { path, referrer } = clean(input.p, input.r);
  const s = await config(env, request.url).catch(() => null);
  if (!s) return done;
  await fetch(`${s.url}/rest/v1/rpc/site_hit`, {
    method: "POST", headers: { apikey: s.key, "content-type": "application/json" },
    body: JSON.stringify({ path, referrer, country: request.cf?.country || "" }),
  }).catch(() => {});
  return done;
}
