// /entrar: o botão "Entrar" dos e-mails de código (Pedro, 29/10). O link apontava direto para o servidor do
// Supabase (no próprio, um endereço aleatório da InstaBox) e o iCloud mandava o e-mail para o spam; agora o
// e-mail só leva ao site, e esta Pages Function repassa para o /auth/v1/verify do servidor lido do supabase.js
// (o mesmo que o site usa). O app aceita este link colado também: lê o token_hash e o type (EmailLink).
const TYPES = new Set(["magiclink", "signup", "recovery", "invite", "email_change", "email"]);
const BACK = "bots-app://auth-callback";
let supabase = null;

async function serverURL(env, url) {
  if (supabase) return supabase;
  const r = await env.ASSETS.fetch(new URL("/supabase.js", url));
  supabase = /url:\s*"([^"]+)"/.exec(await r.text())?.[1] ?? null;
  return supabase;
}

/** Para onde o link do e-mail leva, ou null se ele não for um link de entrada. */
export function verifyURL(server, query) {
  const hash = query.get("token_hash") ?? "", type = query.get("type") ?? "";
  if (!/^[A-Za-z0-9_-]{8,200}$/.test(hash) || !TYPES.has(type)) return null;
  const to = new URL("/auth/v1/verify", server);
  to.search = new URLSearchParams({ token: hash, type, redirect_to: BACK }).toString();
  return to.toString();
}

export async function onRequestGet({ request, env }) {
  const url = new URL(request.url);
  const server = await serverURL(env, url);
  const to = server && verifyURL(server, url.searchParams);
  if (!to) return Response.redirect(new URL("/", url).toString(), 302);
  return new Response(null, { status: 302, headers: { location: to, "cache-control": "no-store", "referrer-policy": "no-referrer" } });
}
