// Webhooks for routines on the site's own address (Aurélio, 26/10: the address a routine showed was the bare
// Supabase one). GitHub, Slack or any service posts to https://appbots.pages.dev/hook/<name>?…, and this Cloudflare
// Pages Function hands the request on untouched (method, headers, body, query) to the Supabase function of the same
// name, so signatures still check. Only the three hook functions go through; anything else is a 404.
const FUNCTIONS = "https://tumwyqswwkhcpbuhhncv.supabase.co/functions/v1/";
const HOOKS = new Set(["routine-hook", "github-hook", "slack-hook"]);

export async function onRequest({ request, params }) {
  const name = String(params.name ?? "");
  if (!HOOKS.has(name)) return new Response("Not found", { status: 404 });
  const headers = new Headers(request.headers);
  headers.delete("host");
  const body = request.method === "GET" || request.method === "HEAD" ? undefined : request.body;
  return fetch(FUNCTIONS + name + new URL(request.url).search, { method: request.method, headers, body, redirect: "manual" });
}
