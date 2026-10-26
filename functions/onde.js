// /onde: a cidade aproximada de quem pergunta, para o mapa do Ao vivo no painel (Pedro, 26/10, fase 2). Quem
// pergunta é o agente (botd) de cada Mac, uma vez por dia (botd/src/city.ts). O Cloudflare já sabe a cidade pelo
// endereço da chamada; aqui só se devolve a cidade, o estado, o país e as coordenadas arredondadas a 0,1° (uns
// 10 km). Nada é guardado, e o IP não sai daqui.
export async function onRequestGet({ request }) {
  const cf = request.cf || {};
  const round = (v) => (Number.isFinite(Number(v)) ? Math.round(Number(v) * 10) / 10 : null);
  const body = { city: cf.city || null, region: cf.region || null, country: cf.country || null, lat: round(cf.latitude), lng: round(cf.longitude) };
  return new Response(JSON.stringify(body), { headers: { "content-type": "application/json", "cache-control": "no-store" } });
}
