// Painel de admin dos Bots. Fala direto com o Supabase (Auth e REST), sem bibliotecas: entra com o código do
// e-mail, confere is_admin e mostra cinco páginas. As políticas e as funções admin_* (migrações 33 e 34) é que
// garantem que só o admin lê e escreve isto, e que ele só vê números, nunca o conteúdo das conversas.
(() => {
  const cfg = window.BOTS_SUPABASE;
  const $ = id => document.getElementById(id);
  const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const STAGES = { next: 'Na fila', dev: 'Em desenvolvimento', soon: 'Pronto, chega em breve', live: 'Já no app' };
  const KEY = 'bots-admin-session', EMAIL_KEY = 'bots-admin-email';
  const nf = new Intl.NumberFormat('pt-BR');
  const money = micro => (micro / 1e6).toLocaleString('pt-BR', { style: 'currency', currency: 'USD', minimumFractionDigits: 2 });
  const tokens = n => n >= 1e6 ? `${(n / 1e6).toLocaleString('pt-BR', { maximumFractionDigits: 1 })} mi` : n >= 1e3 ? `${Math.round(n / 1e3)} mil` : nf.format(n);
  function ago(iso) {
    if (!iso) return '—';
    const m = (Date.now() - new Date(iso)) / 60000;
    if (m < 2) return 'agora';
    if (m < 60) return `há ${Math.round(m)} min`;
    if (m < 60 * 24) return `há ${Math.round(m / 60)} h`;
    if (m < 60 * 48) return 'ontem';
    if (m < 60 * 24 * 30) return `há ${Math.round(m / 1440)} dias`;
    return new Date(iso).toLocaleDateString('pt-BR');
  }
  const day = iso => new Date(iso).toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit' });
  const date = iso => iso ? new Date(iso).toLocaleDateString('pt-BR', { day: '2-digit', month: 'short', year: 'numeric' }) : '—';
  // A foto do perfil (data URL que o app grava) ou a inicial numa cor tirada do seed, sempre a mesma por pessoa.
  function avatar(p, big = false) {
    const cls = `avatar${big ? ' avatar--big' : ''}`, url = p?.avatar_url || '';
    if (/^(data:image\/|https:\/\/)/.test(url)) return `<span class="${cls}"><img src="${esc(url)}" alt="" loading="lazy" decoding="async"></span>`;
    const name = p?.display_name || p?.name || p?.email || '?';
    let h = 0; for (const c of String(p?.avatar_seed || name)) h = (h * 31 + c.charCodeAt(0)) % 360;
    return `<span class="${cls}" style="background:hsl(${h} 70% 68%)" aria-hidden="true">${esc(name.trim()[0]?.toUpperCase() || '?')}</span>`;
  }
  const personName = p => p?.display_name || p?.name || p?.email || 'Sem nome';

  // ---------- sessão ----------
  // Dois modos (Pedro, 19/10). Neste Mac (localhost) o painel fica aberto: a sessão vai para o localStorage e
  // dura até você sair. Publicado (github.io, para o celular) pede a senha: a sessão vai para o
  // sessionStorage e some quando a aba ou o app fecha.
  const LOCAL = ['localhost', '127.0.0.1', '[::1]'].includes(location.hostname);
  const store = (() => { try { return LOCAL ? localStorage : sessionStorage; } catch { return null; } })();
  if (!LOCAL) try { localStorage.removeItem(KEY); } catch {}   // de antes dos dois modos: nada de sessão guardada aqui
  let session = null;
  try { session = JSON.parse(store?.getItem(KEY) || 'null'); } catch { session = null; }
  const save = s => { session = s; try { s ? store?.setItem(KEY, JSON.stringify(s)) : store?.removeItem(KEY); } catch {} };
  async function auth(path, body) {
    const r = await fetch(`${cfg.url}/auth/v1/${path}`, { method: 'POST', headers: { apikey: cfg.key, 'content-type': 'application/json' }, body: JSON.stringify(body) });
    const out = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(out.msg || out.error_description || out.message || 'Não deu certo. Tente de novo.');
    return out;
  }
  const keep = out => save({ access: out.access_token, refresh: out.refresh_token, until: Date.now() + (out.expires_in - 60) * 1000, email: out.user?.email || session?.email });
  async function token() {
    if (!session) return null;
    if (Date.now() > session.until) {
      try { keep(await auth('token?grant_type=refresh_token', { refresh_token: session.refresh })); }
      catch (err) {
        // Sem internet (fetch falhou): mantém a sessão guardada e tenta de novo depois.
        if (err instanceof TypeError) return null;
        // Outra aba pode ter renovado antes (o Supabase só aceita cada refresh uma vez): usa a dela.
        let other = null; try { other = JSON.parse(store?.getItem(KEY) || 'null'); } catch {}
        if (other && other.refresh !== session.refresh && Date.now() < other.until) { session = other; return session.access; }
        save(null); return null;
      }
    }
    return session.access;
  }
  async function api(path, { method = 'GET', body, prefer } = {}) {
    const t = await token();
    if (!t) { if (session) throw new Error('Sem conexão com o Supabase agora. Tente de novo.'); show('login'); throw new Error('Entre de novo.'); }
    const headers = { apikey: cfg.key, authorization: `Bearer ${t}`, 'content-type': 'application/json' };
    if (prefer) headers.prefer = prefer;
    const r = await fetch(`${cfg.url}/rest/v1/${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    if (r.status === 401) { save(null); show('login'); throw new Error('A sessão acabou. Entre de novo.'); }
    const text = await r.text();
    const out = text ? JSON.parse(text) : null;
    if (!r.ok) throw new Error(out?.message || 'O banco recusou a mudança.');
    return out;
  }

  // ---------- telas ----------
  function show(which) {
    if (which === 'login' && $('adm-login').hidden) loginMode(LOCAL ? 'code' : 'pass');
    $('adm-login').hidden = which !== 'login';
    $('adm-denied').hidden = which !== 'denied';
    $('adm-shell').hidden = which !== 'shell';
    $('adm-who').textContent = session?.email || '';
  }
  const status = (el, text, tone = '') => { el.textContent = text; el.dataset.tone = tone; };
  let toastTimer;
  const toast = (text, tone = 'ok') => { status($('adm-status'), text, tone); clearTimeout(toastTimer); toastTimer = setTimeout(() => status($('adm-status'), ''), 4000); };
  const fail = err => toast(err.message, 'erro');

  // O e-mail fica lembrado neste aparelho para a próxima vez (o arquivo publicado não traz e-mail nenhum).
  const lastEmail = () => { try { return localStorage.getItem(EMAIL_KEY) || ''; } catch { return ''; } };
  const rememberEmail = e => { try { localStorage.setItem(EMAIL_KEY, e); } catch {} };
  function loginMode(mode) {
    const pass = mode === 'pass';
    $('adm-pass').hidden = !pass; $('adm-email').hidden = pass; $('adm-code').hidden = true;
    $('adm-use-pass').hidden = pass || LOCAL;
    $('adm-pass-email').value = $('adm-email-input').value = lastEmail();
    $('adm-login-lead').textContent = pass ? 'Entre com o e-mail e a senha do painel.'
      : LOCAL ? 'Só desta vez: mandamos um código para o e-mail da sua conta dos Bots. Depois o painel abre direto neste Mac.'
      : 'Mandamos um código para o e-mail da sua conta dos Bots.';
    status($('adm-login-status'), '');
    setTimeout(() => (pass ? ($('adm-pass-email').value ? $('adm-pass-input') : $('adm-pass-email')) : $('adm-email-input')).focus(), 0);
  }
  $('adm-use-code').addEventListener('click', () => loginMode('code'));
  $('adm-use-pass').addEventListener('click', () => loginMode('pass'));
  $('adm-pass').addEventListener('submit', async e => {
    e.preventDefault();
    const em = $('adm-pass-email').value.trim();
    status($('adm-login-status'), 'Conferindo…');
    try {
      keep(await auth('token?grant_type=password', { email: em, password: $('adm-pass-input').value }));
      $('adm-pass-input').value = ''; rememberEmail(em); status($('adm-login-status'), '');
      start();
    } catch (err) {
      status($('adm-login-status'), /invalid/i.test(err.message) ? 'E-mail ou senha não conferem. Se ainda não criou a senha, crie em "Senha do painel" no painel do Mac.' : err.message, 'erro');
    }
  });

  // Entrar com código: o e-mail recebe um código (o mesmo do app); a conta já tem que existir.
  let email = '';
  $('adm-email').addEventListener('submit', async e => {
    e.preventDefault();
    email = $('adm-email-input').value.trim();
    status($('adm-login-status'), 'Mandando…');
    try {
      await auth('otp', { email, create_user: false });
      $('adm-email').hidden = true; $('adm-code').hidden = false; $('adm-code-input').focus();
      status($('adm-login-status'), `Mandamos um código para ${email}.`, 'ok');
    } catch (err) { status($('adm-login-status'), err.message, 'erro'); }
  });
  $('adm-code').addEventListener('submit', async e => {
    e.preventDefault();
    status($('adm-login-status'), 'Conferindo…');
    try {
      keep(await auth('verify', { type: 'email', email, token: $('adm-code-input').value.replace(/\s/g, '') }));
      rememberEmail(email);
      status($('adm-login-status'), '');
      start();
    } catch (err) { status($('adm-login-status'), /expired|invalid/i.test(err.message) ? 'Esse código expirou ou não confere. Peça outro.' : err.message, 'erro'); }
  });
  $('adm-back').addEventListener('click', () => { $('adm-code').hidden = true; $('adm-email').hidden = false; status($('adm-login-status'), ''); });
  document.querySelectorAll('[data-out]').forEach(b => b.addEventListener('click', async () => {
    const t = session?.access;
    save(null); show('login');
    // scope=local: sai só deste painel. O padrão (global) derrubaria também o app no Mac e no iPhone.
    if (t) fetch(`${cfg.url}/auth/v1/logout?scope=local`, { method: 'POST', headers: { apikey: cfg.key, authorization: `Bearer ${t}` } }).catch(() => {});
  }));

  // ---------- dados ----------
  let people = [], items = [], ideas = [], feedback = [], notices = [];
  const who = id => people.find(p => p.user_id === id);
  async function loadPeople() { people = await api('rpc/admin_people', { method: 'POST', body: {} }) || []; badges(); }
  async function loadInbox() {
    [ideas, feedback] = await Promise.all([
      api('roadmap_ideas?select=*&order=created_at.desc&limit=500'),
      api('feedback?select=*&order=created_at.desc&limit=500'),
    ]);
    badges();
  }
  const setBadge = (k, n) => { const b = document.querySelector(`[data-badge="${k}"]`); if (b) { b.textContent = n; b.hidden = !n; } };
  function badges() {
    const pend = people.filter(p => p.status === 'pending').length;
    const fresh = ideas.filter(i => i.status === 'new').length + feedback.filter(f => f.status === 'new').length;
    const set = (k, n) => { const b = document.querySelector(`[data-badge="${k}"]`); b.textContent = n; b.hidden = !n; };
    set('pessoas', pend); set('ideias', fresh);
  }

  // ---------- páginas ----------
  const pages = { visao: renderOverview, pessoas: renderPeople, pessoa: renderPerson, roadmap: renderBoardPage, ideias: renderInbox, travamentos: renderCrashes, versoes: renderVersions };
  // #pessoa/<id> abre a página de uma pessoa; o menu continua marcando Pessoas.
  function route() {
    const [name, arg] = location.hash.slice(1).split('/');
    const page = pages[name] ? name : 'visao';
    const nav = page === 'pessoa' ? 'pessoas' : page;
    document.querySelectorAll('.adm-page').forEach(p => p.hidden = p.dataset.page !== page);
    document.querySelectorAll('.adm-nav a').forEach(a => a.toggleAttribute('aria-current', a.getAttribute('href') === `#${nav}`));
    scrollTo(0, 0);
    pages[page](arg).catch(fail);
  }
  addEventListener('hashchange', route);

  // Visão geral: os números, o gráfico de tarefas por dia e o que espera você.
  async function renderOverview() {
    const [o, c] = await Promise.all([api('rpc/admin_overview', { method: 'POST', body: {} }), api('rpc/admin_crash_count', { method: 'POST', body: {} }).catch(() => null), loadPeople(), loadInbox()]);
    setBadge('travamentos', c?.reports_7d || 0);
    const tile = (label, value, note = '') => `<div class="kpi"><span>${label}</span><b>${value}</b>${note ? `<small>${note}</small>` : ''}</div>`;
    $('kpis').innerHTML = [
      tile('Pessoas aprovadas', nf.format(o.approved), o.pending ? `${o.pending} esperando acesso` : 'ninguém esperando'),
      tile('Usaram hoje', nf.format(o.active_1d), `${nf.format(o.active_7d)} nos últimos 7 dias`),
      tile('Bots criados', nf.format(o.bots), `${nf.format(o.bots_7d)} ${o.bots_7d === 1 ? 'novo' : 'novos'} em 7 dias`),
      tile('Tarefas em 7 dias', nf.format(o.runs_7d), `${tokens(o.tokens_7d)} tokens`),
      // Engines run on the person's subscription (Claude, ChatGPT): this is what it would cost through the API, not a bill.
      tile('Equivalente em API, 7 dias', money(o.cost_7d), 'se fosse pago pela API; nas assinaturas não é cobrado à parte'),
      tile('Rotinas ligadas', nf.format(o.routines_on)),
      ...(c ? [tile('Travamentos em 7 dias', nf.format(c.reports_7d), c.reports_7d ? `em ${c.people_7d} ${c.people_7d === 1 ? 'pessoa' : 'pessoas'}` : 'nenhum')] : []),
    ].join('');
    drawChart(o.runs_by_day || []);
    const todo = [];
    if (o.pending) todo.push(`<li><a href="#pessoas" data-filter="pending"><b>${o.pending}</b> ${o.pending === 1 ? 'pedido de acesso' : 'pedidos de acesso'}</a></li>`);
    if (o.feedback_new) todo.push(`<li><a href="#ideias" data-kind="feedback"><b>${o.feedback_new}</b> ${o.feedback_new === 1 ? 'feedback sem ler' : 'feedbacks sem ler'}</a></li>`);
    if (c?.reports_7d) todo.push(`<li><a href="#travamentos"><b>${c.reports_7d}</b> ${c.reports_7d === 1 ? 'travamento' : 'travamentos'} nos últimos 7 dias</a></li>`);
    if (o.ideas_new) todo.push(`<li><a href="#ideias" data-kind="ideas"><b>${o.ideas_new}</b> ${o.ideas_new === 1 ? 'ideia nova' : 'ideias novas'}</a></li>`);
    $('todo').innerHTML = todo.join('') || '<li class="adm-empty">Nada esperando por você.</li>';
  }
  $('todo').addEventListener('click', e => {
    const a = e.target.closest('a'); if (!a) return;
    if (a.dataset.filter) peopleFilter = a.dataset.filter;
    if (a.dataset.kind) { inboxKind = a.dataset.kind; inboxStatus = 'new'; }
  });
  // Barras de uma série só (cor validada contra o fundo), dica ao passar o mouse, e a tabela para quem prefere.
  function drawChart(rows, id = 'chart') {
    const plot = $(`${id}-plot`), tip = $(`${id}-tip`);
    const W = 900, H = 220, pad = { l: 36, r: 8, t: 12, b: 26 };
    const max = Math.max(1, ...rows.map(r => r.runs));
    // Topo do eixo redondo e com metade inteira (nada de "2,5 tarefas").
    const step = max <= 10 ? 2 : max <= 50 ? 10 : 10 ** Math.floor(Math.log10(max)) * 2;
    const nice = Math.max(step, Math.ceil(max / step) * step);
    const bw = (W - pad.l - pad.r) / Math.max(rows.length, 1);
    const y = v => H - pad.b - (v / nice) * (H - pad.t - pad.b);
    const grid = [0, nice / 2, nice].map(v => `<line x1="${pad.l}" x2="${W - pad.r}" y1="${y(v)}" y2="${y(v)}" class="chart__grid"/><text x="${pad.l - 8}" y="${y(v) + 4}" class="chart__axis" text-anchor="end">${nf.format(v)}</text>`).join('');
    const bars = rows.map((r, i) => {
      const x = pad.l + i * bw + 1, h = Math.max(0, H - pad.b - y(r.runs)), w = Math.max(2, bw - 2);
      const label = i % 5 === 0 || i === rows.length - 1 ? `<text x="${x + w / 2}" y="${H - 8}" class="chart__axis" text-anchor="middle">${day(r.day + 'T12:00')}</text>` : '';
      return `<g class="chart__bar" data-i="${i}"><rect class="chart__hit" x="${x - 1}" y="${pad.t}" width="${bw}" height="${H - pad.t - pad.b}"/>${h ? `<path d="M${x},${H - pad.b} v${-(h - Math.min(4, h))} q0,${-Math.min(4, h)} ${Math.min(4, w / 2)},${-Math.min(4, h)} h${w - 2 * Math.min(4, w / 2)} q${Math.min(4, w / 2)},0 ${Math.min(4, w / 2)},${Math.min(4, h)} v${h - Math.min(4, h)} z" class="chart__mark"/>` : ''}${label}</g>`;
    }).join('');
    plot.innerHTML = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Tarefas por dia nos últimos 30 dias">${grid}${bars}</svg>`;
    plot.querySelectorAll('.chart__bar').forEach(g => {
      const r = rows[+g.dataset.i];
      g.addEventListener('pointerenter', e => { tip.hidden = false; tip.innerHTML = `<b>${nf.format(r.runs)}</b> ${r.runs === 1 ? 'tarefa' : 'tarefas'}<span>${new Date(r.day + 'T12:00').toLocaleDateString('pt-BR', { weekday: 'short', day: '2-digit', month: 'short' })}</span>`; });
      g.addEventListener('pointermove', e => { const box = plot.getBoundingClientRect(); tip.style.left = `${e.clientX - box.left}px`; tip.style.top = `${e.clientY - box.top}px`; });
      g.addEventListener('pointerleave', () => tip.hidden = true);
    });
    $(`${id}-table`).querySelector('tbody').innerHTML = rows.slice().reverse().map(r => `<tr><td>${day(r.day + 'T12:00')}</td><td>${nf.format(r.runs)}</td></tr>`).join('');
  }

  // Pessoas: a lista, o filtro por situação, a busca e Aprovar / Recusar para quem espera.
  let peopleFilter = 'all';
  async function renderPeople() { await loadPeople(); drawPeople(); }
  function drawPeople() {
    const q = $('people-search').value.trim().toLowerCase();
    const counts = { all: people.length };
    people.forEach(p => counts[p.status] = (counts[p.status] || 0) + 1);
    document.querySelectorAll('#people-filter button').forEach(b => { b.querySelector('b').textContent = counts[b.dataset.f] || 0; b.setAttribute('aria-selected', b.dataset.f === peopleFilter); });
    const label = { approved: 'Aprovada', pending: 'Esperando', denied: 'Recusada' };
    const rows = people.filter(p => (peopleFilter === 'all' || p.status === peopleFilter) && (!q || `${p.name || ''} ${p.email || ''}`.toLowerCase().includes(q)));
    $('people').querySelector('tbody').innerHTML = rows.map(p => `<tr data-user="${p.user_id}" tabindex="0" aria-label="Abrir ${esc(personName(p))}">
      <td><div class="who-cell">${avatar(p)}<div><b>${esc(personName(p))}</b><small>${personName(p) !== p.email ? esc(p.email) + ' · ' : ''}entrou em ${day(p.requested_at)}</small></div></div></td>
      <td><span class="pill" data-st="${p.status}">${label[p.status] || p.status}</span></td>
      <td>${ago(p.last_seen)}</td>
      <td>${p.mac_version ? esc(p.mac_version) : p.agent_version ? `<small>agente ${esc(p.agent_version)}</small>` : '—'}</td>
      <td>${p.ios_version ? esc(p.ios_version) : p.has_ios ? '<small>tem o app</small>' : '—'}</td>
      <td class="num">${nf.format(p.bots)}</td><td class="num">${nf.format(p.runs_7d)}</td><td class="num">${money(p.cost_7d)}</td>
      <td class="act">${p.status === 'approved' ? '' : `<button type="button" class="button button--small" data-decide="approved">Aprovar</button>`}${p.status === 'pending' ? `<button type="button" class="button button--small button--quiet" data-decide="denied">Recusar</button>` : ''}</td>
    </tr>`).join('') || `<tr><td colspan="9" class="adm-empty">Ninguém por aqui.</td></tr>`;
  }
  $('people-filter').addEventListener('click', e => { const b = e.target.closest('button'); if (b) { peopleFilter = b.dataset.f; drawPeople(); } });
  $('people-search').addEventListener('input', drawPeople);
  $('people').addEventListener('keydown', e => { if (e.key === 'Enter' && e.target.matches('tr[data-user]')) e.target.click(); });
  $('people').addEventListener('click', async e => {
    const b = e.target.closest('[data-decide]');
    if (!b) { const tr = e.target.closest('tr[data-user]'); if (tr) location.hash = `pessoa/${tr.dataset.user}`; return; }
    const id = b.closest('tr').dataset.user, st = b.dataset.decide;
    try { await api(`access?user_id=eq.${id}`, { method: 'PATCH', body: { status: st, decided_at: new Date().toISOString() } }); toast(st === 'approved' ? 'Acesso aprovado.' : 'Acesso recusado.'); await renderPeople(); }
    catch (err) { fail(err); }
  });

  // Uma pessoa: conta, computador e aparelhos, uso em 30 dias, motores, erros, travamentos e o que ela mandou.
  // admin_person (migração 36) só devolve números, versões e o texto dos erros do agente, nunca conversas.
  // Os ids que o agente grava (botd/src/engines.ts): "cli:claude", "local:lmstudio/<modelo>", "api".
  const ENGINE = { 'cli:claude': 'Claude Code', 'cli:codex': 'Codex', 'cli:opencode': 'OpenCode', 'cli:antigravity': 'Antigravity', 'cli:grok': 'Grok', 'local:lmstudio': 'LM Studio', 'local:ollama': 'Ollama', api: 'API', 'cli:opencode-vm': 'OpenCode (computador dos Bots)' };
  const engineName = e => { const id = String(e || '').split(/[#/|]/)[0]; return ENGINE[id] || e || '—'; };
  // runs.model leva o motor e o modelo juntos ("cli:claude#opus", "local:ollama/qwen3"): aqui só o modelo.
  const modelName = m => { const t = String(m || ''); return t.includes('#') ? t.split('#')[1].split('|')[0] : t.startsWith('local:') ? t.split('/').slice(1).join('/') : /^(cli:|api$|auto$)/.test(t) || !t ? 'padrão' : t; };
  const fact = (k, v) => `<dt>${k}</dt><dd>${v}</dd>`;
  let personId = null;
  async function renderPerson(id) {
    personId = id;
    let d;
    try { [d] = await Promise.all([api('rpc/admin_person', { method: 'POST', body: { person: id } }), people.length ? null : loadPeople(), ideas.length || feedback.length ? null : loadInbox()]); }
    catch (err) {
      // Sem a migração 36 no banco, a função não existe: diz isso em vez de uma página vazia.
      if (/admin_person|function|schema cache/i.test(err.message)) { $('t-pessoa').textContent = 'Falta atualizar o banco'; $('person-sub').textContent = 'Esta página precisa da migração 36 (admin_person) no Supabase.'; return; }
      throw err;
    }
    if (personId !== id) return;
    const a = d?.account;
    if (!a) { $('t-pessoa').textContent = 'Pessoa não encontrada'; $('person-sub').textContent = ''; return; }
    const p = { ...a, ...(who(id) || {}) }, u = d.usage || {};
    const label = { approved: 'Aprovada', pending: 'Esperando', denied: 'Recusada' };
    $('person-avatar').outerHTML = avatar(p, true).replace('class="avatar', 'id="person-avatar" class="avatar');
    $('t-pessoa').textContent = personName(p);
    $('person-sub').innerHTML = `${personName(p) !== a.email ? `${esc(a.email)} · ` : ''}<span class="pill" data-st="${a.status}">${label[a.status] || a.status}</span>`;
    $('person-act').innerHTML = (a.status === 'approved' ? '' : `<button type="button" class="button button--small" data-decide="approved">Aprovar</button>`)
      + (a.status === 'denied' ? '' : `<button type="button" class="button button--small button--quiet" data-decide="denied">${a.status === 'approved' ? 'Tirar o acesso' : 'Recusar'}</button>`);

    const tile = (label, value, note = '') => `<div class="kpi"><span>${label}</span><b>${value}</b>${note ? `<small>${note}</small>` : ''}</div>`;
    $('person-kpis').innerHTML = [
      tile('Bots', nf.format(u.bots || 0), u.bots_7d ? `${u.bots_7d} ${u.bots_7d === 1 ? 'novo' : 'novos'} em 7 dias` : `${nf.format(u.conversations || 0)} conversas`),
      tile('Tarefas em 30 dias', nf.format(u.runs_30d || 0), `${nf.format(u.runs_7d || 0)} nos últimos 7 dias · ${nf.format(u.runs || 0)} no total`),
      tile('Com erro em 30 dias', nf.format(u.errors_30d || 0), u.runs_30d ? `${Math.round(100 * (u.errors_30d || 0) / u.runs_30d)}% das tarefas` : 'nenhuma tarefa'),
      tile('Tokens em 30 dias', tokens(u.tokens_30d || 0), u.last_run ? `última tarefa ${ago(u.last_run)}` : 'ainda não usou'),
      tile('Equivalente em API, 30 dias', money(u.cost_30d || 0), `${money(u.cost_7d || 0)} em 7 dias · ${money(u.cost_all || 0)} no total`),
      tile('Rotinas ligadas', nf.format(u.routines_on || 0), `de ${nf.format(u.routines || 0)} criadas`),
    ].join('');
    drawChart(d.runs_by_day || [], 'person');

    const provider = { email: 'Código por e-mail', apple: 'Apple', google: 'Google', github: 'GitHub' };
    $('person-account').innerHTML = [
      fact('Nome no app', esc(a.display_name || '—')),
      a.name && a.name !== a.display_name ? fact('Nome da conta', esc(a.name)) : '',
      fact('E-mail', esc(a.email || '—')),
      fact('Entra com', esc(provider[a.provider] || a.provider || '—')),
      fact('Criou a conta', date(a.created_at || a.requested_at)),
      fact('Acesso decidido', a.decided_at ? date(a.decided_at) : '—'),
      fact('Último login', a.last_sign_in_at ? `${ago(a.last_sign_in_at)} <small>· ${date(a.last_sign_in_at)}</small>` : '—'),
      fact('Primeira tarefa', u.first_run ? date(u.first_run) : '—'),
      fact('Fuso', esc(a.timezone || '—')),
      fact('Modelo padrão', esc(a.default_model === 'auto' ? 'Automático' : a.default_model || '—')),
      fact('Terminou o início', a.onboarding_done ? 'Sim' : 'Ainda não'),
    ].join('');

    const c = d.computer, inst = d.installs || [], devs = d.devices || [];
    const app = dev => inst.find(i => i.device === dev);
    const state = { awake: 'Ligado', busy: 'Trabalhando', asleep: 'Dormindo', waking: 'Acordando', offline: 'Desligado', error: 'Com erro' };
    const mac = app('macos'), ios = app('ios'), phone = devs.find(x => x.platform === 'ios');
    const engines = (c?.engines || []).map(e => `${esc(e.label || engineName(e.id))}${e.ready ? '' : ' <small>(falta configurar)</small>'}`).join(', ');
    $('person-devices').innerHTML = [
      fact('Agente (botd)', c ? `${esc(c.agent_version || '?')} <small>· ${state[c.status] || esc(c.status)}${c.last_seen_at ? `, visto ${ago(c.last_seen_at)}` : ''}</small>` : 'Nunca conectou um Mac'),
      fact('Motores no Mac', engines || '—'),
      fact('App do Mac', mac ? `${esc(mac.app_version || '?')} <small>· ${esc(mac.os_version || '')}${mac.last_seen_at ? `, aberto ${ago(mac.last_seen_at)}` : ''}</small>` : c ? '<small>versão ainda não informada</small>' : '—'),
      fact('App do iPhone', ios ? `${esc(ios.app_version || '?')} <small>· ${esc(ios.os_version || '')}${ios.last_seen_at ? `, aberto ${ago(ios.last_seen_at)}` : ''}</small>` : phone ? `<small>instalado, visto ${ago(phone.last_seen_at)}; versão ainda não informada</small>` : '—'),
      fact('Notificações', devs.length ? devs.map(x => `${x.platform === 'ios' ? 'iPhone' : 'Mac'} ${x.push ? 'ligadas' : 'desligadas'}`).join(', ') : '—'),
    ].join('');

    $('person-engines').querySelector('tbody').innerHTML = (d.engines || []).map(e => `<tr>
      <td>${esc(engineName(e.engine))}</td><td>${esc(modelName(e.model))}</td><td class="num">${nf.format(e.runs)}</td>
      <td class="num">${nf.format(e.errors)}</td><td class="num">${tokens(e.tokens || 0)}</td><td class="num">${money(e.cost || 0)}</td></tr>`).join('')
      || `<tr><td colspan="6" class="adm-empty">Nenhuma tarefa nos últimos 30 dias.</td></tr>`;

    const empty = t => `<li class="adm-empty">${t}</li>`;
    $('person-errors').innerHTML = (d.errors || []).map(e => `<li><code>${esc(e.error || 'sem mensagem')}</code><small>${ago(e.at)} · ${esc(engineName(e.engine))}${modelName(e.model) !== 'padrão' ? ` · ${esc(modelName(e.model))}` : ''}</small></li>`).join('') || empty('Nenhum erro.');
    const kind = { crash: 'Fechou sozinho', hang: 'Travou', cpu: 'CPU demais', disk: 'Disco demais' };
    $('person-crashes').innerHTML = (d.crashes || []).map(x => `<li>${kind[x.kind] || esc(x.kind)}<small>${esc(x.reason || '')}${x.reason ? ' · ' : ''}${x.device === 'ios' ? 'iPhone' : 'Mac'} ${esc(x.app_version || '')} · ${ago(x.at)}</small></li>`).join('') || empty('Nenhum travamento.');

    const sent = [...feedback.filter(f => f.user_id === id).map(f => ({ ...f, k: 'Feedback' })), ...ideas.filter(i => i.user_id === id).map(i => ({ ...i, k: 'Ideia' }))]
      .sort((x, y) => new Date(y.created_at) - new Date(x.created_at));
    $('person-inbox').innerHTML = sent.map(f => `<li>${esc(f.body.length > 280 ? f.body.slice(0, 280) + '…' : f.body)}
      <small>${f.k} · ${ago(f.created_at)}${f.app_version ? ` · ${esc(f.app_version)}` : ''}${f.logs ? ` · <button type="button" class="adm-link" data-logs="${f.id}">Ver registros</button>` : ''}</small></li>`).join('') || empty('Ainda não mandou nada.');
  }
  $('person-act').addEventListener('click', async e => {
    const b = e.target.closest('[data-decide]'); if (!b || !personId) return;
    const st = b.dataset.decide;
    if (st === 'denied' && !confirm('Tirar o acesso desta pessoa? Ela para de usar os Bots até você aprovar de novo.')) return;
    try { await api(`access?user_id=eq.${personId}`, { method: 'PATCH', body: { status: st, decided_at: new Date().toISOString() } }); toast(st === 'approved' ? 'Acesso aprovado.' : 'Acesso tirado.'); await loadPeople(); await renderPerson(personId); }
    catch (err) { fail(err); }
  });
  $('person-inbox').addEventListener('click', e => {
    const b = e.target.closest('[data-logs]'); if (!b) return;
    const f = feedback.find(x => x.id === b.dataset.logs); if (f) openLogs(f);
  });

  // Roadmap: o quadro.
  // No toque não tem arrastar: o cartão abre e a etapa muda no editor.
  const touch = matchMedia('(pointer: coarse)').matches;
  if (touch) $('board-hint').textContent = 'Toque num cartão para editar ou mudar de etapa. O roadmap público muda na hora.';
  async function renderBoardPage() { items = await api('roadmap_items?select=*&order=position.asc'); drawBoard(); }
  function drawBoard() {
    document.querySelectorAll('.adm-col').forEach(col => {
      const key = col.dataset.col, list = col.querySelector('[data-list]');
      const mine = items.filter(i => i.stage === key);
      list.innerHTML = mine.map(i => `<article class="adm-card" draggable="true" data-item="${i.id}" tabindex="0">
        <h3>${esc(i.title)}</h3>${i.summary ? `<p>${esc(i.summary)}</p>` : ''}
        <small>${[i.category, i.platforms, i.version].filter(Boolean).map(esc).join(' · ')}${i.published ? '' : ' · <em>escondido</em>'}</small>
      </article>`).join('') || `<p class="adm-empty">${touch ? 'Nenhum cartão aqui.' : 'Arraste um cartão para cá.'}</p>`;
      col.querySelector('[data-count]').textContent = mine.length;
    });
  }
  // Arrastar: a posição nova fica entre os vizinhos onde o cartão caiu.
  let dragging = null;
  const cols = $('adm-cols');
  cols.addEventListener('dragstart', e => {
    const card = e.target.closest('[data-item]'); if (!card) return;
    dragging = card.dataset.item; card.classList.add('is-dragging');
    e.dataTransfer.effectAllowed = 'move'; e.dataTransfer.setData('text/plain', dragging);
  });
  cols.addEventListener('dragend', e => { e.target.closest('[data-item]')?.classList.remove('is-dragging'); document.querySelectorAll('.adm-col.is-over').forEach(c => c.classList.remove('is-over')); });
  cols.addEventListener('dragover', e => {
    const col = e.target.closest('.adm-col'); if (!dragging || !col) return;
    e.preventDefault();
    document.querySelectorAll('.adm-col.is-over').forEach(c => c !== col && c.classList.remove('is-over'));
    col.classList.add('is-over');
  });
  cols.addEventListener('drop', async e => {
    const col = e.target.closest('.adm-col'); if (!dragging || !col) return;
    e.preventDefault(); col.classList.remove('is-over');
    const stage = col.dataset.col, id = dragging; dragging = null;
    const others = [...col.querySelectorAll('[data-item]')].filter(c => c.dataset.item !== id);
    const after = others.findIndex(c => e.clientY < c.getBoundingClientRect().top + c.offsetHeight / 2);
    const pos = k => items.find(i => i.id === others[k]?.dataset.item)?.position;
    let position;
    if (!others.length) position = Math.max(0, ...items.map(i => i.position)) + 1;
    else if (after === -1) position = pos(others.length - 1) + 1;
    else if (after === 0) position = pos(0) - 1;
    else position = (pos(after - 1) + pos(after)) / 2;
    const item = items.find(i => i.id === id), before = { stage: item.stage, position: item.position };
    Object.assign(item, { stage, position }); drawBoard();
    try { await api(`roadmap_items?id=eq.${id}`, { method: 'PATCH', body: { stage, position } }); toast(`Movido para ${STAGES[stage]}.`); }
    catch (err) { Object.assign(item, before); drawBoard(); fail(err); }
  });
  cols.addEventListener('click', e => { const card = e.target.closest('[data-item]'); if (card) openEditor(items.find(i => i.id === card.dataset.item)); });
  cols.addEventListener('keydown', e => { if (e.key === 'Enter' && e.target.matches('[data-item]')) e.target.click(); });
  document.querySelectorAll('[data-new]').forEach(b => b.addEventListener('click', () => openEditor({ stage: b.dataset.new, platforms: 'Mac e iPhone', published: true })));

  // O editor de um cartão (também é por onde uma ideia vira cartão).
  const dlg = $('adm-edit'), form = $('adm-form');
  let editing = null, fromIdea = null;
  function openEditor(item, idea = null) {
    editing = item; fromIdea = idea;
    $('adm-edit-title').textContent = item?.id ? 'Editar cartão' : (idea ? 'Ideia vira cartão' : 'Novo cartão');
    $('adm-edit-kind').textContent = item?.id ? STAGES[item.stage] : 'Cartão novo';
    $('adm-delete').hidden = !item?.id;
    const v = item || {};
    form.title.value = v.title || ''; form.summary.value = v.summary || ''; form.body.value = v.body || '';
    form.stage.value = v.stage || 'next'; form.platforms.value = v.platforms || 'Mac e iPhone';
    form.category.value = v.category || ''; form.version.value = v.version || '';
    form.included.value = (v.included || []).join('\n'); form.published.checked = v.published ?? true;
    dlg.showModal(); form.title.focus();
  }
  dlg.querySelectorAll('[data-close]').forEach(b => b.addEventListener('click', () => dlg.close()));
  form.addEventListener('submit', async e => {
    e.preventDefault();
    const body = {
      title: form.title.value.trim(), summary: form.summary.value.trim(), body: form.body.value.trim(),
      stage: form.stage.value, platforms: form.platforms.value, category: form.category.value.trim(),
      version: form.version.value.trim() || null, published: form.published.checked,
      included: form.included.value.split('\n').map(s => s.trim()).filter(Boolean),
    };
    try {
      if (editing?.id) await api(`roadmap_items?id=eq.${editing.id}`, { method: 'PATCH', body });
      else {
        if (!items.length) items = await api('roadmap_items?select=*&order=position.asc');
        const inStage = items.filter(i => i.stage === body.stage);
        body.position = inStage.length ? Math.min(...inStage.map(i => i.position)) - 1 : 0;   // entra no topo da coluna
        const [created] = await api('roadmap_items', { method: 'POST', body, prefer: 'return=representation' });
        if (fromIdea) await api(`roadmap_ideas?id=eq.${fromIdea.id}`, { method: 'PATCH', body: { status: 'accepted', item_id: created.id } });
      }
      dlg.close(); toast(fromIdea ? 'A ideia virou cartão do roadmap.' : 'Salvo. O roadmap público já mostra.'); route();
    } catch (err) { fail(err); }
  });
  $('adm-delete').addEventListener('click', async () => {
    if (!editing?.id || !confirm(`Apagar "${editing.title}"? Não tem como desfazer.`)) return;
    try { await api(`roadmap_items?id=eq.${editing.id}`, { method: 'DELETE' }); dlg.close(); toast('Cartão apagado.'); route(); }
    catch (err) { fail(err); }
  });

  // Ideias e feedback: uma caixa de entrada com filtro por tipo e situação.
  let inboxKind = 'feedback', inboxStatus = 'new';
  async function renderInbox() { await Promise.all([loadInbox(), people.length ? null : loadPeople()]); drawInbox(); }
  function drawInbox() {
    const q = $('inbox-search').value.trim().toLowerCase();
    document.querySelectorAll('#inbox-kind button').forEach(b => {
      b.setAttribute('aria-selected', b.dataset.k === inboxKind);
      b.querySelector('b').textContent = (b.dataset.k === 'ideas' ? ideas : feedback).filter(x => x.status === 'new').length;
    });
    document.querySelectorAll('#inbox-status button').forEach(b => b.setAttribute('aria-selected', b.dataset.st === inboxStatus));
    const list = (inboxKind === 'ideas' ? ideas : feedback).filter(x =>
      (inboxStatus === 'all' || (inboxStatus === 'new' ? x.status === 'new' : x.status !== 'new')) && (!q || x.body.toLowerCase().includes(q)));
    const from = x => { const p = who(x.user_id); return p ? esc(p.name || p.email) : (x.source === 'site' ? 'Visitante do site' : 'Alguém'); };
    const device = x => x.device === 'macos' ? 'Mac' : x.device === 'ios' ? 'iPhone' : '';
    $('inbox').innerHTML = list.map(x => inboxKind === 'ideas'
      ? `<li class="inbox__item" data-idea="${x.id}">
          <p>${esc(x.body)}</p>
          <small>${from(x)} · ${x.source === 'site' ? 'pelo site' : 'pelo app'}${x.app_version ? ` · ${esc(x.app_version)}` : ''}${x.contact ? ` · <a href="mailto:${esc(x.contact)}">${esc(x.contact)}</a>` : ''} · ${ago(x.created_at)}</small>
          <div class="inbox__acts">${x.status === 'new'
            ? '<button type="button" class="button button--small" data-accept>Virar cartão</button><button type="button" class="button button--small button--quiet" data-decline>Recusar</button>'
            : `<span class="pill" data-st="${x.status}">${x.status === 'accepted' ? 'Virou cartão' : 'Recusada'}</span>`}</div>
        </li>`
      : `<li class="inbox__item" data-fb="${x.id}">
          <p>${esc(x.body)}</p>
          <small>${from(x)}${device(x) ? ` · ${device(x)}` : ''}${x.app_version ? ` · ${esc(x.app_version)}` : ''}${x.os_version ? ` · ${esc(x.os_version)}` : ''} · ${ago(x.created_at)}</small>
          <div class="inbox__acts">
            ${x.logs ? '<button type="button" class="button button--small button--quiet" data-logs>Ver registros</button>' : ''}
            <label class="sr-only" for="st-${x.id}">Situação</label>
            <select id="st-${x.id}" data-status><option value="new"${x.status === 'new' ? ' selected' : ''}>Novo</option><option value="read"${x.status === 'read' ? ' selected' : ''}>Lido</option><option value="done"${x.status === 'done' ? ' selected' : ''}>Resolvido</option></select>
          </div>
        </li>`).join('') || `<li class="adm-empty">${inboxStatus === 'new' ? 'Nada novo por aqui.' : 'Nada por aqui.'}</li>`;
  }
  $('inbox-kind').addEventListener('click', e => { const b = e.target.closest('button'); if (b) { inboxKind = b.dataset.k; drawInbox(); } });
  $('inbox-status').addEventListener('click', e => { const b = e.target.closest('button'); if (b) { inboxStatus = b.dataset.st; drawInbox(); } });
  $('inbox-search').addEventListener('input', drawInbox);
  $('inbox').addEventListener('click', async e => {
    const ideaEl = e.target.closest('[data-idea]'), fbEl = e.target.closest('[data-fb]');
    if (ideaEl) {
      const idea = ideas.find(i => i.id === ideaEl.dataset.idea);
      if (e.target.closest('[data-accept]')) {
        const first = idea.body.split(/[.!?\n]/)[0].trim();
        openEditor({ stage: 'next', title: first.slice(0, 120), summary: idea.body.slice(0, 400), body: idea.body, platforms: 'Mac e iPhone', published: true }, idea);
      }
      if (e.target.closest('[data-decline]')) {
        try { await api(`roadmap_ideas?id=eq.${idea.id}`, { method: 'PATCH', body: { status: 'declined' } }); toast('Ideia recusada.'); await renderInbox(); } catch (err) { fail(err); }
      }
    }
    if (fbEl && e.target.closest('[data-logs]')) openLogs(feedback.find(f => f.id === fbEl.dataset.fb));
  });
  $('inbox').addEventListener('change', async e => {
    const sel = e.target.closest('[data-status]'); if (!sel) return;
    const id = sel.closest('[data-fb]').dataset.fb;
    try { await api(`feedback?id=eq.${id}`, { method: 'PATCH', body: { status: sel.value } }); toast('Situação atualizada.'); await loadInbox(); drawInbox(); } catch (err) { fail(err); }
  });

  // Os registros de um feedback: ler, copiar ou baixar como .txt.
  const logs = $('adm-logs');
  let shownLogs = null;
  function openLogs(f, title = 'Registros') {
    shownLogs = f;
    $('adm-logs-title').textContent = title;
    const p = who(f.user_id);
    $('adm-logs-meta').textContent = [p?.email, f.device === 'macos' ? 'Mac' : 'iPhone', f.app_version, new Date(f.created_at).toLocaleString('pt-BR')].filter(Boolean).join(' · ');
    $('adm-logs-text').textContent = f.logs;
    logs.showModal();
  }
  logs.querySelectorAll('[data-close]').forEach(b => b.addEventListener('click', () => logs.close()));
  $('adm-logs-copy').addEventListener('click', async () => { try { await navigator.clipboard.writeText(shownLogs.logs); toast('Registros copiados.'); } catch { toast('Não deu para copiar.', 'erro'); } });
  $('adm-logs-save').addEventListener('click', () => {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([shownLogs.logs], { type: 'text/plain' }));
    a.download = `bots-registros-${shownLogs.created_at.slice(0, 10)}-${shownLogs.id.slice(0, 8)}.txt`;
    a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  });

  // Travamentos: agrupados pelo lugar onde quebrou; o relatório mais recente de cada grupo abre inteiro.
  let crashDays = 30, crashes = [];
  const KIND = { crash: 'Fechou sozinho', hang: 'Travou', cpu: 'CPU demais', disk: 'Disco demais' };
  async function renderCrashes() {
    [crashes] = await Promise.all([api('rpc/admin_crashes', { method: 'POST', body: { days: crashDays } }), people.length ? null : loadPeople()]);
    crashes = crashes || [];
    document.querySelectorAll('#crash-days button').forEach(b => b.setAttribute('aria-selected', +b.dataset.d === crashDays));
    $('crashes').innerHTML = crashes.map((g, i) => `<li class="inbox__item" data-crash="${i}">
      <p><span class="pill" data-st="${g.kind === 'crash' ? 'denied' : 'pending'}">${KIND[g.kind] || g.kind}</span> <b>${esc(g.reason)}</b></p>
      <small>${esc(g.signature)}<br>${g.reports} ${g.reports === 1 ? 'vez' : 'vezes'} · ${g.people} ${g.people === 1 ? 'pessoa' : 'pessoas'} · ${g.devices.map(d => d === 'macos' ? 'Mac' : 'iPhone').join(' e ')} · versões ${g.versions.map(esc).join(', ')} · última ${ago(g.last_seen)}</small>
      <div class="inbox__acts"><button type="button" class="button button--small button--quiet" data-open>Ver o relatório</button></div>
    </li>`).join('') || `<li class="adm-empty">Nenhum travamento nos últimos ${crashDays} dias.</li>`;
  }
  $('crash-days').addEventListener('click', e => { const b = e.target.closest('button'); if (b) { crashDays = +b.dataset.d; renderCrashes().catch(fail); } });
  $('crashes').addEventListener('click', async e => {
    const li = e.target.closest('[data-crash]'); if (!li || !e.target.closest('[data-open]')) return;
    const g = crashes[+li.dataset.crash];
    try {
      const [r] = await api(`crash_reports?select=*&id=eq.${g.latest}`);
      let pretty = r.payload || '';
      try { pretty = JSON.stringify(JSON.parse(pretty), null, 2); } catch {}
      openLogs({ id: r.id, user_id: r.user_id, device: r.device, app_version: r.app_version, created_at: r.occurred_at,
        logs: `${KIND[r.kind] || r.kind}: ${r.reason}\n${r.signature}\n${r.os_version || ''}\n\n${pretty}` }, 'Relatório de travamento');
    } catch (err) { fail(err); }
  });

  // Versões e avisos.
  async function renderVersions() {
    const [versions, list] = await Promise.all([api('rpc/admin_versions', { method: 'POST', body: {} }), api('announcements?select=*&order=created_at.desc')]);
    notices = list;
    const max = Math.max(1, ...versions.map(v => v.installs));
    const block = dev => {
      const rows = versions.filter(v => v.device === dev);
      return `<h3>${dev === 'macos' ? 'Mac' : 'iPhone'}</h3>` + (rows.map(v => `<div class="vbar"><span class="vbar__name">${esc(v.app_version)}</span>
        <span class="vbar__track"><i style="width:${(v.installs / max) * 100}%"></i></span>
        <span class="vbar__n">${v.installs} ${v.installs === 1 ? 'aparelho' : 'aparelhos'}<small>${v.active_7d} em uso nos últimos 7 dias</small></span></div>`).join('') || '<p class="adm-empty">Nenhum ainda.</p>');
    };
    $('versions').innerHTML = block('macos') + block('ios');
    const now = Date.now();
    const state = n => new Date(n.starts_at) > now ? ['agendado', 'Agendado'] : n.ends_at && new Date(n.ends_at) <= now ? ['fim', 'Encerrado'] : ['on', 'Valendo'];
    $('notices').innerHTML = notices.map(n => { const [k, l] = state(n); return `<li class="notice" data-notice="${n.id}">
      <div><span class="pill" data-st="${k}">${l}</span><b>${esc(n.title)}</b>${n.body ? `<p>${esc(n.body)}</p>` : ''}
      <small>Publicado em ${new Date(n.starts_at).toLocaleDateString('pt-BR')}${n.ends_at ? ` · até ${new Date(n.ends_at).toLocaleDateString('pt-BR')}` : ''}${n.link ? ` · <a href="${esc(n.link)}" target="_blank" rel="noopener">link</a>` : ''}</small></div>
      <div class="inbox__acts">${k === 'on' ? '<button type="button" class="button button--small button--quiet" data-end>Encerrar agora</button>' : ''}<button type="button" class="adm-danger" data-del>Apagar</button></div>
    </li>`; }).join('') || '<li class="adm-empty">Nenhum aviso ainda.</li>';
  }
  $('notice-form').addEventListener('submit', async e => {
    e.preventDefault();
    const f = e.target;
    const body = { title: f.title.value.trim(), body: f.body.value.trim(), link: f.link.value.trim() || null, ends_at: f.ends_at.value ? new Date(f.ends_at.value + 'T23:59:59').toISOString() : null };
    try { await api('announcements', { method: 'POST', body }); f.reset(); toast('Aviso publicado. Aparece no app de quem testa.'); await renderVersions(); } catch (err) { fail(err); }
  });
  $('notices').addEventListener('click', async e => {
    const li = e.target.closest('[data-notice]'); if (!li) return;
    const id = li.dataset.notice;
    try {
      if (e.target.closest('[data-end]')) { await api(`announcements?id=eq.${id}`, { method: 'PATCH', body: { ends_at: new Date().toISOString() } }); toast('Aviso encerrado.'); }
      else if (e.target.closest('[data-del]')) { if (!confirm('Apagar este aviso?')) return; await api(`announcements?id=eq.${id}`, { method: 'DELETE' }); toast('Aviso apagado.'); }
      else return;
      await renderVersions();
    } catch (err) { fail(err); }
  });

  // ---------- começar ----------
  // Senha do painel: muda a senha da conta no Supabase (PUT /auth/v1/user) com a sessão aberta.
  const passDlg = $('adm-pass-dlg'), passForm = $('adm-pass-form');
  $('adm-set-pass').addEventListener('click', () => { passForm.reset(); status($('adm-pass-status'), ''); passDlg.showModal(); passForm.pass.focus(); });
  passDlg.querySelectorAll('[data-close]').forEach(b => b.addEventListener('click', () => passDlg.close()));
  passForm.addEventListener('submit', async e => {
    e.preventDefault();
    if (passForm.pass.value !== passForm.again.value) return status($('adm-pass-status'), 'As duas senhas não são iguais.', 'erro');
    status($('adm-pass-status'), 'Salvando…');
    try {
      const t = await token(); if (!t) throw new Error('A sessão acabou. Entre de novo.');
      const r = await fetch(`${cfg.url}/auth/v1/user`, { method: 'PUT', headers: { apikey: cfg.key, authorization: `Bearer ${t}`, 'content-type': 'application/json' }, body: JSON.stringify({ password: passForm.pass.value }) });
      const out = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(/reauth/i.test(`${out.msg} ${out.error_code}`) ? 'Por segurança, saia e entre de novo com o código do e-mail antes de trocar a senha.'
        : /weak|short|characters/i.test(`${out.msg} ${out.error_code}`) ? 'Essa senha é fraca demais. Use 12 caracteres ou mais, misturando letras e números.' : out.msg || out.message || 'Não deu para salvar a senha.');
      if (session?.email) rememberEmail(session.email);
      passDlg.close(); toast('Senha salva. No celular, o painel pede esta senha.');
    } catch (err) { status($('adm-pass-status'), err.message, 'erro'); }
  });

  async function start() {
    if (!cfg) { show('login'); status($('adm-login-status'), 'Falta a configuração do Supabase (supabase.js).', 'erro'); return; }
    if (!(await token()) && !session) return show('login');
    try {
      const admin = await api('rpc/is_admin', { method: 'POST', body: {} });
      if (!admin) return show('denied');
      show('shell');
      route();
    } catch (err) { if (session) { show('shell'); fail(err); } else { show('login'); status($('adm-login-status'), err.message, 'erro'); } }
  }
  start();
  // Renova a sessão antes de vencer, mesmo com a aba parada: neste Mac o painel nunca pede o código de novo,
  // e no celular não pede a senha no meio do uso.
  setInterval(() => { if (session) token().catch(() => {}); }, 10 * 60 * 1000);
  document.addEventListener('visibilitychange', () => { if (!document.hidden && session) token().catch(() => {}); });
})();
