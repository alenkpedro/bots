// Site dos Bots: mascotes que olham para o ponteiro (como no Entrar do app), o app montado na página, as funções
// dos Bots e o roadmap. Sem bibliotecas.
(() => {
  const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;

  // ---------- mascotes ----------
  const bodies = {
    none: '',
    round: '<circle cx="50" cy="52" r="44"/>',
    square: '<rect x="8" y="12" width="84" height="80" rx="24"/>',
    bean: '<path d="M8 56c0-24 18-38 42-38s42 14 42 38-18 32-42 32S8 80 8 56z"/>',
    hex: '<path d="M50 6l38 22v44L50 94 12 72V28z"/>',
    ghost: '<path d="M12 50a38 38 0 0 1 76 0v38c-6 5-12 5-19 0-6 5-13 5-19 0-6 5-13 5-19 0-7 5-13 5-19 0z"/>',
  };
  const eye = x => `<circle cx="${x}" cy="46" r="11" fill="#fff"/><g class="pupil"><circle cx="${x}" cy="46" r="6" fill="#111"/><circle cx="${x + 2}" cy="43.5" r="2" fill="#fff"/></g><rect class="lid" x="${x - 12}" y="34" width="24" height="24" rx="12" fill="currentColor"/>`;
  function mascot(el) {
    const hue = el.dataset.hue || '#38bdf8', shape = el.dataset.mascot;
    const view = shape === 'none' ? '22 32 56 42' : '0 0 100 100';
    el.innerHTML = `<svg class="mascot" viewBox="${view}" aria-hidden="true" style="color:${hue}"><g class="mascot__body"><g fill="${hue}">${bodies[shape] ?? bodies.round}</g>${eye(36)}${eye(64)}<path d="M43 66q7 6 14 0" fill="none" stroke="#111" stroke-opacity=".7" stroke-width="3.5" stroke-linecap="round"/><g class="hands" fill="${hue}" stroke="#111" stroke-opacity=".35" stroke-width="2.5"><ellipse cx="34" cy="47" rx="14" ry="11"/><ellipse cx="66" cy="47" rx="14" ry="11"/></g></g></svg>`;
  }
  const paint = root => root.querySelectorAll('[data-mascot]').forEach(mascot);
  paint(document);

  // Os olhos seguem o ponteiro, como no app: só os mascotes do lugar onde o mouse está (a linha da lista, o cartão,
  // o botão, o topo da página). Os outros olham para frente e ficam parados, sem custo nenhum enquanto o mouse anda.
  // A cada quadro, primeiro lê as posições de todos e só depois mexe nas pupilas (ler e escrever misturado força o
  // navegador a recalcular a página várias vezes).
  const ZONES = '.app__bot, .app__head, .ui-row, .chips button, .job, .team, .hero > :not(.app), .cta, [data-peek], .call, .phone, .b-login, .bar__name, .rm-top';
  let px = 0, py = 0, queued = false, watching = [];
  const center = svg => svg.querySelectorAll('.pupil').forEach(p => p.style.transform = '');
  function look() {
    queued = false;
    const spots = watching.map(svg => svg.getBoundingClientRect());
    watching.forEach((svg, i) => {
      const r = spots[i], dx = px - (r.left + r.width / 2), dy = py - (r.top + r.height / 2);
      const d = Math.hypot(dx, dy) || 1, k = Math.min(1, d / 300) * 4.5;
      svg.querySelectorAll('.pupil').forEach(p => p.style.transform = `translate(${(dx / d) * k}px, ${(dy / d) * k}px)`);
    });
  }
  const queue = () => { if (!queued && watching.length) { queued = true; requestAnimationFrame(look); } };
  addEventListener('pointermove', e => {
    px = e.clientX; py = e.clientY;
    const now = [];
    for (let z = e.target.closest?.(ZONES); z; z = z.parentElement?.closest(ZONES)) {
      now.push(...z.querySelectorAll('.mascot'));
      if (z.matches('.hero > :not(.app)')) now.push(...document.querySelectorAll('.hero > h1 .mascot'));   // o rosto do título olha quando o mouse está no topo
    }
    watching.filter(svg => !now.includes(svg)).forEach(center);
    watching = now;
    queue();
  }, { passive: true });
  addEventListener('scroll', queue, { passive: true });
  document.documentElement.addEventListener('pointerleave', () => { watching.forEach(center); watching = []; });
  if (!reduce) setInterval(() => {
    const all = [...document.querySelectorAll('.mascot')];
    const m = all[Math.floor(Math.random() * all.length)];
    if (!m) return;
    m.classList.add('is-blinking');
    setTimeout(() => m.classList.remove('is-blinking'), 200);
  }, 1400);

  // A barra de cima ganha fundo só depois que a página rola.
  const bar = document.querySelector('.bar');
  if (bar) {
    const stick = () => bar.classList.toggle('is-stuck', scrollY > 8);
    addEventListener('scroll', stick, { passive: true });
    stick();
  }

  // Um gesto de cada vez no mascote (pulo ou amassado): recomeça mesmo se o anterior não terminou.
  function play(svg, cls) {
    if (reduce || !svg) return;
    svg.classList.remove('is-hopping', 'is-squished');
    void svg.getBoundingClientRect();
    svg.classList.add(cls);
    svg.addEventListener('animationend', () => svg.classList.remove(cls), { once: true });
  }
  // Números que contam até o valor (do que estava antes até o novo), em vez de trocar de repente.
  function countUp(el, to, ms = 900) {
    const from = parseInt(el.textContent, 10) || 0;
    if (reduce || from === to) { el.textContent = to; return; }
    const t0 = performance.now();
    const step = now => {
      const k = Math.min(1, (now - t0) / ms), e = 1 - Math.pow(1 - k, 3);
      el.textContent = Math.round(from + (to - from) * e);
      if (k < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }
  // Tocou num mascote, ele amassa e volta, como uma bolinha de borracha.
  addEventListener('pointerdown', e => play(e.target.closest?.('.mascot'), 'is-squished'));

  // ---------- entrada das seções ----------
  const io = new IntersectionObserver(entries => entries.forEach(e => {
    if (e.isIntersecting) { e.target.classList.add('is-in'); io.unobserve(e.target); }
  }), { rootMargin: '0px 0px -10% 0px' });
  document.querySelectorAll('.rv').forEach(el => io.observe(el));

  // ---------- abas e filtros com uma pílula que desliza até o escolhido ----------
  document.querySelectorAll('.chips[role="tablist"], .rm-tabs').forEach(bar => {
    const glider = document.createElement('span');
    glider.className = 'glider'; glider.setAttribute('aria-hidden', 'true');
    bar.classList.add('has-glider', 'is-still'); bar.prepend(glider);
    const place = () => {
      const on = bar.querySelector('[aria-selected="true"]');
      if (!on) return;
      glider.style.transform = `translate(${on.offsetLeft}px, ${on.offsetTop}px)`;
      glider.style.width = `${on.offsetWidth}px`; glider.style.height = `${on.offsetHeight}px`;
    };
    place();
    requestAnimationFrame(() => bar.classList.remove('is-still'));   // a primeira posição não anima
    new MutationObserver(place).observe(bar, { subtree: true, attributes: true, attributeFilter: ['aria-selected'], childList: true, characterData: true });
    addEventListener('resize', () => { bar.classList.add('is-still'); place(); requestAnimationFrame(() => bar.classList.remove('is-still')); }, { passive: true });
  });

  // ---------- Dynamic Island da tela bloqueada: abre a cada poucos segundos e o número de voos avança ----------
  const island = document.querySelector('.island');
  if (island && !reduce) {
    const n = island.querySelector('.island__n');
    let seen = false, voos = 32;
    new IntersectionObserver(es => { seen = es[0].isIntersecting; }).observe(island);
    setInterval(() => {
      if (!seen) return;
      const open = !island.classList.contains('is-open');
      if (open) { voos = voos >= 40 ? 32 : voos + 2; setTimeout(() => countUp(n, voos, 700), 300); }
      island.classList.toggle('is-open', open);
    }, 3200);
  }

  // ---------- Perguntas: abrem com uma mola (passa um tiquinho e acomoda) e fecham rápido ----------
  document.querySelectorAll('.faq details').forEach(d => {
    const sum = d.querySelector('summary');
    let anim = null;
    sum.addEventListener('click', e => {
      if (reduce) return;   // o <details> abre e fecha sozinho, sem animação
      e.preventDefault();
      anim?.cancel();
      const from = d.offsetHeight;
      if (!d.open) {
        d.open = true;
        const to = d.offsetHeight;
        anim = d.animate([{ height: `${from}px` }, { height: `${to}px` }], { duration: 560, easing: 'cubic-bezier(0.3, 1.35, 0.5, 1)' });
        d.querySelector('p')?.animate([{ opacity: 0, transform: 'translateY(-6px)', filter: 'blur(3px)' }, { opacity: 1, transform: 'none', filter: 'none' }], { duration: 380, delay: 80, easing: 'ease-out', fill: 'backwards' });
      } else {
        anim = d.animate([{ height: `${from}px` }, { height: `${sum.offsetHeight}px` }], { duration: 260, easing: 'cubic-bezier(0.4, 0, 0.2, 1)' });
        anim.onfinish = () => { d.open = false; };
      }
    });
  });

  // ---------- botões de baixar ----------
  // O clique mostra que funcionou: o botão vira uma barrinha que enche e termina em "✓ Baixando". O download é o de
  // verdade (o link segue normal); depois de uns segundos o botão volta a ser o que era.
  document.querySelectorAll('[data-dl]').forEach(btn => {
    let busy = false;
    btn.addEventListener('click', () => {
      if (busy) return;
      busy = true;
      const html = btn.innerHTML;
      btn.style.width = `${btn.offsetWidth}px`;   // a largura não muda: o vizinho não sai do lugar
      btn.classList.add('is-loading');
      const peek = btn.querySelector('.peek');   // o mascote fica e comemora com um pulo
      const swap = inner => { btn.innerHTML = inner; if (peek) btn.prepend(peek); };
      swap('<span class="dl__bar" aria-hidden="true"></span><span>Preparando…</span>');
      setTimeout(() => {
        btn.classList.replace('is-loading', 'is-done');
        swap(`<span class="dl__check" aria-hidden="true">✓</span>${btn.dataset.done}`);
        play(peek?.querySelector('.mascot'), 'is-hopping');
      }, reduce ? 0 : 1100);
      setTimeout(() => {
        btn.classList.replace('is-done', 'is-back'); btn.innerHTML = html; paint(btn); btn.style.width = ''; busy = false;
        setTimeout(() => btn.classList.remove('is-back'), 400);
      }, 4200);
    });
  });
  // Um mascotinho mora atrás dos botões principais: no hover ele sobe pela borda e espia (e olha para o cursor).
  document.querySelectorAll('[data-peek]').forEach(btn => {
    btn.insertAdjacentHTML('afterbegin', '<span class="peek" aria-hidden="true"><span data-mascot="round" data-hue="#38bdf8"></span></span>');
    paint(btn.querySelector('.peek'));
  });
  // Botão magnético: com o mouse por perto, o botão vai uns pixels na direção dele. Só com mouse e com movimento.
  if (!reduce && matchMedia('(pointer: fine)').matches) {
    const magnets = [...document.querySelectorAll('[data-magnet]')];
    addEventListener('pointermove', e => magnets.forEach(m => {
      const r = m.getBoundingClientRect(), cx = r.left + r.width / 2, cy = r.top + r.height / 2;
      const dx = e.clientX - cx, dy = e.clientY - cy, near = Math.abs(dx) < r.width / 2 + 60 && Math.abs(dy) < r.height / 2 + 50;
      // No máximo 4 px para o lado e 3 px para cima/baixo: o vizinho fica a 12 px, e o botão nunca encosta nele.
      const clamp = (v, m) => Math.max(-m, Math.min(m, v));
      m.style.translate = near ? `${clamp(dx * 0.08, 4).toFixed(1)}px ${clamp(dy * 0.15, 3).toFixed(1)}px` : '';
    }), { passive: true });
  }

  // ---------- o app montado na página: cada Bot da lista abre uma conversa de exemplo ----------
  const chat = document.getElementById('app-chat');
  if (chat) {
    const esc = s => s.replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
    const bots = {
      caixa: { me: 'Dá conta dos e-mails de hoje?', bot: ['Caixa zerada. Respondi 6, arquivei 23 e deixei 4 rascunhos no seu tom para você revisar.', 'Um cliente pediu o orçamento atualizado. O rascunho está pronto.'], card: ['Enviar a resposta para o cliente', 'Sai pelo seu Gmail, com o orçamento anexado.', 'Enviar', 'Revisar antes'], yes: 'Enviado pelo seu Gmail.', no: 'Ficou nos rascunhos para você revisar.' },
      viagens: { me: 'Monta um roteiro de 5 dias em Lisboa em dezembro', bot: ['Comparei voos e hotéis no navegador do meu computador. O melhor custo fica em R$ 4.380 por pessoa, com hotel no centro.', 'Montei o roteiro dia a dia, com os horários dos museus e onde comer perto.'], card: ['Reservar o hotel', '5 noites no centro, cancelamento grátis até 1º de dezembro.', 'Reservar', 'Ainda não'], yes: 'Reservado. A confirmação chegou no seu e-mail.', no: 'Tudo bem, deixei salvo para depois.' },
      contas: { me: 'Paga a conta de luz que vence hoje', bot: ['Achei a conta no seu e-mail: R$ 236,40, vence hoje. Para pagar, preciso entrar no app do banco.'], card: ['Contas da casa precisa da sua aprovação', 'Pagar R$ 236,40 no site do banco.', 'Permitir uma vez', 'Negar'], yes: 'Permitido uma vez. Pago, e o comprovante está na conversa.', no: 'Negado. Não paguei e aguardo você.' },
      loja: { me: 'Responde os clientes que perguntaram do prazo', bot: ['Respondi 12 perguntas sobre prazo e 3 sobre troca.', 'Dois pedidos atrasaram na transportadora. Avisei os clientes e mandei o código de rastreio.'] },
      estudos: { me: 'Resume o capítulo 5 e monta 10 perguntas para a prova', bot: ['Li o PDF da aula. O resumo tem uma página, e as 10 perguntas vêm com as respostas no fim.', 'Quer que eu monte um cronograma de revisão até a prova?'] },
      saude: { me: 'Marca a consulta com a dermatologista', bot: ['Achei horário na terça às 15h, perto do seu trabalho.'], card: ['Confirmar a consulta', 'Terça, 15h, no site da clínica.', 'Confirmar', 'Outro horário'], yes: 'Confirmada. Coloquei na sua agenda com um lembrete.', no: 'Vou procurar outros horários e te mostro.' },
    };
    const rules = [
      [/pag|fatura|boleto|pix|conta de|imposto|nota fiscal|transfer|cobran|gasto|recibo/i, 'contas'],
      [/viag|voo|hotel|passagem|roteiro|f[eé]rias/i, 'viagens'],
      [/consulta|m[eé]dic|dentista|exame|rem[eé]dio|academia/i, 'saude'],
      [/estud|prova|resum|aula|trabalho da escola|faculdade|livro/i, 'estudos'],
      [/cliente|loja|pedido|estoque|venda|produto|an[uú]ncio/i, 'loja'],
      [/e-?mail|caixa|responde|rascunho|gmail|reuni|agenda/i, 'caixa'],
    ];
    const list = [...document.querySelectorAll('.app__bot')];
    const head = document.getElementById('app-head');
    let current, working = null;
    // Quem está sem trabalho cochila (olhos fechados e uns "z"). Acorda com um pulo quando você abre a conversa ou
    // manda um pedido, e volta a cochilar uns segundos depois que você vai para outro Bot.
    const naps = new Map();
    const sleep = row => { if (row.dataset.sleepy !== undefined && row.getAttribute('aria-selected') !== 'true' && !row.classList.contains('is-working')) row.dataset.sleep = ''; };
    const wake = row => {
      clearTimeout(naps.get(row));
      if (row.dataset.sleep === undefined) return;
      delete row.dataset.sleep;
      play(row.querySelector('.mascot'), 'is-hopping');
    };
    const nap = row => { clearTimeout(naps.get(row)); naps.set(row, setTimeout(() => sleep(row), 9000)); };
    // Quem recebeu um pedido pula, e balança enquanto trabalha; depois de uns segundos a linha volta ao que era.
    function work(row) {
      if (working) { clearTimeout(working.timer); working.done(); }
      const svg = row.querySelector('.mascot'), small = row.querySelector('small');
      const before = [small.textContent, small.dataset.tone];
      small.textContent = 'Trabalhando…'; small.dataset.tone = 'go';
      row.classList.add('is-working');
      // No celular a lista de Bots é uma fileira que rola de lado: traz para a vista quem recebeu o pedido.
      const side = row.parentElement;
      if (side.scrollWidth > side.clientWidth) {
        const s = side.getBoundingClientRect(), r = row.getBoundingClientRect();
        side.scrollTo({ left: side.scrollLeft + r.left - s.left - (s.width - r.width) / 2, behavior: reduce ? 'auto' : 'smooth' });
      }
      play(svg, 'is-hopping'); play(head.querySelector('.mascot'), 'is-hopping');
      const done = () => {
        row.classList.remove('is-working'); head.classList.remove('is-working');
        nap(row);
        small.textContent = before[0];
        if (before[1]) small.dataset.tone = before[1]; else delete small.dataset.tone;
        working = null;
      };
      working = { done, timer: setTimeout(done, 4500) };
      head.classList.add('is-working');
    }
    function open(id, ask) {
      if (working && !ask) { clearTimeout(working.timer); working.done(); }
      current = id; const b = bots[id], row = list.find(x => x.dataset.bot === id);
      list.forEach(x => { if (x.getAttribute('aria-selected') === 'true' && x !== row) nap(x); x.setAttribute('aria-selected', x === row); });
      wake(row);
      head.innerHTML = row.querySelector('span').outerHTML + `<span>${row.querySelector('b').textContent}</span>` + (b.card && !ask ? ' <small>· esperando você</small>' : ' <small>· trabalhando</small>');
      let html = `<p class="msg-me">${esc(ask || b.me)}</p>` + (ask ? `<p class="msg-bot">Pode deixar. Já estou nisso e te aviso quando terminar.</p>` : b.bot.map(t => `<p class="msg-bot">${t}</p>`).join(''));
      if (b.card && !ask) html += `<div class="msg-card"><strong>${b.card[0]}</strong><p>${b.card[1]}</p><div class="msg-card__buttons"><button type="button" class="yes">${b.card[2]}</button><button type="button" class="no">${b.card[3]}</button></div></div>`;
      chat.innerHTML = html;
      head.querySelectorAll('[data-mascot]').forEach(mascot);
      if (ask) work(row);
    }
    list.forEach(x => x.addEventListener('click', () => open(x.dataset.bot)));
    const answer = (box, ok) => {
      box.remove();
      chat.insertAdjacentHTML('beforeend', `<p class="msg-note"${ok ? '' : ' data-tone="no"'}>${ok ? '✓ ' : ''}${bots[current][ok ? 'yes' : 'no']}</p>`);
      if (ok) { play(head.querySelector('.mascot'), 'is-hopping'); play(list.find(x => x.dataset.bot === current).querySelector('.mascot'), 'is-hopping'); }
    };
    chat.addEventListener('click', e => {
      const btn = e.target.closest('.msg-card__buttons button');
      if (btn) answer(btn.parentElement, btn.classList.contains('yes'));
    });
    // Enquanto você digita, o Bot daquele assunto se interessa: inclina a cabeça, acorda se estava cochilando e diz
    // "Isso é comigo!". Mudou de assunto, ele volta ao que estava fazendo.
    const input = document.getElementById('app-input');
    let curious = null;
    const calm = () => {
      if (!curious) return;
      const { row, before } = curious, small = row.querySelector('small');
      row.classList.remove('is-curious');
      if (!row.classList.contains('is-working')) { small.textContent = before[0]; if (before[1]) small.dataset.tone = before[1]; else delete small.dataset.tone; }
      if (before[2]) nap(row);
      curious = null;
    };
    input.addEventListener('input', () => {
      const id = (rules.find(([re]) => re.test(input.value)) || [])[1];
      const row = id && list.find(x => x.dataset.bot === id);
      if (curious?.row === row) return;
      calm();
      if (!row || row.classList.contains('is-working')) return;
      const small = row.querySelector('small'), slept = row.dataset.sleep !== undefined;
      curious = { row, before: [small.textContent, small.dataset.tone, slept] };
      wake(row);
      row.classList.add('is-curious');
      small.textContent = 'Isso é comigo!'; small.dataset.tone = 'hey';
    });
    document.getElementById('app-ask').addEventListener('submit', e => {
      e.preventDefault();
      calm();
      const text = input.value.trim();
      if (!text) return;
      open((rules.find(([re]) => re.test(text)) || [, 'caixa'])[1], text);
      input.value = '';
    });
    list.forEach(sleep);
    open('contas');
    // Avisos dos outros Bots: um a cada poucos segundos enquanto a demo está na tela. Clicar num aviso abre a conversa.
    const toasts = document.getElementById('app-toasts'), app = chat.closest('.app');
    const news = [['viagens', 'Achei um voo R$ 380 mais barato para Lisboa.'], ['caixa', 'Caixa zerada. 4 rascunhos esperando você.'], ['loja', '2 pedidos atrasados: já avisei os clientes.'], ['viagens', 'Check-in feito. O cartão de embarque está no chat.'], ['caixa', 'O cliente respondeu: orçamento aprovado.']];
    let nk = 0, demoSeen = false;
    new IntersectionObserver(es => { demoSeen = es[0].isIntersecting; }, { threshold: 0.5 }).observe(app);
    const stack = () => [...toasts.children].filter(t => !t.classList.contains('is-gone')).forEach((t, i) => { t.dataset.i = i; });
    const dismiss = t => { t.classList.add('is-gone'); setTimeout(() => t.remove(), 400); stack(); };
    setInterval(() => {
      if (!demoSeen || document.hidden) return;
      const [id, text] = news[nk++ % news.length], row = list.find(x => x.dataset.bot === id);
      if (id === current) return;
      const t = document.createElement('button');
      t.type = 'button'; t.className = 'toast is-new'; t.dataset.bot = id;
      t.innerHTML = `${row.querySelector('span').outerHTML}<span><b>${row.querySelector('b').textContent}</b><small>${text}</small></span>`;
      paint(t); toasts.prepend(t); stack();
      requestAnimationFrame(() => requestAnimationFrame(() => t.classList.remove('is-new')));
      play(row.querySelector('.mascot'), 'is-hopping');
      setTimeout(() => t.isConnected && dismiss(t), 9000);
      [...toasts.children].slice(4).forEach(x => x.remove());
    }, 5200);
    toasts.addEventListener('click', e => { const t = e.target.closest('.toast'); if (!t) return; open(t.dataset.bot); dismiss(t); });
  }

  // ---------- os apps num globo que gira devagar (cartão "Seus apps") ----------
  const globe = document.querySelector('.globe');
  if (globe) {
    const pills = [...globe.children], n = pills.length;
    // Cada app num ponto da esfera (espiral de Fibonacci: espalha por igual).
    const pts = pills.map((_, i) => { const y = 1 - (i + 0.5) * 2 / n, r = Math.sqrt(1 - y * y), a = i * 2.39996; return [Math.cos(a) * r, y, Math.sin(a) * r]; });
    let turn = 0, raf = 0, visible = false;
    const tilt = -0.32, ct = Math.cos(tilt), st = Math.sin(tilt);
    function draw() {
      const R = globe.clientWidth * 0.4, c = Math.cos(turn), s = Math.sin(turn);
      pts.forEach(([x, y, z], i) => {
        const x1 = x * c + z * s, z1 = -x * s + z * c;          // gira em volta do eixo vertical
        const y2 = y * ct - z1 * st, z2 = y * st + z1 * ct;     // e inclina um pouco para frente
        const depth = (z2 + 1) / 2;                              // 0 atrás, 1 na frente
        const el = pills[i];
        el.style.transform = `translate(-50%, -50%) translate3d(${(x1 * R).toFixed(1)}px, ${(y2 * R).toFixed(1)}px, 0) scale(${(0.62 + depth * 0.48).toFixed(3)})`;
        el.style.opacity = depth > 0.5 ? 1 : (0.15 + depth * 1.7).toFixed(2);   // a metade da frente fica opaca, para os de trás não aparecerem através
        el.style.zIndex = Math.round(depth * 100);
      });
    }
    const loop = () => { turn += 0.0035; draw(); raf = visible ? requestAnimationFrame(loop) : 0; };
    draw();
    if (!reduce) new IntersectionObserver(es => { visible = es[0].isIntersecting; if (visible && !raf) raf = requestAnimationFrame(loop); }).observe(globe);
    addEventListener('resize', draw, { passive: true });
  }

  // ---------- a ligação (cartão "Ligue para um Bot"): o relógio anda e as falas se alternam ----------
  const call = document.querySelector('.call');
  if (call) {
    const lines = [
      ['bot', 'Contas da casa', 'Achei a conta de luz: R$ 236,40, vence hoje. Pago agora?'],
      ['me', 'Você', 'Pode pagar.'],
      ['bot', 'Contas da casa', 'Pago. Deixo o comprovante e um resumo no chat.'],
      ['me', 'Você', 'Valeu! E a de água?'],
      ['bot', 'Contas da casa', 'Vence só dia 28. Te aviso dois dias antes.'],
    ];
    const line = call.querySelector('.call__line'), clock = call.querySelector('.call__time');
    let sec = 42, k = 0, visible = false;
    const say = () => { const [who, name, text] = lines[k % lines.length]; call.dataset.who = who; line.innerHTML = `<b>${name}</b>${text}`; line.style.animation = 'none'; void line.offsetWidth; line.style.animation = ''; k++; };
    say();
    new IntersectionObserver(es => { visible = es[0].isIntersecting; call.classList.toggle('is-live', visible && !reduce); }).observe(call);
    setInterval(() => { if (!visible) return; sec++; clock.textContent = `${String(Math.floor(sec / 60)).padStart(2, '0')}:${String(sec % 60).padStart(2, '0')}`; if (!reduce && sec % 4 === 0) say(); }, 1000);
  }

  // ---------- login de exemplo (cartão "Entra nos sites sem ver a senha"): na senha, o Bot tapa os olhos ----------
  document.querySelectorAll('.b-login').forEach(form => {
    const bot = () => form.querySelector('.b-login__bot .mascot');
    const pass = form.querySelector('[type="password"]'), btn = form.querySelector('button');
    pass.addEventListener('focus', () => bot().classList.add('is-shy'));
    pass.addEventListener('blur', () => bot().classList.remove('is-shy'));
    // É só um exemplo: nada sai da página. Os campos se limpam e o botão confirma.
    form.addEventListener('submit', e => {
      e.preventDefault();
      form.reset(); pass.blur(); bot().classList.remove('is-shy');
      btn.textContent = '✓ Entrou, e o Bot não viu';
      play(bot(), 'is-hopping');
      setTimeout(() => { btn.textContent = 'Continuar'; }, 2400);
    });
  });

  // ---------- uma função para cada Bot: a ficha escolhida troca a descrição ----------
  const job = document.getElementById('job');
  if (job) {
    const jobs = [
      ['Caixa de entrada', 'Lê, separa e responde seus e-mails, deixa rascunhos no seu tom e só envia com o seu clique.', [['Caixa zerada', '8h20'], ['4 rascunhos guardados para você revisar', '8h21'], ['Reunião confirmada com o cliente', '9h05']]],
      ['Viagens', 'Compara voos e hotéis no navegador dele, monta o roteiro e só reserva com a sua aprovação.', [['Comparou 40 voos para Lisboa', '10h12'], ['Roteiro de 5 dias pronto', '10h40'], ['Pede você para reservar o hotel', '10h41']]],
      ['Contas da casa', 'Acha as contas no seu e-mail, avisa o vencimento e pede a sua aprovação antes de pagar.', [['Conta de luz encontrada no e-mail', '8h02'], ['Pede sua aprovação para pagar', '8h03'], ['Recibos do mês guardados na pasta', '18h00']]],
      ['Loja online', 'Responde clientes, confere pedidos e avisa quando algo atrasa na entrega.', [['12 clientes respondidos', '9h30'], ['2 pedidos atrasados avisados', '9h42'], ['Estoque baixo de 3 produtos', '11h15']]],
      ['Estudos', 'Lê o material da aula, faz resumos e monta perguntas para revisar antes da prova.', [['Resumo do capítulo 5', '19h10'], ['10 perguntas com as respostas', '19h12'], ['Cronograma de revisão até sexta', '19h15']]],
      ['Saúde', 'Marca consultas, lembra dos remédios e organiza os exames num lugar só.', [['Consulta marcada para terça, 15h', '8h45'], ['Lembrete do remédio às 21h', 'diário'], ['Resultado do exame guardado', '14h20']]],
      ['Redes sociais', 'Escreve posts, junta os destaques da semana e deixa tudo pronto para você aprovar.', [['Resumo da semana em rascunho', 'seg 9h'], ['3 ideias de post para quinta', 'qua 17h'], ['Respostas aos comentários', 'diário']]],
      ['Código', 'Lê o repositório, corrige bugs, roda os testes e abre o pull request para você revisar.', [['Corrigiu o erro do login', '14h10'], ['Testes passando', '14h18'], ['Pull request aberto para revisão', '14h20']]],
    ];
    // O cartão mostra o Bot trabalhando: cada passo aparece girando, vira um ✓ e chama o próximo. O que precisa de
    // você ("Pede você…") fica amarelo, esperando. Quem pede menos movimento vê tudo pronto de uma vez.
    const chips = [...document.querySelectorAll('[data-job]')];
    const hues = Object.fromEntries(chips.map(c => [c.dataset.job, c.querySelector('[data-mascot]').outerHTML]));
    let timers = [];
    function run(i) {
      timers.forEach(clearTimeout); timers = [];
      const [t, d, rows] = jobs[i];
      job.innerHTML = `<div class="job__head">${hues[i]}<h3>${t}</h3><small class="job__state">Trabalhando…</small></div><p>${d}</p><ul>${rows.map(([a, b]) => `<li data-step="${/^pede/i.test(a) ? 'ask' : 'done'}"><i aria-hidden="true"></i>${a}<span>${b}</span></li>`).join('')}</ul>`;
      paint(job);
      const items = [...job.querySelectorAll('li')], state = job.querySelector('.job__state');
      const finish = () => {
        const asks = items.some(li => li.dataset.step === 'ask');
        state.textContent = asks ? 'Esperando você' : 'Pronto';
        state.classList.add('is-swapped');
        state.dataset.tone = asks ? 'wait' : 'go';
      };
      if (reduce) { items.forEach(li => li.classList.add('is-in', 'is-done')); finish(); return; }
      items.forEach((li, n) => {
        timers.push(setTimeout(() => li.classList.add('is-in'), 500 + n * 1300));
        timers.push(setTimeout(() => li.classList.add('is-done'), 500 + n * 1300 + 1000));
      });
      timers.push(setTimeout(finish, 500 + items.length * 1300));
    }
    chips.forEach(c => c.addEventListener('click', () => {
      chips.forEach(x => x.setAttribute('aria-selected', x === c));
      run(+c.dataset.job);
    }));
    // Começa quando o cartão aparece na tela, não antes.
    new IntersectionObserver((es, o) => { if (es[0].isIntersecting) { o.disconnect(); run(+(chips.find(c => c.getAttribute('aria-selected') === 'true') || chips[0]).dataset.job); } }, { threshold: 0.4 }).observe(job);
  }

  // ---------- roadmap: lê os itens do banco (os cartões gravados na página ficam de plano B), abas com a contagem,
  // a frase da aba, carregar mais de 9 em 9, ver detalhes e "Sugerir uma ideia" ----------
  const tabsBar = document.querySelector('.rm-tabs');
  const STAGES = { dev: 'Em desenvolvimento', soon: 'Pronto, chega em breve', next: 'Na fila', live: 'Já no app' };
  const escHTML = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  function cardHTML(it) {
    const stage = STAGES[it.stage] || it.stage;
    const dl = `<dt>Etapa</dt><dd>${stage}</dd>` + (it.category ? `<dt>Categoria</dt><dd>${escHTML(it.category)}</dd>` : '')
      + `<dt>Onde</dt><dd>${escHTML(it.platforms)}</dd>` + (it.version ? `<dt>Versão</dt><dd>${escHTML(it.version)}</dd>` : '');
    const inc = it.included?.length ? `<h3>O que está incluído</h3><ul>${it.included.map(x => `<li>${escHTML(x)}</li>`).join('')}</ul>` : '';
    return `<article class="rm-card" data-s="${escHTML(it.stage)}"><h3>${escHTML(it.title)}</h3><p>${escHTML(it.summary || it.body)}</p>`
      + `<span class="rm-card__foot"><span class="rm-card__stage"><span class="dot"></span>${stage}${it.category ? `<span class="rm-card__cat"> · ${escHTML(it.category)}</span>` : ''}</span><button type="button" class="rm-card__more">Ver detalhes</button></span>`
      + `<template><dl>${dl}</dl><div class="rm-dialog__text"><p>${escHTML(it.body || it.summary)}</p></div>${inc}</template></article>`;
  }
  async function loadFromDatabase() {
    const cfg = window.BOTS_SUPABASE;
    if (!cfg) return;
    try {
      const ctl = new AbortController(); setTimeout(() => ctl.abort(), 4000);
      const r = await fetch(`${cfg.url}/rest/v1/roadmap_items?select=*&order=position.asc`, { headers: { apikey: cfg.key }, signal: ctl.signal });
      if (!r.ok) return;
      const rows = await r.json();
      const order = ['dev', 'soon', 'next', 'live'];
      rows.sort((a, b) => order.indexOf(a.stage) - order.indexOf(b.stage) || a.position - b.position);
      if (rows.length) document.querySelector('.rm-grid').innerHTML = rows.map(cardHTML).join('');
    } catch { /* sem banco: ficam os cartões gravados na página */ }
  }
  function initRoadmap() {
    const PAGE = 9;
    const items = [...document.querySelectorAll('.rm-card')];
    const about = document.getElementById('rm-about'), more = document.getElementById('rm-more');
    const shown = document.getElementById('rm-shown'), moreBtn = more.querySelector('button');
    const counts = { all: items.length };
    items.forEach(c => counts[c.dataset.s] = (counts[c.dataset.s] || 0) + 1);
    const total = document.getElementById('rm-total');
    if (!total.dataset.counted) { total.dataset.counted = '1'; total.textContent = '0'; }   // na primeira vez conta do zero
    countUp(total, items.length, 1100);
    let filter = 'all', limit = PAGE;
    const tabs = [...tabsBar.querySelectorAll('button')];
    tabs.forEach(b => {
      const n = counts[b.dataset.s] || 0;
      countUp(b.querySelector('b'), n);
      b.disabled = !n;
      if (!n) b.setAttribute('aria-disabled', 'true'); else b.removeAttribute('aria-disabled');
    });
    function render() {
      const match = items.filter(c => filter === 'all' || c.dataset.s === filter);
      const visible = new Set(match.slice(0, limit));
      items.forEach(c => { if (!visible.has(c)) c.hidden = true; });
      match.slice(0, limit).forEach((c, k) => {
        // os cartões que acabaram de aparecer sobem em sequência
        const was = c.hidden; c.hidden = false;
        if (was) { c.classList.remove('is-new'); void c.offsetWidth; c.style.setProperty('--k', k % PAGE); c.classList.add('is-new'); }
      });
      tabs.forEach(b => b.setAttribute('aria-selected', b.dataset.s === filter));
      about.textContent = tabs.find(b => b.dataset.s === filter).dataset.about;
      shown.textContent = `Mostrando ${Math.min(limit, match.length)} de ${match.length}`;
      moreBtn.hidden = limit >= match.length;
      more.hidden = !match.length;
    }
    tabsBar.onclick = e => {
      const b = e.target.closest('button');
      if (!b || b.disabled) return;
      filter = b.dataset.s; limit = PAGE; render();
      history.replaceState(null, '', filter === 'all' ? location.pathname : `#${filter}`);
    };
    moreBtn.onclick = () => { limit += PAGE; render(); };
    const start = location.hash.slice(1);
    if (counts[start]) filter = start;
    items.forEach(c => c.hidden = true);   // assim os primeiros cartões também entram em sequência
    render();
  }
  if (tabsBar) {
    // Ver detalhes: a janela mostra a etapa, a categoria, onde, a versão e o texto inteiro do cartão.
    const dlg = document.getElementById('rm-dialog');
    document.querySelector('.rm-grid').addEventListener('click', e => {
      const c = e.target.closest('.rm-card');
      if (!c) return;
      dlg.querySelector('.rm-dialog__stage').innerHTML = c.querySelector('.rm-card__stage').innerHTML;
      dlg.querySelector('h2').textContent = c.querySelector('h3').textContent;
      dlg.querySelector('.rm-dialog__fill').replaceChildren(c.querySelector('template').content.cloneNode(true));
      dlg.showModal();
    });
    dlg.querySelector('.rm-dialog__close').addEventListener('click', () => dlg.close());
    dlg.addEventListener('click', e => { if (e.target === dlg) dlg.close(); });
    loadFromDatabase().then(initRoadmap);

    // Sugerir uma ideia: vai para a função roadmap-idea, que confere e guarda para o quadro de admin.
    const idea = document.getElementById('rm-idea');
    if (idea) {
      const form = idea.querySelector('form'), status = idea.querySelector('.rm-idea__status'), send = form.querySelector('[type=submit]');
      document.querySelectorAll('[data-open-idea]').forEach(b => b.addEventListener('click', () => { status.textContent = ''; idea.showModal(); }));
      idea.querySelector('.rm-dialog__close').addEventListener('click', () => idea.close());
      idea.addEventListener('click', e => { if (e.target === idea) idea.close(); });
      form.addEventListener('submit', async e => {
        e.preventDefault();
        const cfg = window.BOTS_SUPABASE, data = Object.fromEntries(new FormData(form));
        send.disabled = true; status.dataset.tone = ''; status.textContent = 'Enviando…';
        try {
          const r = await fetch(`${cfg.url}/functions/v1/roadmap-idea`, { method: 'POST', headers: { 'content-type': 'application/json', apikey: cfg.key }, body: JSON.stringify(data) });
          const out = await r.json().catch(() => ({}));
          if (!r.ok) throw new Error(out.error || 'Não deu para enviar agora. Tente de novo.');
          form.reset(); status.dataset.tone = 'ok'; status.textContent = 'Recebido. Obrigado! Toda ideia é lida.';
        } catch (err) {
          status.dataset.tone = 'erro'; status.textContent = err.message === 'Failed to fetch' ? 'Sem conexão com o servidor. Tente de novo.' : err.message;
        } finally { send.disabled = false; }
      });
    }
  }
})();
