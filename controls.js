'use strict';

(function buildPaxinbotControls() {
  let sequence = 0;
  const instances = new WeakMap();

  function directLabel(control, fallback) {
    const explicit = control.getAttribute('aria-label');
    if (explicit) return explicit;
    const label = control.closest('label');
    const text = label ? [...label.childNodes].filter(node => node.nodeType === Node.TEXT_NODE).map(node => node.textContent.trim()).filter(Boolean).join(' ') : '';
    return text || fallback;
  }

  function icon(symbol) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('aria-hidden', 'true');
    const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
    use.setAttribute('href', `#${symbol}`); svg.append(use); return svg;
  }

  function emit(control) {
    control.dispatchEvent(new Event('input', { bubbles:true }));
    control.dispatchEvent(new Event('change', { bubbles:true }));
  }

  function invalidFeedback(control, trigger, label) {
    control.addEventListener('invalid', event => {
      event.preventDefault(); trigger.classList.add('is-invalid'); trigger.setAttribute('aria-invalid', 'true'); trigger.focus();
      window.showToast?.(`Preencha o campo ${label.toLocaleLowerCase('pt-BR')}.`);
    });
  }

  function positionPopover(root, panel) {
    root.classList.remove('is-upward'); panel.removeAttribute('style');
    if (window.matchMedia('(max-width: 520px)').matches) return;
    const trigger = root.firstElementChild.getBoundingClientRect();
    const width = root.classList.contains('paxin-calendar') ? Math.min(326, window.innerWidth - 24) : trigger.width;
    panel.style.position = 'fixed'; panel.style.width = `${width}px`;
    panel.style.left = `${Math.max(12, Math.min(trigger.left, window.innerWidth - width - 12))}px`;
    if (root.classList.contains('paxin-calendar')) {
      panel.style.top = '50%'; panel.style.bottom = 'auto'; panel.style.transform = 'translateY(-50%)'; panel.style.maxHeight = 'calc(100dvh - 24px)'; panel.style.overflowY = 'auto'; return;
    }
    const desiredHeight = panel.scrollHeight; const below = window.innerHeight - trigger.bottom - 12; const above = trigger.top - 12; const openBelow = below >= Math.min(desiredHeight, 260) || below >= above;
    panel.style.maxHeight = `${Math.max(180, openBelow ? below : above)}px`; panel.style.overflowY = desiredHeight > (openBelow ? below : above) ? 'auto' : 'visible';
    if (openBelow) { panel.style.top = `${trigger.bottom + 7}px`; panel.style.bottom = 'auto'; }
    else { panel.style.top = 'auto'; panel.style.bottom = `${window.innerHeight - trigger.top + 7}px`; }
  }

  function enhanceSelect(select) {
    if (instances.has(select)) return instances.get(select);
    const label = directLabel(select, 'Seleção'); const id = `paxin-select-${++sequence}`;
    const root = document.createElement('div'); root.className = 'paxin-select';
    const trigger = document.createElement('button'); trigger.type = 'button'; trigger.className = 'paxin-select-trigger'; trigger.setAttribute('aria-haspopup', 'listbox'); trigger.setAttribute('aria-expanded', 'false'); trigger.setAttribute('aria-controls', id);
    const value = document.createElement('span'); trigger.append(value, icon('i-chevron'));
    const menu = document.createElement('div'); menu.className = 'paxin-select-menu'; menu.id = id; menu.hidden = true; menu.setAttribute('role', 'listbox'); menu.setAttribute('aria-label', label);
    root.append(trigger, menu); select.after(root); select.classList.add('paxin-control-native'); select.tabIndex = -1; select.setAttribute('aria-hidden', 'true');

    function selectedOption() { return select.options[select.selectedIndex] || null; }
    function updateTrigger() {
      const selected = selectedOption(); value.textContent = selected?.textContent || 'Selecione'; trigger.disabled = select.disabled; trigger.setAttribute('aria-label', `${label}: ${value.textContent}`);
      trigger.classList.remove('is-invalid'); trigger.removeAttribute('aria-invalid');
      [...menu.children].forEach((item, index) => item.setAttribute('aria-selected', String(index === select.selectedIndex)));
    }
    function close(focus = false) { menu.hidden = true; menu.removeAttribute('style'); trigger.setAttribute('aria-expanded', 'false'); root.classList.remove('is-upward'); if (focus) trigger.focus(); }
    function choose(index) {
      const option = select.options[index]; if (!option || option.disabled) return;
      select.selectedIndex = index; updateTrigger(); close(true); emit(select);
    }
    function render() {
      menu.replaceChildren();
      [...select.options].forEach((option, index) => {
        const item = document.createElement('button'); item.type = 'button'; item.className = 'paxin-select-option'; item.setAttribute('role', 'option'); item.dataset.index = String(index); item.textContent = option.textContent; item.disabled = option.disabled;
        item.addEventListener('click', () => choose(index)); menu.append(item);
      });
      updateTrigger();
    }
    function open() {
      if (trigger.disabled) return; document.dispatchEvent(new CustomEvent('paxin-control-open', { detail:root })); menu.hidden = false; trigger.setAttribute('aria-expanded', 'true'); positionPopover(root, menu);
      (menu.querySelector('[aria-selected="true"]') || menu.querySelector('button:not(:disabled)'))?.focus();
    }
    trigger.addEventListener('click', () => menu.hidden ? open() : close(true));
    trigger.addEventListener('keydown', event => { if (['ArrowDown','ArrowUp','Enter',' '].includes(event.key)) { event.preventDefault(); open(); } });
    menu.addEventListener('keydown', event => {
      const options = [...menu.querySelectorAll('button:not(:disabled)')]; const current = options.indexOf(document.activeElement); let next = null;
      if (event.key === 'ArrowDown') next = options[(current + 1) % options.length];
      if (event.key === 'ArrowUp') next = options[(current - 1 + options.length) % options.length];
      if (event.key === 'Home') next = options[0]; if (event.key === 'End') next = options.at(-1);
      if (next) { event.preventDefault(); next.focus(); }
      if (event.key === 'Escape') { event.preventDefault(); close(true); }
      if (event.key === 'Tab') close(false);
    });
    root.addEventListener('click', event => event.stopPropagation()); select.addEventListener('change', updateTrigger);
    document.addEventListener('click', () => close(false));
    document.addEventListener('paxin-control-open', event => { if (event.detail !== root) close(false); });
    select.form?.addEventListener('reset', () => setTimeout(updateTrigger));
    invalidFeedback(select, trigger, label); render();
    const api = { refresh:render, close }; instances.set(select, api); return api;
  }

  const pad = value => String(value).padStart(2, '0');
  function parseLocal(value, hasTime) {
    const match = String(value || '').match(hasTime ? /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/ : /^(\d{4})-(\d{2})-(\d{2})$/);
    if (!match) return null;
    const date = new Date(Number(match[1]), Number(match[2]) - 1, Number(match[3]), Number(match[4] || 0), Number(match[5] || 0));
    return Number.isNaN(date.valueOf()) ? null : date;
  }
  function localValue(date, hasTime) {
    const day = `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
    return hasTime ? `${day}T${pad(date.getHours())}:${pad(date.getMinutes())}` : day;
  }
  function sameDay(left, right) { return left && right && left.getFullYear() === right.getFullYear() && left.getMonth() === right.getMonth() && left.getDate() === right.getDate(); }
  function dayStart(date) { return new Date(date.getFullYear(), date.getMonth(), date.getDate()).valueOf(); }

  function enhanceCalendar(input) {
    if (instances.has(input)) return instances.get(input);
    const hasTime = input.type === 'datetime-local'; const label = directLabel(input, hasTime ? 'Data e hora' : 'Data'); const id = `paxin-calendar-${++sequence}`;
    const root = document.createElement('div'); root.className = 'paxin-calendar';
    const trigger = document.createElement('button'); trigger.type = 'button'; trigger.className = 'paxin-calendar-trigger'; trigger.setAttribute('aria-haspopup', 'dialog'); trigger.setAttribute('aria-expanded', 'false'); trigger.setAttribute('aria-controls', id);
    const value = document.createElement('span'); trigger.append(value, icon('i-clock'));
    const panel = document.createElement('div'); panel.className = 'paxin-calendar-panel'; panel.id = id; panel.hidden = true; panel.setAttribute('role', 'dialog'); panel.setAttribute('aria-label', label);
    const head = document.createElement('div'); head.className = 'paxin-calendar-head';
    const previous = document.createElement('button'); previous.type = 'button'; previous.setAttribute('aria-label', 'Mês anterior'); previous.textContent = '‹';
    const title = document.createElement('strong'); title.setAttribute('aria-live', 'polite');
    const next = document.createElement('button'); next.type = 'button'; next.setAttribute('aria-label', 'Próximo mês'); next.textContent = '›'; head.append(previous, title, next);
    const week = document.createElement('div'); week.className = 'paxin-calendar-week'; week.setAttribute('aria-hidden', 'true'); ['S','T','Q','Q','S','S','D'].forEach(day => { const item = document.createElement('span'); item.textContent = day; week.append(item); });
    const grid = document.createElement('div'); grid.className = 'paxin-calendar-grid'; grid.setAttribute('role', 'grid');
    let hour = null; let minute = null; let time = null;
    if (hasTime) {
      time = document.createElement('div'); time.className = 'paxin-calendar-time';
      const hourLabel = document.createElement('label'); hourLabel.textContent = 'Hora'; hour = document.createElement('input'); hour.type = 'number'; hour.min = '0'; hour.max = '23'; hour.inputMode = 'numeric'; hourLabel.append(hour);
      const separator = document.createElement('span'); separator.textContent = ':';
      const minuteLabel = document.createElement('label'); minuteLabel.textContent = 'Minuto'; minute = document.createElement('input'); minute.type = 'number'; minute.min = '0'; minute.max = '59'; minute.step = '1'; minute.inputMode = 'numeric'; minuteLabel.append(minute); time.append(hourLabel, separator, minuteLabel);
    }
    const footer = document.createElement('div'); footer.className = 'paxin-calendar-footer';
    const clear = document.createElement('button'); clear.type = 'button'; clear.textContent = 'Limpar';
    const today = document.createElement('button'); today.type = 'button'; today.textContent = 'Hoje';
    const apply = document.createElement('button'); apply.type = 'button'; apply.className = 'is-primary'; apply.textContent = 'Aplicar'; footer.append(clear, today, apply);
    panel.append(head, week, grid); if (time) panel.append(time); panel.append(footer); root.append(trigger, panel); input.after(root); input.classList.add('paxin-control-native'); input.tabIndex = -1; input.setAttribute('aria-hidden', 'true');

    let selected = parseLocal(input.value, hasTime); let view = new Date((selected || new Date()).getFullYear(), (selected || new Date()).getMonth(), 1);
    function bounds() { return { min:parseLocal(input.min?.slice(0, hasTime ? 16 : 10), hasTime), max:parseLocal(input.max?.slice(0, hasTime ? 16 : 10), hasTime) }; }
    function updateTrigger() {
      const parsed = parseLocal(input.value, hasTime);
      value.textContent = parsed ? new Intl.DateTimeFormat('pt-BR', hasTime ? { dateStyle:'short', timeStyle:'short' } : { dateStyle:'short' }).format(parsed) : 'Selecionar';
      trigger.disabled = input.disabled; trigger.setAttribute('aria-label', `${label}: ${value.textContent}`); trigger.classList.remove('is-invalid'); trigger.removeAttribute('aria-invalid');
    }
    function render() {
      title.textContent = new Intl.DateTimeFormat('pt-BR', { month:'long', year:'numeric' }).format(view); grid.replaceChildren();
      const first = new Date(view.getFullYear(), view.getMonth(), 1); const offset = (first.getDay() + 6) % 7; const cursor = new Date(first); cursor.setDate(1 - offset); const limit = bounds(); const now = new Date();
      for (let index = 0; index < 42; index += 1) {
        const date = new Date(cursor); date.setDate(cursor.getDate() + index); const button = document.createElement('button'); button.type = 'button'; button.className = 'paxin-calendar-day'; button.setAttribute('role', 'gridcell'); button.dataset.date = localValue(date, false); button.textContent = String(date.getDate()); button.setAttribute('aria-label', new Intl.DateTimeFormat('pt-BR', { dateStyle:'full' }).format(date)); button.setAttribute('aria-selected', String(sameDay(date, selected)));
        button.classList.toggle('is-outside', date.getMonth() !== view.getMonth()); button.classList.toggle('is-today', sameDay(date, now));
        button.disabled = Boolean((limit.min && dayStart(date) < dayStart(limit.min)) || (limit.max && dayStart(date) > dayStart(limit.max)));
        button.addEventListener('click', () => { const previousTime = selected || new Date(); selected = new Date(date.getFullYear(), date.getMonth(), date.getDate(), previousTime.getHours(), previousTime.getMinutes()); view = new Date(date.getFullYear(), date.getMonth(), 1); render(); }); grid.append(button);
      }
      if (hasTime) { hour.value = pad((selected || new Date()).getHours()); minute.value = pad((selected || new Date()).getMinutes()); }
    }
    function close(focus = false) { panel.hidden = true; panel.removeAttribute('style'); trigger.setAttribute('aria-expanded', 'false'); root.classList.remove('is-upward'); if (focus) trigger.focus(); }
    function open() {
      document.dispatchEvent(new CustomEvent('paxin-control-open', { detail:root })); selected = parseLocal(input.value, hasTime) || new Date(); view = new Date(selected.getFullYear(), selected.getMonth(), 1); render(); panel.hidden = false; trigger.setAttribute('aria-expanded', 'true'); positionPopover(root, panel);
      setTimeout(() => (grid.querySelector('[aria-selected="true"]') || grid.querySelector('.is-today') || grid.querySelector('button:not(:disabled)'))?.focus());
    }
    function focusDate(date) { view = new Date(date.getFullYear(), date.getMonth(), 1); render(); setTimeout(() => grid.querySelector(`[data-date="${localValue(date, false)}"]`)?.focus()); }
    trigger.addEventListener('click', () => panel.hidden ? open() : close(true));
    trigger.addEventListener('keydown', event => { if (['ArrowDown','Enter',' '].includes(event.key)) { event.preventDefault(); open(); } });
    previous.addEventListener('click', () => { view = new Date(view.getFullYear(), view.getMonth() - 1, 1); render(); }); next.addEventListener('click', () => { view = new Date(view.getFullYear(), view.getMonth() + 1, 1); render(); });
    grid.addEventListener('keydown', event => { const current = parseLocal(document.activeElement?.dataset?.date, false); if (!current) return; const movement = { ArrowLeft:-1, ArrowRight:1, ArrowUp:-7, ArrowDown:7 }[event.key]; if (movement) { event.preventDefault(); current.setDate(current.getDate() + movement); focusDate(current); } if (event.key === 'PageUp' || event.key === 'PageDown') { event.preventDefault(); current.setMonth(current.getMonth() + (event.key === 'PageUp' ? -1 : 1)); focusDate(current); } if (event.key === 'Escape') { event.preventDefault(); close(true); } });
    clear.addEventListener('click', () => { input.value = ''; selected = null; updateTrigger(); emit(input); close(true); });
    today.addEventListener('click', () => { selected = new Date(); view = new Date(selected.getFullYear(), selected.getMonth(), 1); render(); });
    apply.addEventListener('click', () => { selected ||= new Date(); if (hasTime) selected.setHours(Math.min(23, Math.max(0, Number(hour.value) || 0)), Math.min(59, Math.max(0, Number(minute.value) || 0)), 0, 0); input.value = localValue(selected, hasTime); updateTrigger(); emit(input); close(true); });
    panel.addEventListener('click', event => event.stopPropagation()); root.addEventListener('click', event => event.stopPropagation()); input.addEventListener('change', updateTrigger);
    document.addEventListener('click', () => close(false)); document.addEventListener('paxin-control-open', event => { if (event.detail !== root) close(false); });
    document.addEventListener('keydown', event => { if (event.key === 'Escape' && !panel.hidden) close(true); }); input.form?.addEventListener('reset', () => setTimeout(() => { selected = parseLocal(input.value, hasTime); updateTrigger(); }));
    invalidFeedback(input, trigger, label); updateTrigger();
    const api = { refresh() { selected = parseLocal(input.value, hasTime); view = new Date((selected || new Date()).getFullYear(), (selected || new Date()).getMonth(), 1); updateTrigger(); if (!panel.hidden) render(); }, close }; instances.set(input, api); return api;
  }

  function enhance(root = document) {
    root.querySelectorAll('select:not([data-native-control])').forEach(enhanceSelect);
    root.querySelectorAll('input[type="date"]:not([data-native-control]),input[type="datetime-local"]:not([data-native-control])').forEach(enhanceCalendar);
  }
  function refresh(root = document) { root.querySelectorAll('select,input[type="date"],input[type="datetime-local"]').forEach(control => instances.get(control)?.refresh()); }

  window.PaxinbotControls = { enhance, refresh };
  enhance();
})();
