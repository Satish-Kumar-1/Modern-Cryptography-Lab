(function () {
  'use strict';
  const {createApi, reconcileConversation} = window.SignedChat;
  const api = createApi(), $ = selector => document.querySelector(selector);
  // Session identity is memory-only and public-only. Private keys exist only in the vault fields.
  const state = {screen:'home', view:'inbox', user:null, users:[], inbox:[], selectedMessage:null,
    recipient:'', selected:['',''], messages:[], busy:false, connected:false, epoch:0};
  const panels = [], cache = new Map();
  const titles = {inbox:'Inbox', compose:'Compose / search', simulation:'User simulation', math:'Signing math'};
  function el(tag, cls, text) { const node = document.createElement(tag); if (cls) node.className = cls; if (text !== undefined) node.textContent = text; return node; }
  function notice(selector, kind, text) { const node = $(selector); node.className = 'notice ' + kind + (selector === '#workspace-notice' ? ' workspace-notice' : ''); node.textContent = text; node.hidden = !text; }
  function clearVault() { $('#vault-name').textContent = ''; $('#vault-public').value = ''; $('#vault-private').value = ''; $('#vault-trust').textContent = ''; notice('#vault-notice','',''); }
  function showScreen(screen) {
    if (screen !== 'vault') clearVault();
    state.screen = screen;
    ['home','create','vault','workspace'].forEach(name => { $('#screen-' + name).hidden = name !== screen; });
    const active = Boolean(state.user);
    $('#session-name').hidden = !active; $('#logout').hidden = !active;
    $('#open-vault').hidden = !active || screen === 'vault';
    $('#session-name').textContent = state.user?.name || '';
    const heading = $('#screen-' + screen).querySelector('h1');
    if (heading) { heading.tabIndex = -1; heading.focus({preventScroll:true}); }
    window.scrollTo({top:0});
    controls();
  }
  function showView(view) {
    if (!state.user || !titles[view]) return;
    state.view = view;
    $('.dashboard-view:not([hidden])')?.setAttribute('hidden','');
    Object.keys(titles).forEach(name => { $('#view-' + name).hidden = name !== view; });
    document.querySelectorAll('nav [data-view]').forEach(button => {
      const active = button.dataset.view === view;
      button.classList.toggle('nav-current', active); button.setAttribute('aria-pressed', active);
    });
    $('#section-label').textContent = titles[view].toUpperCase(); $('#workspace-title').textContent = titles[view];
    controls();
  }
  function controls() {
    document.querySelectorAll('[data-lock]').forEach(node => { node.disabled = state.busy; });
    ['#login-name','#create-name','#select-left','#select-right'].forEach(selector => { $(selector).disabled = state.busy; });
    $('#open-vault').disabled = state.busy;
    $('#compose-content').disabled = state.busy;
    document.querySelectorAll('[data-view]').forEach(button => { button.disabled = state.busy; });
    document.querySelectorAll('.recipient-row').forEach(button => { button.disabled = state.busy; });
    $('#send-mail').disabled = state.busy || !state.user || !state.recipient || !$('#compose-content').value.trim();
    panels.forEach((entry,i) => {
      const allowed = Boolean(state.user && state.selected[i] && state.selected[1-i] && state.selected[i] !== state.selected[1-i]);
      entry.textarea.disabled = state.busy || !allowed;
      entry.panel.querySelector('.send-button').disabled = state.busy || !allowed || !entry.textarea.value.trim();
    });
  }
  async function run(operation, feedback = '#workspace-notice') {
    if (state.busy) return;
    const epoch = state.epoch, current = () => epoch === state.epoch;
    state.busy = true; controls(); notice(feedback,'','');
    try { await operation(current); }
    catch (error) { if (current()) notice(feedback,'error',error.message); }
    finally { if (current()) { state.busy = false; controls(); } }
  }
  function enterVault(pair) {
    if (!pair.name || !pair.publicKey || !pair.privateKey) throw new Error('The backend did not return a complete demo key pair.');
    state.user = {name:pair.name, publicKey:pair.publicKey, trusted:pair.trusted};
    showScreen('vault');
    $('#vault-name').textContent = pair.name; $('#vault-public').value = pair.publicKey; $('#vault-private').value = pair.privateKey;
    $('#vault-trust').textContent = pair.trusted ? 'Server-trusted key' : 'Untrusted key';
  }
  function logout() {
    // Invalidate in-flight callbacks before clearing any displayed state.
    state.epoch++; state.busy = false; state.user = null; state.users = []; state.inbox = [];
    state.selectedMessage = null; state.recipient = ''; state.selected = ['','']; state.messages = [];
    state.connected = false; state.view = 'inbox'; cache.clear();
    clearVault();
    document.querySelectorAll('input,textarea').forEach(node => { node.value = ''; });
    document.querySelectorAll('.notice').forEach(node => { node.textContent = ''; node.hidden = true; });
    $('#mail-list').replaceChildren(); $('#mail-reader').replaceChildren(); $('#recipient-results').replaceChildren();
    $('#workspace-user-results').replaceChildren(); $('#workspace-user-results').hidden = true;
    $('#compose-public-key').textContent = ''; $('#compose-key-section').hidden = true;
    $('#compose-title').textContent = 'New signed message'; $('#copy-recipient-key').textContent = 'Copy public key';
    $('#compose-from').textContent = ''; $('#compose-to').textContent = 'Select a recipient'; $('#inbox-count').textContent = '0';
    $('#connection-status').textContent = 'Not refreshed'; $('#connection-status').className = 'connection-status';
    panels.forEach(entry => { entry.log.replaceChildren(); entry.version = null; entry.panel.querySelector('h2').textContent = ''; entry.panel.querySelector('.peer-label').textContent = ''; entry.panel.querySelector('.initial').textContent = ''; entry.panel.querySelector('.trust-strip').textContent = ''; });
    ['#select-left','#select-right'].forEach(selector => $(selector).replaceChildren());
    document.querySelectorAll('[data-copy]').forEach(button => { button.textContent = 'Copy'; });
    window.dispatchEvent(new Event('signedchat:logout'));
    showScreen('home'); $('#login-name').focus();
  }
  $('#login-form').addEventListener('submit', event => {
    event.preventDefault(); const name = $('#login-name').value.trim();
    if (!name) { notice('#login-notice','error','Enter a username.'); return; }
    void run(async current => {
      try {
        const pair = await api.getUserKeys(name);
        if (current()) enterVault(pair);
      } catch (error) {
        if (!current()) return;
        if (error.status === 404) { $('#create-name').value = name; notice('#create-notice','',''); showScreen('create'); }
        else throw error;
      }
    }, '#login-notice');
  });
  $('#create-form').addEventListener('submit', event => {
    event.preventDefault(); const name = $('#create-name').value.trim();
    if (!name) { notice('#create-notice','error','Enter a nonblank username.'); return; }
    void run(async current => {
      try { const pair = await api.createUser({name,trusted:true}); if (current()) enterVault(pair); }
      catch (error) {
        if (!current()) return;
        if (error.status === 409) {
          $('#login-name').value = name; showScreen('home');
          notice('#login-notice','error','That username was just registered. Continue to open its existing demo identity.');
        } else throw error;
      }
    }, '#create-notice');
  });
  $('#back-home').addEventListener('click', () => { if (!state.busy) { $('#login-name').value = $('#create-name').value; showScreen('home'); } });
  $('#logout').addEventListener('click', logout);
  $('.brand').addEventListener('click', event => { event.preventDefault(); if (!state.user) showScreen('home'); });
  $('#open-vault').addEventListener('click', () => {
    if (!state.user) return;
    const name = state.user.name;
    void run(async current => { const pair = await api.getUserKeys(name); if (current()) enterVault(pair); });
  });
  document.querySelectorAll('[data-copy]').forEach(button => button.addEventListener('click', async () => {
    const epoch = state.epoch;
    try {
      await navigator.clipboard.writeText($('#' + button.dataset.copy).value);
      if (epoch === state.epoch && state.screen === 'vault') { button.textContent = 'Copied'; notice('#vault-notice','success','Copied to clipboard. Store private keys securely.'); }
    } catch { if (epoch === state.epoch) notice('#vault-notice','error','Clipboard unavailable. Select the key text and copy it manually.'); }
  }));
  function empty(title, text) {
    const node = el('div','empty-state'); node.append(el('span','empty-icon','▤'),el('h3','',title),el('p','',text)); return node;
  }
  function signatureDetails(message) {
    const details = el('details','message-details'); details.append(el('summary','','Inspect Ed25519 signature & signed package'));
    const content = el('div','detail-content'), list = el('dl');
    [['Sender',message.senderId],['Recipient',message.receiverId],['Ed25519 signature · Base64',message.signature]].forEach(([name,value]) => list.append(el('dt','',name),el('dd','',value)));
    const actions = el('div','reader-actions'), copy = el('button','text-button','Copy signed package'), trace = el('button','text-button','Trace payload in math lab →');
    copy.type = trace.type = 'button';
    copy.addEventListener('click', async () => {
      const epoch = state.epoch;
      try { await navigator.clipboard.writeText(JSON.stringify(message,null,2)); if (epoch === state.epoch) copy.textContent = 'Copied JSON'; }
      catch { if (epoch === state.epoch) copy.textContent = 'Clipboard unavailable; select the signature manually.'; }
    });
    trace.addEventListener('click', () => {
      $('#math-sender').value = message.senderId; $('#math-recipient').value = message.receiverId; $('#math-message').value = message.message;
      showView('math'); $('#run-math').focus();
    });
    actions.append(copy,trace); content.append(list,actions); details.append(content); return details;
  }
  function timestampNode(message) {
    // No client clock fallback: the current API does not supply a timestamp.
    const value = message.timestamp;
    if (typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(value) && Number.isFinite(Date.parse(value))) {
      const time = el('time','message-time',new Date(value).toLocaleString()); time.dateTime = value; return time;
    }
    return el('span','message-time unavailable-time','Not provided by server');
  }
  function selectRecipient(name) {
    if (state.busy || !state.user || !state.users.some(user => user.name === name)) return;
    state.recipient = name;
    $('#workspace-user-search').value = ''; $('#workspace-user-results').hidden = true;
    notice('#compose-notice','','');
    renderRecipients(); showView('compose'); $('#compose-content').focus();
  }
  function matchingUsers(query) {
    const filter = query.toLocaleLowerCase().trim(), keyFilter = filter.replace(/\s/g,'');
    return state.users.filter(user => !filter || user.name.toLocaleLowerCase().includes(filter) || user.publicKey.toLocaleLowerCase().includes(keyFilter));
  }
  function recipientButton(user) {
    const button = el('button','recipient-row' + (state.recipient === user.name ? ' selected' : '')); button.type = 'button';
    button.disabled = state.busy;
    button.setAttribute('aria-pressed',String(state.recipient === user.name));
    button.append(el('strong','',user.name),el('code','',user.publicKey.slice(0,18) + '…' + user.publicKey.slice(-12)));
    button.addEventListener('click',() => selectRecipient(user.name));
    return button;
  }
  function renderUserSearch() {
    const query = $('#workspace-user-search').value.trim(), results = $('#workspace-user-results');
    results.replaceChildren(); results.hidden = !query || !state.user;
    if (results.hidden) return;
    const matches = matchingUsers(query);
    matches.forEach(user => results.append(recipientButton(user)));
    if (!matches.length) results.append(el('p','hint','No matching registered users.'));
  }
  function renderInbox() {
    $('#inbox-count').textContent = state.inbox.length;
    const filter = $('#inbox-search').value.toLocaleLowerCase();
    const rows = state.inbox.map((message,index) => ({message,index})).filter(({message}) => (message.senderId + '\n' + message.message).toLocaleLowerCase().includes(filter));
    $('#inbox-summary').textContent = rows.length + ' of ' + state.inbox.length + ' received messages';
    if (state.selectedMessage !== null && !rows.some(row => row.index === state.selectedMessage)) state.selectedMessage = null;
    const list = $('#mail-list'); list.replaceChildren();
    rows.forEach(({message,index}) => {
      const item = el('div','mail-list-item'); item.setAttribute('role','listitem');
      const button = el('button','mail-row' + (state.selectedMessage === index ? ' selected' : '')); button.type = 'button';
      button.setAttribute('aria-pressed', String(state.selectedMessage === index));
      button.append(el('strong','',message.senderId),el('p','',message.message),el('span','','✓ Accepted by backend'));
      button.addEventListener('click', () => { state.selectedMessage = index; renderInbox(); });
      item.append(button); list.append(item);
    });
    if (!rows.length) list.append(empty(filter ? 'No matching mail' : 'Your inbox is empty',filter ? 'Try a different sender or message.' : 'Messages from every sender will appear here after delivery.'));
    const reader = $('#mail-reader'); reader.replaceChildren();
    const message = state.inbox[state.selectedMessage];
    if (!message) { reader.append(empty('Select a signed message','Open a message to read its content and inspect its signature.')); return; }
    const heading = el('div','reader-title'); heading.append(el('h2','','Signed message'),el('span','verification-pill','✓ Backend accepted'));
    const meta = el('div','reader-meta');
    [['FROM',message.senderId],['TO',message.receiverId]].forEach(([label,value]) => { const row = el('p'); row.append(el('b','',label),el('span','',value)); meta.append(row); });
    const timeRow = el('p'); timeRow.append(el('b','','TIME'),timestampNode(message)); meta.append(timeRow);
    const actions = el('div','reader-actions'), reply = el('button','button button-outline','Reply →');
    reply.type = 'button'; reply.addEventListener('click', () => { if (state.busy) return; $('#compose-content').value = ''; selectRecipient(message.senderId); });
    actions.append(reply);
    reader.append(heading,meta,el('div','message-body',message.message),signatureDetails(message),actions);
  }
  function renderRecipients() {
    $('#compose-from').textContent = state.user?.name || '';
    if (!state.users.some(user => user.name === state.recipient)) state.recipient = '';
    $('#compose-to').textContent = state.recipient || 'Select a recipient';
    const recipient = state.users.find(user => user.name === state.recipient);
    $('#compose-title').textContent = recipient ? 'Message to ' + recipient.name : 'New signed message';
    $('#compose-public-key').textContent = recipient?.publicKey || '';
    $('#compose-key-section').hidden = !recipient;
    $('#copy-recipient-key').textContent = 'Copy public key';
    const matches = matchingUsers($('#recipient-search').value);
    const results = $('#recipient-results'); results.replaceChildren();
    matches.forEach(user => {
      results.append(recipientButton(user));
    });
    if (!matches.length) results.append(el('p','hint','No matching registered users. Create another identity through the Home screen.'));
    controls();
  }
  function renderSimulation() {
    ['#select-left','#select-right'].forEach((selector,i) => {
      const select = $(selector); select.replaceChildren(new Option('Choose a user',''));
      state.users.forEach(user => { const option = new Option(user.name,user.name); option.disabled = user.name === state.selected[1-i]; select.add(option); });
      select.value = state.selected[i];
    });
    document.querySelectorAll('[data-tab]').forEach(button => { button.textContent = state.selected[Number(button.dataset.tab)] || (button.dataset.tab === '0' ? 'Left user' : 'Right user'); });
    panels.forEach((entry,i) => {
      const name = state.selected[i], peer = state.selected[1-i], user = state.users.find(u => u.name === name);
      entry.panel.setAttribute('aria-label',(name || (i ? 'Right user' : 'Left user')) + "'s simulation");
      entry.panel.querySelector('h2').textContent = name || 'Choose a user';
      entry.panel.querySelector('.initial').textContent = name ? Array.from(name)[0] : '?';
      entry.panel.querySelector('.peer-label').textContent = peer ? 'To ' + peer : 'Choose another identity';
      entry.panel.querySelector('.trust-strip').textContent = user ? (user.trusted ? '✓ Server-trusted key' : 'Untrusted key — delivery will be rejected') : 'No identity selected';
      entry.textarea.placeholder = peer ? 'Message ' + peer + '…' : 'Choose a recipient…';
      entry.panel.querySelector('label').textContent = 'Message from ' + (name || 'left user') + ' to ' + (peer || 'right user');
      entry.panel.querySelector('.send-button').setAttribute('aria-label','Send from ' + (name || 'left user') + ' to ' + (peer || 'right user'));
      const messages = state.messages.filter(m => (m.senderId === name && m.receiverId === peer) || (m.senderId === peer && m.receiverId === name));
      const version = JSON.stringify([name,peer,messages]);
      if (version !== entry.version) {
        entry.version = version; entry.log.replaceChildren();
        messages.forEach(message => {
          const node = el('article','message ' + (message.senderId === name ? 'outgoing' : 'incoming'));
          node.append(el('div','message-sender',message.senderId),el('p','',message.message),el('div','verified','✓ Accepted by backend'),signatureDetails(message)); entry.log.append(node);
        });
        if (!messages.length) entry.log.append(empty('Start a signed exchange',name && peer ? 'Send from either identity to see both perspectives.' : 'Register a second identity through Home, then select it here.'));
        entry.log.scrollTop = entry.log.scrollHeight;
      }
    });
    controls();
  }
  async function loadWorkspace(current) {
    const name = state.user.name;
    const [users,inbox] = await Promise.all([api.listUsers(),api.getInbox(name)]);
    if (!current()) return;
    state.users = users.sort((a,b) => a.name.localeCompare(b.name)); state.inbox = inbox;
    state.selected = state.selected.map(value => users.some(user => user.name === value) ? value : '');
    if (!state.selected[0]) state.selected[0] = name;
    if (!state.selected[1]) state.selected[1] = users.find(user => user.name !== state.selected[0])?.name || '';
    if (state.view === 'simulation') {
      const pair = [...state.selected], inboxes = await Promise.all(pair.map(id => id ? api.getInbox(id) : []));
      if (!current()) return;
      const key = JSON.stringify([...pair].sort()); state.messages = reconcileConversation(cache.get(key) || [],inboxes.flat()); cache.set(key,state.messages);
    }
    state.connected = true; $('#connection-status').textContent = 'Backend connected'; $('#connection-status').className = 'connection-status connected';
    renderInbox(); renderRecipients(); renderSimulation(); renderUserSearch();
  }
  async function refresh(current) {
    try { await loadWorkspace(current); }
    catch (error) {
      if (!current()) return;
      state.connected = false; $('#connection-status').textContent = 'Refresh failed'; $('#connection-status').className = 'connection-status error';
      if (error.status === 404) throw new Error('This demo identity is no longer on the server. Log out and create it again; a server restart clears users.');
      throw error;
    }
  }
  $('#continue-mail').addEventListener('click', () => {
    if (!state.user) return;
    showScreen('workspace'); showView('inbox');
    void run(refresh);
  });
  $('#refresh').addEventListener('click', () => { if (state.user) void run(refresh); });
  document.querySelectorAll('[data-view]').forEach(button => button.addEventListener('click', () => {
    if (!state.user || state.busy) return;
    showView(button.dataset.view);
    if (state.view === 'simulation') void run(refresh);
  }));
  $('#inbox-search').addEventListener('input',renderInbox);
  $('#recipient-search').addEventListener('input',renderRecipients);
  $('#workspace-user-search').addEventListener('input',renderUserSearch);
  $('#workspace-user-search').addEventListener('keydown',event => { if (event.key === 'Escape') { $('#workspace-user-search').value = ''; renderUserSearch(); } });
  document.addEventListener('click',event => { if (!event.target.closest('.workspace-user-search')) $('#workspace-user-results').hidden = true; });
  $('#copy-recipient-key').addEventListener('click',async () => {
    const epoch = state.epoch, value = $('#compose-public-key').textContent;
    if (!value) return;
    try { await navigator.clipboard.writeText(value); if (epoch === state.epoch && value === $('#compose-public-key').textContent) $('#copy-recipient-key').textContent = 'Copied public key'; }
    catch { if (epoch === state.epoch) notice('#compose-notice','error','Clipboard unavailable. Select the public key and copy it manually.'); }
  });
  $('#compose-content').addEventListener('input',controls);
  $('#compose-form').addEventListener('submit', event => {
    event.preventDefault(); if (!state.user || !state.recipient || !$('#compose-content').value.trim()) return;
    const sender = state.user.name, recipient = state.recipient, content = $('#compose-content').value;
    void run(async current => {
      const result = await api.send({sender,recipient,content});
      if (!current()) return;
      if (!result.delivered) { notice('#compose-notice','error','The backend rejected this message. It was not delivered.'); return; }
      $('#compose-content').value = ''; notice('#compose-notice','success','Signed and delivered to ' + recipient + '.');
      try { await refresh(current); } catch { if (current()) notice('#compose-notice','success','Delivered. Refresh to synchronize your inbox.'); }
    },'#compose-notice');
  });
  async function sendSimulation(i) {
    const entry = panels[i], sender = state.selected[i], recipient = state.selected[1-i], content = entry.textarea.value;
    if (!state.user || !sender || !recipient || sender === recipient || !content.trim()) return;
    await run(async current => {
      const result = await api.send({sender,recipient,content});
      if (!current()) return;
      if (!result.delivered) { entry.note.textContent = 'Backend rejected delivery.'; entry.note.className = 'notice error'; entry.note.hidden = false; return; }
      entry.textarea.value = ''; entry.note.textContent = 'Signed and delivered.'; entry.note.className = 'notice success'; entry.note.hidden = false;
      try { await refresh(current); } catch { if (current()) notice('#workspace-notice','error','Message delivered. Refresh to synchronize the simulation.'); }
    });
  }
  [0,1].forEach(i => {
    const panel = $('#panel-template').content.firstElementChild.cloneNode(true); panel.classList.add(i ? 'bob' : 'alice');
    const textarea = panel.querySelector('textarea'); textarea.id = 'message-' + i; panel.querySelector('label').htmlFor = textarea.id;
    const entry = {panel,textarea,log:panel.querySelector('.messages'),note:panel.querySelector('.notice'),version:null}; panels.push(entry); $('#chat-grid').append(panel);
    textarea.addEventListener('input',controls);
    textarea.addEventListener('keydown',event => { if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) { event.preventDefault(); void sendSimulation(i); } });
    panel.querySelector('form').addEventListener('submit',event => { event.preventDefault(); void sendSimulation(i); });
    $(i ? '#select-right' : '#select-left').addEventListener('change',() => {
      state.selected[i] = $(i ? '#select-right' : '#select-left').value; state.messages = [];
      panels.forEach(item => { item.textarea.value = ''; item.note.hidden = true; });
      renderSimulation(); void run(refresh);
    });
  });
  document.querySelectorAll('[data-tab]').forEach(button => button.addEventListener('click',() => {
    $('#chat-grid').className = 'chat-grid ' + (button.dataset.tab === '0' ? 'show-alice' : 'show-bob');
    document.querySelectorAll('[data-tab]').forEach(tab => tab.setAttribute('aria-pressed',String(tab === button)));
  }));
  showScreen('home');
})();
