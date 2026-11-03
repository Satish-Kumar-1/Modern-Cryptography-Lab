const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom'); // Optional developer-only DOM dependency.
const html = fs.readFileSync(path.join(__dirname,'index.html'),'utf8');
const app = fs.readFileSync(path.join(__dirname,'app.js'),'utf8');
const apiSource = fs.readFileSync(path.join(__dirname,'api.js'),'utf8');
const pair = name => ({name,publicKey:'public-' + name,privateKey:'private-' + name,trusted:true});
const message = (senderId,receiverId,body='Hello') => ({senderId,receiverId,message:body,signature:'example-signature'});
function boot(overrides={}) {
  const dom = new JSDOM(html,{url:'https://signedchat.test/',runScripts:'outside-only'});
  const {window} = dom; window.scrollTo = () => {};
  window.eval(apiSource);
  const records = {sent:[],copied:[],created:[]};
  Object.defineProperty(window.navigator,'clipboard',{value:{writeText:async text => records.copied.push(text)}});
  const api = {
    getUserKeys: async name => { if (name === 'missing') throw Object.assign(new Error('Not found'),{status:404}); return pair(name); },
    createUser: async data => { records.created.push(data); return pair(data.name); },
    listUsers: async () => ['Alice','Bob','Mallory'].map(name => pair(name)),
    getInbox: async name => name === 'Alice' ? [message('Bob','Alice','First'),message('Mallory','Alice','Second')] : [],
    send: async data => { records.sent.push(data); return {delivered:true}; },
    ...overrides
  };
  window.SignedChat.createApi = () => api; window.eval(app);
  const $ = selector => window.document.querySelector(selector);
  const submit = selector => $(selector).dispatchEvent(new window.Event('submit',{bubbles:true,cancelable:true}));
  const flush = async () => { for (let i=0;i<8;i++) await new Promise(resolve => setImmediate(resolve)); };
  const login = async (name='Alice') => { $('#login-name').value=name; submit('#login-form'); await flush(); };
  const enter = async () => { $('#continue-mail').click(); await flush(); };
  return {dom,window,$,submit,flush,login,enter,records};
}
test('home guards the workspace; existing user enters copyable key vault',async () => {
  const ui=boot();
  try {
    assert.equal(ui.$('#screen-home').hidden,false); assert.equal(ui.$('#screen-workspace').hidden,true);
    await ui.login(); assert.equal(ui.$('#screen-vault').hidden,false);
    assert.equal(ui.$('#vault-name').textContent,'Alice');
    assert.equal(ui.$('#vault-private').value,'private-Alice');
    ui.$('[data-copy="vault-private"]').click(); await ui.flush();
    assert.deepEqual(ui.records.copied,['private-Alice']);
    assert.equal(ui.window.localStorage.length,0); assert.equal(ui.window.sessionStorage.length,0);
  } finally { ui.dom.window.close(); }
});
test('unknown user routes to creation and creates through API before vault',async () => {
  const ui=boot();
  try {
    await ui.login('missing'); assert.equal(ui.$('#screen-create').hidden,false);
    assert.equal(ui.$('#create-name').value,'missing'); assert.equal(ui.$('#screen-vault').hidden,true);
    ui.$('#create-name').value='Carol'; ui.submit('#create-form'); await ui.flush();
    assert.equal(ui.records.created[0].name,'Carol');
    assert.equal(ui.$('#screen-vault').hidden,false); assert.equal(ui.$('#vault-name').textContent,'Carol');
  } finally { ui.dom.window.close(); }
});
test('network errors do not route to user creation; duplicate creation returns home',async () => {
  let failure = Object.assign(new Error('Backend offline'),{status:0});
  const ui=boot({getUserKeys:async () => {throw failure;},createUser:async () => {throw Object.assign(new Error('Duplicate'),{status:409});}});
  try {
    await ui.login(); assert.equal(ui.$('#screen-home').hidden,false); assert.equal(ui.$('#screen-create').hidden,true);
    assert.match(ui.$('#login-notice').textContent,/offline/);
    failure=Object.assign(new Error('Not found'),{status:404}); await ui.login('new');
    ui.submit('#create-form'); await ui.flush(); assert.equal(ui.$('#screen-home').hidden,false);
    assert.match(ui.$('#login-notice').textContent,/registered/);
  } finally { ui.dom.window.close(); }
});
test('mail inbox contains every sender and search/reply/compose use current identity',async () => {
  const ui=boot();
  try {
    await ui.login(); await ui.enter();
    assert.equal(ui.$('#vault-private').value,''); assert.equal(ui.$('#vault-public').value,'');
    assert.equal(ui.$('#screen-workspace').hidden,false);
    assert.equal(ui.window.document.querySelectorAll('.mail-row').length,2);
    ui.$('#inbox-search').value='Mallory'; ui.$('#inbox-search').dispatchEvent(new ui.window.Event('input'));
    assert.equal(ui.window.document.querySelectorAll('.mail-row').length,1);
    ui.$('.mail-row').click(); assert.match(ui.$('#mail-reader').textContent,/Second/);
    ui.$('#mail-reader .button').click(); assert.equal(ui.$('#view-compose').hidden,false);
    assert.equal(ui.$('#compose-to').textContent,'Mallory');
    assert.equal(ui.$('#compose-public-key').textContent,'public-Mallory');
    ui.$('#recipient-search').value='public-Bob'; ui.$('#recipient-search').dispatchEvent(new ui.window.Event('input'));
    assert.equal(ui.window.document.querySelectorAll('.recipient-row').length,1);
    ui.$('.recipient-row').click(); ui.$('#compose-content').value='  exact\ncontent  '; ui.submit('#compose-form'); await ui.flush();
    assert.equal(ui.records.sent[0].sender,'Alice'); assert.equal(ui.records.sent[0].recipient,'Bob');
    assert.equal(ui.records.sent[0].content,'  exact\ncontent  ');
  } finally { ui.dom.window.close(); }
});
test('logout clears keys, identity, received messages and drafts; reentry is isolated',async () => {
  const ui=boot();
  try {
    await ui.login(); await ui.enter(); ui.$('#compose-content').value='private draft';
    ui.$('#logout').click();
    assert.equal(ui.$('#screen-home').hidden,false); assert.equal(ui.$('#screen-workspace').hidden,true);
    assert.equal(ui.$('#logout').hidden,true); assert.equal(ui.$('#session-name').textContent,'');
    assert.equal(ui.$('#vault-private').value,''); assert.equal(ui.$('#compose-content').value,'');
    assert.equal(ui.$('#compose-public-key').textContent,''); assert.equal(ui.$('#compose-key-section').hidden,true);
    assert.equal(ui.$('#mail-list').childElementCount,0); assert.equal(ui.$('#recipient-results').childElementCount,0);
    await ui.login('Bob'); await ui.enter(); assert.equal(ui.$('#compose-from').textContent,'Bob');
    assert.equal(ui.window.document.querySelectorAll('.mail-row').length,0);
  } finally { ui.dom.window.close(); }
});
test('logout prevents a delayed key response from reopening a previous session',async () => {
  let release;
  const ui=boot({getUserKeys:async () => new Promise(resolve => { release=resolve; })});
  try {
    // Start normally, then exercise the persistent logout during a vault re-fetch.
    release=null; const pendingLogin=ui.login(); await ui.flush(); release(pair('Alice')); await pendingLogin;
    await ui.enter(); ui.$('#open-vault').click(); await ui.flush();
    ui.$('#logout').click(); release(pair('Alice')); await ui.flush();
    assert.equal(ui.$('#screen-home').hidden,false); assert.equal(ui.$('#vault-private').value,'');
    assert.equal(ui.$('#session-name').textContent,'');
  } finally { ui.dom.window.close(); }
});
test('logout prevents a delayed inbox response from repopulating the workspace',async () => {
  let release;
  const ui=boot({getInbox:async () => new Promise(resolve => {release=resolve;})});
  try {
    await ui.login(); ui.$('#continue-mail').click(); await ui.flush(); ui.$('#logout').click();
    release([message('Bob','Alice','stale secret')]); await ui.flush();
    assert.equal(ui.$('#screen-home').hidden,false); assert.equal(ui.$('#mail-list').childElementCount,0);
    assert.equal(ui.$('#mail-reader').textContent,'');
  } finally { ui.dom.window.close(); }
});
test('logout invalidates an in-flight math trace and clears disposable results',async () => {
  const ui=boot();
  try {
    let release;
    ui.window.requestAnimationFrame = callback => setImmediate(callback);
    ui.window.SignedChatMath = {payload:() => 'example',hex:() => '00',traceSignature:async () => new Promise(resolve => {release=resolve;})};
    ui.window.eval(fs.readFileSync(path.join(__dirname,'math-ui.js'),'utf8'));
    await ui.login(); await ui.enter();
    ui.submit('#math-form'); await ui.flush();
    assert.equal(typeof release,'function'); ui.$('#logout').click(); release({}); await ui.flush();
    assert.equal(ui.$('#math-output').childElementCount,0); assert.equal(ui.$('#math-status').textContent,'');
    assert.equal(ui.$('#run-math').disabled,false);
  } finally { ui.dom.window.close(); }
});
test('workspace search finds username or full public key and immediately opens recipient compose',async () => {
  const ui=boot();
  try {
    await ui.login(); await ui.enter();
    const search=ui.$('#workspace-user-search');
    search.value='bob'; search.dispatchEvent(new ui.window.Event('input'));
    assert.equal(ui.$('#workspace-user-results').hidden,false);
    assert.equal(ui.window.document.querySelectorAll('#workspace-user-results .recipient-row').length,1);
    assert.equal(ui.$('#workspace-user-results .recipient-row').disabled,false);
    ui.$('#workspace-user-results .recipient-row').click();
    assert.equal(ui.$('#view-compose').hidden,false); assert.equal(ui.$('#view-inbox').hidden,true);
    assert.equal(ui.$('#compose-title').textContent,'Message to Bob');
    assert.equal(ui.$('#compose-to').textContent,'Bob');
    assert.equal(ui.$('#compose-public-key').textContent,'public-Bob');
    assert.equal(ui.$('#compose-key-section').hidden,false);
    assert.equal(ui.window.document.activeElement.id,'compose-content');
    assert.equal(ui.$('#workspace-user-results').hidden,true);
    ui.$('#copy-recipient-key').click(); await ui.flush(); assert.deepEqual(ui.records.copied,['public-Bob']);
    search.value='public-Mallory'; search.dispatchEvent(new ui.window.Event('input'));
    assert.equal(ui.window.document.querySelectorAll('#workspace-user-results .recipient-row').length,1);
    ui.$('#workspace-user-results .recipient-row').click();
    assert.equal(ui.$('#compose-public-key').textContent,'public-Mallory');
    search.value='not-registered'; search.dispatchEvent(new ui.window.Event('input'));
    assert.match(ui.$('#workspace-user-results').textContent,/No matching/);
    search.dispatchEvent(new ui.window.KeyboardEvent('keydown',{key:'Escape'}));
    assert.equal(ui.$('#workspace-user-results').hidden,true);
  } finally { ui.dom.window.close(); }
});
test('inbox reading pane has all senders, backend verification, signature, and honest missing time',async () => {
  const ui=boot();
  try {
    await ui.login(); await ui.enter(); ui.$('.mail-row').click();
    assert.match(ui.$('#mail-reader').textContent,/First/);
    assert.match(ui.$('#mail-reader').textContent,/Backend accepted/);
    assert.match(ui.$('#mail-reader .message-details').textContent,/example-signature/);
    assert.equal(ui.$('#mail-reader .message-time').textContent,'Not provided by server');
    assert.equal(ui.$('#mail-reader time'),null);
  } finally { ui.dom.window.close(); }
});
test('inbox renders valid server timestamps but never fabricates invalid timestamps',async () => {
  const ui=boot({getInbox:async () => [
    {...message('Bob','Alice'),timestamp:'2026-10-27T12:00:00Z'},
    {...message('Mallory','Alice'),timestamp:'invalid timestamp'}
  ]});
  try {
    await ui.login(); await ui.enter(); ui.$('.mail-row').click();
    assert.equal(ui.$('#mail-reader time').dateTime,'2026-10-27T12:00:00Z');
    ui.window.document.querySelectorAll('.mail-row')[1].click();
    assert.equal(ui.$('#mail-reader time'),null);
    assert.equal(ui.$('#mail-reader .message-time').textContent,'Not provided by server');
  } finally { ui.dom.window.close(); }
});
