(async function () {
  const { ApiError, createApi, reconcileConversation } = globalThis.SignedChat;
  const cases = [];
  const test = (name, run) => cases.push({ name, run });
  const equal = (actual, expected) => { if (JSON.stringify(actual) !== JSON.stringify(expected)) throw new Error(`Expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`); };
  const message = (senderId, signature) => ({ message: 'hello', senderId, receiverId: senderId === 'Alice' ? 'Bob' : 'Alice', signature });
  test('User identities are encoded as one URL segment', async () => {
    let url; const api = createApi('http://localhost:8080/', async path => { url = path; return new Response('[]'); });
    await api.getInbox('Alice/Bob'); equal(url, 'http://localhost:8080/api/users/Alice%2FBob/inbox');
  });
  test('Demo key lookup encodes the username and bypasses browser caching', async () => {
    let url, options;
    const api = createApi('', async (path, request) => { url = path; options = request; return new Response('{"name":"Demo User","publicKey":"public-example","privateKey":"private-example"}'); });
    const pair = await api.getUserKeys('Demo User/#?');
    equal(url, '/api/users/Demo%20User%2F%23%3F/keys');
    equal(options.cache, 'no-store'); equal(pair.privateKey, 'private-example');
  });
  test('Unknown demo user lookup reports 404', async () => {
    const api = createApi('', async () => new Response('{"detail":"Unknown user"}', {status:404}));
    try { await api.getUserKeys('missing'); throw new Error('Expected failure'); }
    catch (error) { if (!(error instanceof ApiError)) throw error; equal(error.status, 404); }
  });
  test('Exact message content survives request encoding', async () => {
    const content = '  Hello\nBob 🔐 <script>alert(1)</script>  '; let sent;
    const api = createApi('', async (_, request) => { sent = JSON.parse(request.body); return new Response('{"delivered":true}'); });
    await api.send({ sender: 'Alice', recipient: 'Bob', content }); equal(sent.content, content);
  });
  test('HTTP 422 remains an explicit rejection result', async () => {
    const api = createApi('', async () => new Response('{"accepted":false}', { status: 422 }));
    equal(await api.receive('Bob', message('Alice', 'AA==')), { accepted: false });
  });
  test('Validation details are preserved', async () => {
    const api = createApi('', async () => new Response('{"detail":"Invalid name","errors":{"name":"blank"}}', { status: 400 }));
    try { await api.createUser({ name: '' }); throw new Error('Expected rejection'); }
    catch (error) { if (!(error instanceof ApiError)) throw error; equal(error.status, 400); equal(error.problem.errors, { name: 'blank' }); }
  });
  test('Network errors report connection failure', async () => {
    const api = createApi('', async () => { throw new TypeError('offline'); });
    try { await api.listUsers(); throw new Error('Expected failure'); }
    catch (error) { if (!(error instanceof ApiError)) throw error; equal(error.status, 0); }
  });
  test('Unexpected HTML is rejected', async () => {
    const api = createApi('', async () => new Response('<html>Bad gateway</html>', { status: 502 }));
    try { await api.listUsers(); throw new Error('Expected failure'); }
    catch (error) { if (!(error instanceof ApiError)) throw error; equal(error.status, 502); }
  });
  test('Observed order is preserved across both inboxes', () => {
    const first = message('Alice', '1'), reply = message('Bob', '2'); equal(reconcileConversation([first], [reply, first]), [first, reply]);
  });
  test('Replays remain visible; reset removes old messages', () => {
    const first = message('Alice', '1'); equal(reconcileConversation([first], [first, first]), [first, first]); equal(reconcileConversation([first], []), []);
  });
  let passed = 0;
  for (const { name, run } of cases) {
    const item = document.createElement('li');
    try { await run(); passed++; item.className = 'pass'; item.textContent = `PASS — ${name}`; }
    catch (error) { item.className = 'fail'; item.textContent = `FAIL — ${name}: ${error.message}`; }
    document.querySelector('#tests').append(item);
  }
  document.querySelector('#result').textContent = `${passed}/${cases.length} tests passed`;
})();
