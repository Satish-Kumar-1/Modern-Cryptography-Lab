/* Plain browser JavaScript. No dependencies or build step. */
(function (global) {
  'use strict';
  class ApiError extends Error {
    constructor(message, status, problem) { super(message); this.name = 'ApiError'; this.status = status; this.problem = problem; }
  }
  function createApi(baseUrl = '', fetchImpl = (...args) => fetch(...args)) {
    async function request(path, init = {}, acceptedStatuses = []) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 75000);
      try {
        const response = await fetchImpl(`${baseUrl.replace(/\/$/, '')}/api${path}`, {
          ...init, signal: controller.signal,
          headers: { Accept: 'application/json', ...(init.body ? { 'Content-Type': 'application/json' } : {}), ...init.headers }
        });
        const raw = await response.text();
        let body;
        try { body = raw ? JSON.parse(raw) : undefined; }
        catch { throw new ApiError('The server returned an unreadable response. Check the API address.', response.status); }
        if (!response.ok && !acceptedStatuses.includes(response.status)) {
          throw new ApiError(body?.detail || body?.title || `Request failed (${response.status}).`, response.status, body);
        }
        return body;
      } catch (error) {
        if (error instanceof ApiError) throw error;
        throw new ApiError(controller.signal.aborted ? 'The backend took too long to respond. Try again.' : 'Cannot reach the backend. Check that it is running.', 0);
      } finally { clearTimeout(timeout); }
    }
    const post = body => ({ method: 'POST', body: JSON.stringify(body) });
    return {
      listUsers: () => request('/users'),
      getUser: name => request(`/users/${encodeURIComponent(name)}`),
      getUserKeys: name => request(`/users/${encodeURIComponent(name)}/keys`, { cache: 'no-store' }),
      createUser: body => request('/users', post(body)),
      getInbox: name => request(`/users/${encodeURIComponent(name)}/inbox`),
      sign: body => request('/messages/sign', post(body)),
      send: body => request('/messages', post(body), [422]),
      receive: (name, body) => request(`/users/${encodeURIComponent(name)}/inbox`, post(body), [422])
    };
  }
  function reconcileConversation(previous, incoming) {
    const counts = new Map();
    const identify = messages => messages.map(message => {
      const value = JSON.stringify(message);
      const count = counts.get(value) || 0;
      counts.set(value, count + 1);
      return { id: `${value}:${count}`, message };
    });
    const current = identify(incoming);
    counts.clear();
    const old = identify(previous);
    const remaining = new Map(current.map(entry => [entry.id, entry.message]));
    const ordered = [];
    for (const entry of old) {
      const message = remaining.get(entry.id);
      if (message) { ordered.push(message); remaining.delete(entry.id); }
    }
    return [...ordered, ...remaining.values()];
  }
  global.SignedChat = { ApiError, createApi, reconcileConversation };
})(globalThis);
