import { el } from './dom.js';
import { historyRecord } from './history_record.js';

let sdk, auth, db, user = null, startup;
const observers = new Set();
export const currentUser = () => user;
export function onAccountChange(callback) { observers.add(callback); }
export function accountError(error) {
  if (error instanceof TypeError) return 'Account services could not be reached. Check your connection and reload the page.';
  const messages = {
    'auth/invalid-credential': 'The email or password is incorrect.',
    'auth/invalid-email': 'Enter a valid email address.',
    'auth/email-already-in-use': 'An account with this email already exists. Try signing in.',
    'auth/weak-password': 'Use a stronger password with at least 6 characters.',
    'auth/password-does-not-meet-requirements': 'Use a stronger password with upper and lowercase letters, a number, and a symbol.',
    'auth/too-many-requests': 'Too many attempts. Please wait a moment and try again.',
    'auth/network-request-failed': 'Unable to connect. Check your connection and try again.',
    'auth/operation-not-allowed': 'Account sign-in is not enabled yet. Please try again later.',
    'permission-denied': 'Your history could not be accessed. Sign in again or contact the app owner.',
    'unavailable': 'History is temporarily unavailable. Your encryption still works; please retry saving.',
    'resource-exhausted': 'History has reached its service limit. Please try again later.',
  };
  return messages[error.code] || (error.code ? 'Something went wrong. Please try again.' : error.message);
}

async function connect() {
  const response = await fetch('/static/firebase-config.json', { cache: 'no-store' });
  if (!response.ok) throw new Error('Account services could not be loaded. Please try again.');
  const config = await response.json();
  if (!config.apiKey || !config.projectId || !config.appId) throw new Error('Account services are not connected yet. You can still use the cipher lab as a guest.');
  sdk = await import('./firebase.bundle.js');
  const app = sdk.initializeApp(config);
  auth = sdk.getAuth(app);
  db = sdk.getFirestore(app);
  await sdk.setPersistence(auth, sdk.browserSessionPersistence);
  await new Promise((resolve, reject) => {
    sdk.onAuthStateChanged(auth, (next) => {
      user = next;
      observers.forEach((callback) => callback(next));
      resolve();
    }, reject);
  });
}

function requireOwner(uid) {
  if (!uid || user?.uid !== uid) throw new Error('Sign in to save this encryption to your history.');
  return sdk.collection(db, 'users', uid, 'encryptions');
}

export async function saveEncryption(source, id, uid) {
  await startup;
  const collection = requireOwner(uid);
  const record = historyRecord(source);
  // The result's ID is reused for retry clicks. A second create cannot duplicate history.
  const ref = sdk.doc(collection, id);
  await sdk.runTransaction(db, async (transaction) => {
    const existing = await transaction.get(ref);
    if (existing.exists()) return;
    transaction.set(ref, {
      title: `${record.algorithm === 'rc4' ? 'RC4' : 'A5/1'} encryption`,
      createdAt: sdk.serverTimestamp(), record,
    });
  });
}

export function initAccount(state) {
  const form = document.getElementById('auth-form');
  const email = document.getElementById('auth-email');
  const password = document.getElementById('auth-password');
  const submit = document.getElementById('auth-submit');
  const reset = document.getElementById('auth-reset');
  const message = document.getElementById('auth-message');
  const signIn = document.getElementById('auth-login-mode');
  const create = document.getElementById('auth-create-mode');
  const status = document.getElementById('history-status');
  const list = document.getElementById('history-list');
  const more = document.getElementById('history-more');
  const refresh = document.getElementById('history-refresh');
  let creating = false, cursor = null, generation = 0, loading = false;

  function mode(value) {
    creating = value;
    signIn.setAttribute('aria-pressed', String(!value));
    create.setAttribute('aria-pressed', String(value));
    document.getElementById('auth-heading').textContent = value ? 'Start your notebook' : 'Welcome back';
    submit.textContent = value ? 'Create account' : 'Sign in';
    password.autocomplete = value ? 'new-password' : 'current-password';
    reset.hidden = value;
  }
  signIn.addEventListener('click', () => mode(false));
  create.addEventListener('click', () => mode(true));

  async function authAction(action) {
    submit.disabled = reset.disabled = true;
    message.textContent = 'Please wait…';
    try { await startup; await action(); }
    catch (error) { message.textContent = accountError(error); }
    finally { submit.disabled = reset.disabled = false; }
  }
  form.addEventListener('submit', (event) => {
    event.preventDefault();
    if (!form.reportValidity()) return;
    authAction(async () => {
      const method = creating ? sdk.createUserWithEmailAndPassword : sdk.signInWithEmailAndPassword;
      await method(auth, email.value.trim(), password.value);
      password.value = '';
      message.textContent = 'You’re signed in. New encryptions will be saved to your history.';
      state.setView('workspace');
    });
  });
  reset.addEventListener('click', () => {
    if (!email.reportValidity() || !email.value.trim()) { email.focus(); return; }
    authAction(async () => {
      await sdk.sendPasswordResetEmail(auth, email.value.trim());
      message.textContent = 'If an account exists for that address, a password reset email is on its way.';
    });
  });
  document.getElementById('account-logout').addEventListener('click', async (event) => {
    event.target.disabled = true;
    try { await sdk.signOut(auth); state.setView('login'); message.textContent = 'You’re signed out.'; }
    catch (error) { message.textContent = accountError(error); state.setView('login'); }
    finally { event.target.disabled = false; }
  });

  function clearHistory() {
    generation += 1; cursor = null; loading = false;
    list.replaceChildren(); more.hidden = true; refresh.disabled = false;
    status.textContent = '';
  }

  function historyCard(snapshot, uid) {
    const data = snapshot.data();
    const record = historyRecord(data.record);
    const title = el('input', { type: 'text', value: data.title, maxlength: '100', required: true, 'aria-label': 'Encryption title' });
    const note = el('p', { className: 'hint', role: 'status' });
    const card = el('article', { className: 'panel history-card' });
    const actions = el('div', { className: 'button-row' });
    const rename = el('button', { type: 'button', className: 'btn btn-small', text: 'Rename' });
    rename.addEventListener('click', async () => {
      if (!title.value.trim()) { title.focus(); note.textContent = 'Enter a title.'; return; }
      rename.disabled = true;
      try {
        requireOwner(uid);
        await sdk.updateDoc(snapshot.ref, { title: title.value.trim().slice(0, 100) });
        note.textContent = 'Title saved.';
      } catch (error) { note.textContent = accountError(error); }
      finally { rename.disabled = false; }
    });
    const open = el('button', { type: 'button', className: 'btn btn-primary', text: 'Open in Decryption', onclick: () => {
      if (user?.uid !== uid) return;
      window.dispatchEvent(new CustomEvent('history:open', { detail: record }));
    } });
    const download = el('button', { type: 'button', className: 'btn', text: 'Export Record', onclick: () => {
      if (user?.uid !== uid) return;
      const url = URL.createObjectURL(new Blob([JSON.stringify(record, null, 2)], {type: 'application/json'}));
      const link = el('a', { href: url, download: `${record.algorithm}-ciphertext-record.json` });
      document.body.append(link); link.click(); link.remove(); URL.revokeObjectURL(url);
    } });
    const remove = el('button', { type: 'button', className: 'btn danger-button', text: 'Delete', onclick: async () => {
      if (!confirm('Permanently delete this saved encryption? Export it first if you need a copy.')) return;
      remove.disabled = true;
      try { requireOwner(uid); await sdk.deleteDoc(snapshot.ref); card.remove(); if (!list.children.length) status.textContent = 'No encryptions on this page. Refresh or load older records.'; }
      catch (error) { note.textContent = accountError(error); remove.disabled = false; }
    } });
    actions.append(open, download, remove);
    const date = data.createdAt?.toDate?.();
    card.append(
      el('div', {className: 'history-card-top'}, el('span', {className: 'tag', text: record.algorithm === 'rc4' ? 'RC4' : 'A5/1'}), el('time', {datetime: date?.toISOString(), text: date ? date.toLocaleString() : 'Just saved'})),
      el('div', {className: 'input-row'}, title, rename),
      el('p', {className: 'hint', text: `${record.bit_length} bits${record.algorithm === 'a51' ? ` · ${record.direction} · ${record.segment_count} frame(s)` : ''}`}),
      el('div', {className: 'output-value mono history-ciphertext', text: record.ciphertext.length > 160 ? `${record.ciphertext.slice(0, 160)}…` : record.ciphertext}),
      actions, note,
    );
    return card;
  }

  async function loadHistory(append = false) {
    if (!user || loading) return;
    if (!append) clearHistory();
    const uid = user.uid, ticket = generation;
    loading = true; refresh.disabled = true; more.disabled = true;
    status.textContent = 'Loading your encryptions…';
    try {
      const constraints = [sdk.orderBy('createdAt', 'desc'), sdk.limit(25)];
      if (append && cursor) constraints.push(sdk.startAfter(cursor));
      const results = await sdk.getDocs(sdk.query(requireOwner(uid), ...constraints));
      if (generation !== ticket || user?.uid !== uid) return;
      for (const snapshot of results.docs) {
        try { list.append(historyCard(snapshot, uid)); }
        catch { list.append(el('p', {className: 'notice', text: 'A saved record could not be read.'})); }
      }
      cursor = results.docs.at(-1) || cursor;
      more.hidden = results.size < 25;
      status.textContent = list.children.length ? `${list.children.length} saved encryption(s)` : 'No saved encryptions yet. Encrypt a message while signed in to start your history.';
    } catch (error) {
      if (generation === ticket) status.textContent = accountError(error);
    } finally {
      if (generation === ticket) { loading = false; refresh.disabled = false; more.disabled = false; }
    }
  }
  refresh.addEventListener('click', () => loadHistory());
  more.addEventListener('click', () => loadHistory(true));
  state.subscribe((change) => { if (change === 'view' && state.view === 'history') loadHistory(); });
  onAccountChange((next) => {
    clearHistory();
    password.value = '';
    document.getElementById('account-name').textContent = next?.email || 'Guest session';
    document.getElementById('account-login').hidden = Boolean(next);
    document.getElementById('account-logout').hidden = !next;
    document.getElementById('history-guest').hidden = Boolean(next);
    refresh.hidden = !next;
    if (state.view === 'history') loadHistory();
  });
  refresh.hidden = true;
  startup = connect();
  startup.then(() => { submit.disabled = reset.disabled = false; message.textContent = user ? 'You’re signed in.' : 'Sign in to save new encryptions automatically.'; })
    .catch((error) => { message.textContent = accountError(error); status.textContent = accountError(error); });
}
