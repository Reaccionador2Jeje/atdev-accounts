const dashboard = document.getElementById('dashboard');
const signedOut = document.getElementById('signed-out');
const headerActions = document.getElementById('header-actions');
const headerUser = document.getElementById('header-user');
const userName = document.getElementById('user-name');
const userAvatar = document.getElementById('user-avatar');
const signOutBtn = document.getElementById('sign-out');

const profileForm = document.getElementById('profile-form');
const profileMessage = document.getElementById('profile-message');
const nameInput = document.getElementById('name');
const emailInput = document.getElementById('email');

const passwordForm = document.getElementById('password-form');
const passwordMessage = document.getElementById('password-message');

const sessionsList = document.getElementById('sessions-list');
const apiKeysList = document.getElementById('api-keys-list');
const connectionsList = document.getElementById('connections-list');

const apiKeyForm = document.getElementById('api-key-form');
const apiKeyName = document.getElementById('api-key-name');
const apiKeyMessage = document.getElementById('api-key-message');
const newKeyBox = document.getElementById('new-key');
const newKeyValue = document.getElementById('new-key-value');
const copyKeyBtn = document.getElementById('copy-key');

const deleteForm = document.getElementById('delete-form');
const deleteMessage = document.getElementById('delete-message');
const deletePassword = document.getElementById('delete-password');

let currentUser = null;

async function api(path, options = {}) {
  const config = {
    credentials: 'same-origin',
    headers: { Accept: 'application/json' },
    ...options,
  };
  if (config.body && typeof config.body !== 'string') {
    config.headers['Content-Type'] = 'application/json';
    config.body = JSON.stringify(config.body);
  }
  const response = await fetch(path, config);
  let data = null;
  try {
    data = await response.json();
  } catch {
    data = null;
  }
  if (!response.ok) {
    if (response.status === 401) {
      const error = new Error('Unauthorized');
      error.unauthorized = true;
      throw error;
    }
    let message = 'Something went wrong. Please try again.';
    if (data && typeof data.detail === 'string') message = data.detail;
    else if (data && Array.isArray(data.detail)) message = data.detail.map((d) => d.msg).join('. ');
    throw new Error(message);
  }
  return data;
}

function showMessage(el, text, type = 'success') {
  el.textContent = text;
  el.className = `form-message ${type}`;
}

function clearMessage(el) {
  el.textContent = '';
  el.className = 'form-message';
}

function setHeader(user) {
  currentUser = user;
  if (!user) {
    dashboard.hidden = true;
    signedOut.hidden = false;
    headerActions.classList.remove('hidden');
    headerUser.classList.add('hidden');
    return;
  }
  dashboard.hidden = false;
  signedOut.hidden = true;
  headerActions.classList.add('hidden');
  headerUser.classList.remove('hidden');
  userName.textContent = user.name || user.email;
  userAvatar.textContent = (user.name || user.email).trim().charAt(0).toUpperCase();
}

function formatDate(value) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function makeItem(title, subtitle, meta, actions = []) {
  const item = document.createElement('div');
  item.className = 'list-item';
  const body = document.createElement('div');
  body.className = 'list-item-body';
  const titleEl = document.createElement('div');
  titleEl.className = 'list-item-title';
  titleEl.textContent = title;
  const subtitleEl = document.createElement('div');
  subtitleEl.className = 'list-item-subtitle';
  subtitleEl.textContent = subtitle;
  body.append(titleEl, subtitleEl);
  item.append(body);
  if (meta) {
    const metaEl = document.createElement('span');
    metaEl.className = 'pill';
    metaEl.textContent = meta;
    item.append(metaEl);
  }
  const actionWrap = document.createElement('div');
  actionWrap.className = 'list-item-actions';
  actions.forEach((action) => actionWrap.append(action));
  if (actions.length) item.append(actionWrap);
  return item;
}

function makeButton(label, onClick, className = 'btn ghost small') {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = className;
  button.textContent = label;
  button.addEventListener('click', onClick);
  return button;
}

function renderProfile(user) {
  nameInput.value = user.name;
  emailInput.value = user.email;
  document.getElementById('profile-name').textContent = user.name;
  document.getElementById('profile-email').textContent = user.email;
  document.getElementById('profile-avatar').textContent = (user.name || user.email)
    .trim()
    .charAt(0)
    .toUpperCase();
}

async function loadSessions() {
  const sessions = await api('/api/account/sessions');
  sessionsList.replaceChildren();
  document.getElementById('stat-sessions').textContent = String(sessions.length);
  if (!sessions.length) {
    sessionsList.append(makeItem('No active sessions', 'Sign in again to create one.'));
    return;
  }
  sessions.forEach((session) => {
    const agent = session.user_agent || 'Unknown device';
    const subtitle = `Last active ${formatDate(session.last_seen_at)} · ${session.ip || 'unknown IP'}`;
    const actions = [];
    if (session.current) {
      actions.push(makeButton('This device', () => {}, 'pill current'));
    } else {
      actions.push(
        makeButton('Revoke', async () => {
          if (!window.confirm('Sign out this session?')) return;
          await api(`/api/account/sessions/${session.id}`, { method: 'DELETE' });
          await loadSessions();
        })
      );
    }
    sessionsList.append(makeItem(agent, subtitle, session.current ? 'Current' : null, actions));
  });
}

async function loadApiKeys() {
  const keys = await api('/api/account/api-keys');
  apiKeysList.replaceChildren();
  document.getElementById('stat-keys').textContent = String(keys.length);
  if (!keys.length) {
    apiKeysList.append(makeItem('No API keys yet', 'Create one to use AtDev services from scripts.'));
    return;
  }
  keys.forEach((key) => {
    const subtitle = `Created ${formatDate(key.created_at)} · Last used ${formatDate(key.last_used_at)}`;
    apiKeysList.append(
      makeItem(
        `${key.name} (${key.prefix}…)`,
        subtitle,
        null,
        [
          makeButton('Revoke', async () => {
            if (!window.confirm(`Revoke API key "${key.name}"?`)) return;
            await api(`/api/account/api-keys/${key.id}`, { method: 'DELETE' });
            await loadApiKeys();
          }),
        ]
      )
    );
  });
}

async function loadConnections() {
  const connections = await api('/api/account/connections');
  connectionsList.replaceChildren();
  document.getElementById('stat-connections').textContent = String(connections.length);
  if (!connections.length) {
    connectionsList.append(makeItem('No connected apps', 'Apps appear here after you authorize them.'));
    return;
  }
  connections.forEach((connection) => {
    const subtitle = `Scopes: ${connection.scopes.join(', ')} · Updated ${formatDate(connection.updated_at)}`;
    connectionsList.append(
      makeItem(connection.name, subtitle, null, [
        makeButton('Disconnect', async () => {
          if (!window.confirm(`Disconnect "${connection.name}"?`)) return;
          await api(`/api/account/connections/${encodeURIComponent(connection.client_id)}`, {
            method: 'DELETE',
          });
          await loadConnections();
        }),
      ])
    );
  });
}

async function loadAll() {
  await Promise.all([loadSessions(), loadApiKeys(), loadConnections()]);
}

profileForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  clearMessage(profileMessage);
  try {
    const user = await api('/api/account', {
      method: 'PATCH',
      body: { name: nameInput.value.trim() },
    });
    setHeader(user);
    renderProfile(user);
    showMessage(profileMessage, 'Profile updated.');
  } catch (error) {
    showMessage(profileMessage, error.message, 'error');
  }
});

passwordForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  clearMessage(passwordMessage);
  const currentPassword = document.getElementById('current-password').value;
  const newPassword = document.getElementById('new-password').value;
  if (newPassword.length < 8) {
    showMessage(passwordMessage, 'New password must be at least 8 characters.', 'error');
    return;
  }
  try {
    await api('/api/account/password', {
      method: 'POST',
      body: { current_password: currentPassword, new_password: newPassword },
    });
    passwordForm.reset();
    showMessage(passwordMessage, 'Password changed. Other sessions were signed out.');
    await loadSessions();
  } catch (error) {
    showMessage(passwordMessage, error.message, 'error');
  }
});

document.getElementById('revoke-other-sessions').addEventListener('click', async () => {
  if (!window.confirm('Sign out all other sessions?')) return;
  await api('/api/account/sessions?keep_current=true', { method: 'DELETE' });
  await loadSessions();
});

apiKeyForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  clearMessage(apiKeyMessage);
  newKeyBox.classList.add('hidden');
  try {
    const created = await api('/api/account/api-keys', {
      method: 'POST',
      body: { name: apiKeyName.value.trim() },
    });
    apiKeyForm.reset();
    newKeyValue.textContent = created.key;
    newKeyBox.classList.remove('hidden');
    showMessage(apiKeyMessage, 'API key created.');
    await loadApiKeys();
  } catch (error) {
    showMessage(apiKeyMessage, error.message, 'error');
  }
});

copyKeyBtn.addEventListener('click', async () => {
  const value = newKeyValue.textContent;
  try {
    await navigator.clipboard.writeText(value);
    copyKeyBtn.textContent = 'Copied';
    setTimeout(() => {
      copyKeyBtn.textContent = 'Copy';
    }, 1500);
  } catch {
    window.prompt('Copy your API key:', value);
  }
});

deleteForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!window.confirm('Permanently delete your AtDev account? This cannot be undone.')) return;
  clearMessage(deleteMessage);
  try {
    await api('/api/account', {
      method: 'DELETE',
      body: { password: deletePassword.value },
    });
    window.location.assign('/');
  } catch (error) {
    showMessage(deleteMessage, error.message, 'error');
  }
});

signOutBtn.addEventListener('click', async () => {
  try {
    await api('/api/auth/logout', { method: 'POST' });
  } finally {
    window.location.assign('/');
  }
});

async function init() {
  try {
    const user = await api('/api/account');
    setHeader(user);
    renderProfile(user);
    await loadAll();
  } catch (error) {
    setHeader(null);
    if (!error.unauthorized) {
      console.error(error);
    }
  }
}

init();
