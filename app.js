const authModal = document.getElementById('auth-modal');
const modalClose = document.getElementById('modal-close');
const openAuthButtons = document.querySelectorAll('[data-open-auth]');
const authTabs = document.querySelectorAll('.auth-tab');
const authForms = document.querySelectorAll('.auth-form');
const loginForm = document.getElementById('login-form');
const registerForm = document.getElementById('register-form');
const headerActions = document.getElementById('header-actions');
const headerUser = document.getElementById('header-user');
const userName = document.getElementById('user-name');
const userAvatar = document.getElementById('user-avatar');
const signOutBtn = document.getElementById('sign-out');

const loginEmail = document.getElementById('login-email');
const loginPassword = document.getElementById('login-password');
const loginRemember = document.getElementById('remember-me');
const loginEmailError = document.getElementById('login-email-error');
const loginPasswordError = document.getElementById('login-password-error');
const loginMessage = document.getElementById('login-message');

const registerName = document.getElementById('register-name');
const registerEmail = document.getElementById('register-email');
const registerPassword = document.getElementById('register-password');
const registerConfirm = document.getElementById('register-confirm');
const registerNameError = document.getElementById('register-name-error');
const registerEmailError = document.getElementById('register-email-error');
const registerPasswordError = document.getElementById('register-password-error');
const registerConfirmError = document.getElementById('register-confirm-error');
const terms = document.getElementById('terms');
const termsError = document.getElementById('terms-error');
const registerMessage = document.getElementById('register-message');

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
    throw new Error(errorMessage(data, response.status));
  }
  return data;
}

function errorMessage(data, status) {
  if (data && typeof data.detail === 'string') return data.detail;
  if (data && Array.isArray(data.detail)) {
    return data.detail.map((item) => item.msg).join('. ');
  }
  if (status === 401) return 'Incorrect email or password';
  if (status === 409) return 'An account with this email already exists';
  return 'Something went wrong. Please try again.';
}

function nextTarget() {
  const next = new URLSearchParams(window.location.search).get('next');
  if (next && next.startsWith('/') && !next.startsWith('//')) return next;
  return null;
}

function openModal(tab = 'login') {
  authModal.classList.add('active');
  authModal.setAttribute('aria-hidden', 'false');
  setActiveTab(tab);
  clearAllMessages();
  clearAllErrors();
}

function closeModal() {
  authModal.classList.remove('active');
  authModal.setAttribute('aria-hidden', 'true');
}

openAuthButtons.forEach((btn) => {
  btn.addEventListener('click', () => openModal(btn.dataset.openAuth));
});

modalClose.addEventListener('click', closeModal);
authModal.addEventListener('click', (e) => {
  if (e.target === authModal) closeModal();
});

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && authModal.classList.contains('active')) closeModal();
});

function setActiveTab(tab) {
  authTabs.forEach((t) => t.classList.toggle('active', t.dataset.authTab === tab));
  authForms.forEach((f) => f.classList.toggle('active', f.id === `${tab}-form`));
  const title = document.getElementById('auth-title');
  const subtitle = document.getElementById('auth-subtitle');
  if (tab === 'login') {
    title.textContent = 'Sign in to AtDev';
    subtitle.textContent = 'Access your AtDev services';
  } else {
    title.textContent = 'Create your AtDev account';
    subtitle.textContent = 'Join the AtDev ecosystem';
  }
}

authTabs.forEach((tab) => {
  tab.addEventListener('click', () => setActiveTab(tab.dataset.authTab));
});

function clearAllErrors() {
  [
    loginEmailError,
    loginPasswordError,
    registerNameError,
    registerEmailError,
    registerPasswordError,
    registerConfirmError,
    termsError,
  ].forEach((el) => {
    if (el) el.textContent = '';
  });
}

function clearAllMessages() {
  if (loginMessage) {
    loginMessage.textContent = '';
    loginMessage.className = 'form-message';
  }
  if (registerMessage) {
    registerMessage.textContent = '';
    registerMessage.className = 'form-message';
  }
}

function showMessage(el, text, type) {
  el.textContent = text;
  el.className = `form-message ${type}`;
}

function setSession(user) {
  currentUser = user;
  updateHeader();
}

function updateHeader() {
  if (currentUser) {
    headerActions.classList.add('hidden');
    headerUser.classList.remove('hidden');
    userName.textContent = currentUser.name || currentUser.email;
    userAvatar.textContent = (currentUser.name || currentUser.email).trim().charAt(0).toUpperCase();
  } else {
    headerActions.classList.remove('hidden');
    headerUser.classList.add('hidden');
  }
}

function finishAuth(messageEl, message) {
  showMessage(messageEl, message, 'success');
  const target = nextTarget();
  if (target) {
    setTimeout(() => window.location.assign(target), 350);
    return;
  }
  setTimeout(() => closeModal(), 650);
}

signOutBtn.addEventListener('click', async () => {
  try {
    await api('/api/auth/logout', { method: 'POST' });
  } finally {
    setSession(null);
  }
});

document.getElementById('forgot-password')?.addEventListener('click', () => {
  showMessage(loginMessage, 'Password reset is not enabled yet. Contact the AtDev administrator.', 'error');
});

loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  clearAllErrors();
  clearAllMessages();

  let valid = true;
  const email = loginEmail.value.trim();
  const password = loginPassword.value;

  if (!email) {
    loginEmailError.textContent = 'Email is required';
    valid = false;
  } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    loginEmailError.textContent = 'Enter a valid email';
    valid = false;
  }
  if (!password) {
    loginPasswordError.textContent = 'Password is required';
    valid = false;
  }
  if (!valid) return;

  const submit = loginForm.querySelector('button[type="submit"]');
  submit.disabled = true;
  try {
    const user = await api('/api/auth/login', {
      method: 'POST',
      body: { email, password, remember: Boolean(loginRemember?.checked) },
    });
    setSession(user);
    finishAuth(loginMessage, `Welcome back, ${user.name.split(' ')[0]}!`);
  } catch (error) {
    showMessage(loginMessage, error.message, 'error');
  } finally {
    submit.disabled = false;
  }
});

registerForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  clearAllErrors();
  clearAllMessages();

  let valid = true;
  const name = registerName.value.trim();
  const email = registerEmail.value.trim();
  const password = registerPassword.value;
  const confirm = registerConfirm.value;

  if (!name) {
    registerNameError.textContent = 'Full name is required';
    valid = false;
  }
  if (!email) {
    registerEmailError.textContent = 'Email is required';
    valid = false;
  } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    registerEmailError.textContent = 'Enter a valid email';
    valid = false;
  }
  if (!password) {
    registerPasswordError.textContent = 'Password is required';
    valid = false;
  } else if (password.length < 8) {
    registerPasswordError.textContent = 'Password must be at least 8 characters';
    valid = false;
  }
  if (password !== confirm) {
    registerConfirmError.textContent = 'Passwords do not match';
    valid = false;
  }
  if (!terms.checked) {
    termsError.textContent = 'You must accept the Terms of Service';
    valid = false;
  }
  if (!valid) return;

  const submit = registerForm.querySelector('button[type="submit"]');
  submit.disabled = true;
  try {
    const user = await api('/api/auth/register', {
      method: 'POST',
      body: { name, email, password },
    });
    setSession(user);
    finishAuth(registerMessage, 'Account created successfully!');
  } catch (error) {
    const target = /already exists/i.test(error.message) ? 'login' : null;
    showMessage(registerMessage, error.message, 'error');
    if (target) setTimeout(() => setActiveTab(target), 1200);
  } finally {
    submit.disabled = false;
  }
});

async function init() {
  try {
    const config = await api('/api/auth/config');
    if (!config.allow_registration) {
      document.querySelectorAll('[data-open-auth="register"]').forEach((el) => {
        el.disabled = true;
        el.title = 'Registration is disabled';
      });
    }
  } catch {
    /* config is optional for rendering */
  }

  try {
    const user = await api('/api/auth/me');
    setSession(user);
  } catch {
    setSession(null);
    if (nextTarget()) {
      openModal('login');
      showMessage(loginMessage, 'Sign in to continue to the requesting app.', 'error');
    }
  }
}

init();
