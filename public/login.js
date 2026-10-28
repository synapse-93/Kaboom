const form = document.getElementById('login-form');
const errorBox = document.getElementById('login-error');
const password = document.getElementById('password');
const username = document.getElementById('username');
const switchMode = document.getElementById('switch-mode');
const submitLabel = document.getElementById('submit-label');
const formTitle = document.getElementById('form-title');
const formHint = document.getElementById('form-hint');
const passwordHint = document.getElementById('password-hint');
const switchCopy = document.getElementById('switch-copy');
let registerMode = false;

switchMode.addEventListener('click', () => {
  registerMode = !registerMode;
  errorBox.textContent = '';
  formTitle.textContent = registerMode ? 'Create your account' : 'Welcome back';
  formHint.textContent = registerMode ? 'Choose a username and a strong password to get started.' : 'Sign in to manage your shared files.';
  submitLabel.firstChild.textContent = registerMode ? 'Create account ' : 'Sign in ';
  switchCopy.textContent = registerMode ? 'Already have an account?' : 'New to Drop Space?';
  switchMode.textContent = registerMode ? 'Sign in' : 'Create an account';
  passwordHint.hidden = !registerMode;
  username.autocomplete = registerMode ? 'username' : 'username';
  password.autocomplete = registerMode ? 'new-password' : 'current-password';
  password.minLength = registerMode ? 12 : 0;
  username.minLength = 3;
  username.maxLength = 24;
  username.pattern = '[A-Za-z0-9][A-Za-z0-9_-]{2,23}';
  username.title = 'Use 3-24 letters, numbers, underscores, or hyphens; start with a letter or number.';
  submitLabel.disabled = false;
});

document.getElementById('toggle-password').addEventListener('click', event => {
  const showing = password.type === 'text';
  password.type = showing ? 'password' : 'text';
  event.currentTarget.textContent = showing ? 'Show' : 'Hide';
  event.currentTarget.setAttribute('aria-label', showing ? 'Show password' : 'Hide password');
});
form.addEventListener('submit', async event => {
  event.preventDefault();
  const button = form.querySelector('button[type="submit"]');
  button.disabled = true;
  errorBox.textContent = '';
  try {
    const response = await fetch(registerMode ? '/api/register' : '/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: username.value, password: password.value }) });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || (registerMode ? 'Account creation failed.' : 'Sign-in failed.'));
    location.replace('/');
  } catch (error) {
    errorBox.textContent = error.message;
    password.value = '';
    password.focus();
  } finally { button.disabled = false; }
});
