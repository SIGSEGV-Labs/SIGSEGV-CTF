/**
 * activity.js — /activity page logic
 * -----------------------------------------------------------------------
 * Renders a realistic authentication log (normal logins mixed with a
 * brute-force pattern against the admin account) and validates the
 * player's IP submission against a hashed answer so the raw answer never
 * sits in plaintext in the page source.
 * -----------------------------------------------------------------------
 */

// SHA-256 of the correct source IP ("192.168.1.47"), lowercased/trimmed
// before hashing. Kept out of plaintext so casual view-source doesn't
// hand over the answer.
const CORRECT_IP_HASH = 'a36cafa65ef55934cfc778695ff5a4daa9b293244500f79491d9d1c789593707';

// --- Log data -------------------------------------------------------------
// type: 'ok' | 'fail' | 'alert' | 'plain'
const LOG_ENTRIES = [
  { t: '09:41:12', type: 'ok',    text: 'USER LOGIN       alice       SUCCESS' },
  { t: '09:41:19', type: 'ok',    text: 'USER LOGIN       bob         SUCCESS' },
  { t: '09:41:34', type: 'ok',    text: 'USER LOGIN       chen.w      SUCCESS' },
  { t: '09:41:47', type: 'plain', text: 'SESSION REFRESH  alice       OK' },
  { t: '09:42:01', type: 'fail',  text: 'ADMIN LOGIN      admin       FAILED' },
  { t: '09:42:02', type: 'fail',  text: 'ADMIN LOGIN      admin       FAILED' },
  { t: '09:42:03', type: 'fail',  text: 'ADMIN LOGIN      admin       FAILED' },
  { t: '09:42:04', type: 'fail',  text: 'ADMIN LOGIN      admin       FAILED' },
  { t: '09:42:05', type: 'fail',  text: 'ADMIN LOGIN      admin       FAILED' },
  { t: '09:42:06', type: 'ok',    text: 'USER LOGIN       priya.s     SUCCESS' },
  { t: '09:42:09', type: 'fail',  text: 'ADMIN LOGIN      admin       FAILED' },
  { t: '09:42:10', type: 'fail',  text: 'ADMIN LOGIN      admin       FAILED' },
  { t: '09:42:11', type: 'fail',  text: 'ADMIN LOGIN      admin       FAILED' },
  { t: '09:42:13', type: 'fail',  text: 'ADMIN LOGIN      admin       FAILED' },
  { t: '09:42:14', type: 'fail',  text: 'ADMIN LOGIN      admin       FAILED' },
  { t: '09:42:16', type: 'fail',  text: 'ADMIN LOGIN      admin       FAILED' },
  { t: '09:42:19', type: 'fail',  text: 'ADMIN LOGIN      admin       FAILED' },
  { t: '09:42:20', type: 'plain', text: 'RATE THRESHOLD   admin       12 failures / 60s' },
  { t: '09:42:22', type: 'fail',  text: 'ADMIN LOGIN      admin       FAILED' },
  { t: '09:42:23', type: 'fail',  text: 'ADMIN LOGIN      admin       FAILED' },
  { t: '09:42:25', type: 'fail',  text: 'ADMIN LOGIN      admin       FAILED' },
  { t: '09:42:26', type: 'ok',    text: 'USER LOGIN       chen.w      SUCCESS' },
  { t: '09:42:28', type: 'fail',  text: 'ADMIN LOGIN      admin       FAILED' },
  { t: '09:42:29', type: 'fail',  text: 'ADMIN LOGIN      admin       FAILED' },
  { t: '09:42:31', type: 'alert', text: 'IDS ALERT        BRUTE-FORCE PATTERN DETECTED (auth: admin)' },
];

const LOG_DIVIDER = true;
const ATTACK_SOURCE_IP = '192.168.1.47';

const SOURCE_BLOCK = [
  'SOURCE IP: 192.168.1.47',
  'TARGET:    admin',
  'STATUS:    FAILED (37 attempts, 09:42:01\u201309:42:31)',
  'ENDPOINT:  /auth/admin-login',
];

function renderLog() {
  const console_ = document.getElementById('log-console');
  const frag = document.createDocumentFragment();

  LOG_ENTRIES.forEach((entry) => {
    const line = document.createElement('div');
    line.className = `log-line ${entry.type === 'alert' ? 'alert' : entry.type === 'fail' ? 'fail' : entry.type === 'ok' ? 'ok' : ''}`;
    const source = entry.type === 'fail' ? ` <span class="src">SRC ${ATTACK_SOURCE_IP}</span>` : '';
    line.innerHTML = `<span class="ts">[${entry.t}]</span> <span class="evt">${entry.text}</span>${source}`;
    frag.appendChild(line);
  });

  if (LOG_DIVIDER) {
    const hr = document.createElement('hr');
    hr.className = 'log-divider';
    frag.appendChild(hr);
  }

  const block = document.createElement('div');
  block.className = 'alert-block';
  block.innerHTML = SOURCE_BLOCK.map((l) => `<div>${l}</div>`).join('');
  frag.appendChild(block);

  console_.appendChild(frag);
}

function showDeniedBannerIfNeeded() {
  const params = new URLSearchParams(window.location.search);
  if (params.get('denied')) {
    document.getElementById('denied-banner').classList.remove('hidden');
  }
}

function setFeedback(el, message, kind) {
  el.textContent = message;
  el.className = `feedback show ${kind}`;
}

async function handleSubmit() {
  const input = document.getElementById('ip-input');
  const feedback = document.getElementById('feedback');
  const value = input.value.trim();

  if (!value) {
    setFeedback(feedback, 'Enter an IP address before submitting.', 'error');
    return;
  }

  const hash = await CTFState.sha256(value);

  if (hash === CORRECT_IP_HASH) {
    CTFState.set(CTFState.KEYS.IP_IDENTIFIED, true);
    setFeedback(feedback, '\u2713 Correct. Source of the brute-force activity identified. Admin Console access unlocked.', 'success');
    input.disabled = true;
    document.getElementById('submit-ip').disabled = true;
    document.getElementById('proceed-row').classList.remove('hidden');
  } else {
    setFeedback(feedback, '\u2717 That does not match the recorded source of the failed admin logins. Re-check the log above.', 'error');
  }
}

document.addEventListener('DOMContentLoaded', () => {
  renderLog();
  showDeniedBannerIfNeeded();

  document.getElementById('submit-ip').addEventListener('click', handleSubmit);
  document.getElementById('ip-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') handleSubmit();
  });

  // If the player already solved this in the current session, reflect that.
  if (CTFState.get(CTFState.KEYS.IP_IDENTIFIED)) {
    const feedback = document.getElementById('feedback');
    setFeedback(feedback, '\u2713 Already identified this session. You may proceed to the Admin Console.', 'success');
    document.getElementById('proceed-row').classList.remove('hidden');
  }
});
