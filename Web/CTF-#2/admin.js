/**
 * admin.js — /admin page logic
 * -----------------------------------------------------------------------
 * Guards direct access (must have identified the IP on /activity first),
 * handles containment (Block IP), validates the hardening checklist, and
 * only generates the final code after verification succeeds.
 * -----------------------------------------------------------------------
 */

// Target hardened configuration. `true` = checkbox should be CHECKED in the
// final state; `false` = it should be UNCHECKED.
const REQUIRED_CONFIG = {
  'cfg-root': false,      // root login must be disabled
  'cfg-password': false,  // password-only auth must be disabled
  'cfg-firewall': true,   // firewall must stay enabled
  'cfg-attempts': false,  // unlimited attempts must be disabled (rate-limited)
  'cfg-guest': false,     // guest account must be disabled
};

const CONFIG_LABELS = {
  'cfg-root': 'Root login disabled',
  'cfg-password': 'Strong authentication in place',
  'cfg-firewall': 'Firewall active',
  'cfg-attempts': 'Login attempts restricted',
  'cfg-guest': 'Guest access removed',
};

const WORDLIST = [
  'DMC1', 'DMC2', 'DMC3', 'DMC4', 'DMC5', 'DMC6', 'DMC7',
  'DMC8', 'DMC9', 'DMC10', 'DMC11', 'DMC12', 'DMC13', 'DMC14', 'DMC15',
];

function updateTrail() {
  const blocked = CTFState.get(CTFState.KEYS.IP_BLOCKED, false);
  const hardened = CTFState.get(CTFState.KEYS.HARDENING_COMPLETE, false);
  const verified = !!CTFState.get(CTFState.KEYS.FINAL_CODE, null);

  document.getElementById('trail-contain').classList.toggle('done', blocked);
  document.getElementById('trail-harden').classList.toggle('done', hardened);
  document.getElementById('trail-verify').classList.toggle('done', verified);
}

function isConfigCorrect() {
  return Object.entries(REQUIRED_CONFIG).every(
    ([id, wanted]) => document.getElementById(id).checked === wanted
  );
}

function renderSummary() {
  const list = document.getElementById('summary-list');
  list.innerHTML = '';
  Object.entries(REQUIRED_CONFIG).forEach(([id, wanted]) => {
    const isDone = document.getElementById(id).checked === wanted;
    const li = document.createElement('li');
    li.className = isDone ? 'done' : '';
    li.innerHTML = `<span class="tick">${isDone ? '\u2713' : '\u2013'}</span>${CONFIG_LABELS[id]}`;
    list.appendChild(li);
  });
}

function handleConfigChange() {
  renderSummary();
  const feedback = document.getElementById('hardening-feedback');
  const verifyBtn = document.getElementById('verify-btn');

  if (isConfigCorrect()) {
    CTFState.set(CTFState.KEYS.HARDENING_COMPLETE, true);
    feedback.textContent = '\u2713 Configuration meets hardening requirements.';
    feedback.className = 'feedback show success';
    verifyBtn.disabled = false;
  } else {
    CTFState.set(CTFState.KEYS.HARDENING_COMPLETE, false);
    feedback.textContent = '';
    feedback.className = 'feedback';
    verifyBtn.disabled = true;
  }
  updateTrail();
}

function handleBlockIp() {
  CTFState.set(CTFState.KEYS.IP_BLOCKED, true);

  document.getElementById('pre-block').classList.add('hidden');
  document.getElementById('post-block').classList.remove('hidden');
  document.getElementById('threat-status').textContent = 'BLOCKED';
  document.getElementById('threat-dot').classList.remove('red');
  document.getElementById('threat-level').textContent = 'CONTAINED';
  document.getElementById('threat-level').classList.remove('high');
  document.getElementById('threat-level').classList.add('blocked');

  document.getElementById('hardening-panel').classList.remove('hidden');
  document.getElementById('verify-panel').classList.remove('hidden');

  updateTrail();
}

async function handleVerify() {
  const feedback = document.getElementById('verify-feedback');

  const blocked = CTFState.get(CTFState.KEYS.IP_BLOCKED, false);
  const hardened = CTFState.get(CTFState.KEYS.HARDENING_COMPLETE, false) && isConfigCorrect();

  if (!blocked || !hardened) {
    feedback.textContent = '\u2717 Verification failed: containment and hardening must both be complete.';
    feedback.className = 'feedback show error';
    return;
  }

  feedback.textContent = 'Running verification...';
  feedback.className = 'feedback show info';

  // Small delay to make the check feel real rather than instantaneous.
  await new Promise((r) => setTimeout(r, 600));

  let code = CTFState.get(CTFState.KEYS.FINAL_CODE, null);
  if (!code) {
    code = CTFState.secureRandomChoice(WORDLIST);
    CTFState.set(CTFState.KEYS.FINAL_CODE, code);
  }

  feedback.textContent = '\u2713 Verification passed.';
  feedback.className = 'feedback show success';

  document.getElementById('final-code').textContent = code;
  document.getElementById('code-panel').classList.remove('hidden');
  document.getElementById('verify-btn').disabled = true;

  updateTrail();
}

function restoreExistingProgress() {
  if (CTFState.get(CTFState.KEYS.IP_BLOCKED, false)) {
    handleBlockIp();
  } else {
    document.getElementById('hardening-panel').classList.add('hidden');
    document.getElementById('verify-panel').classList.add('hidden');
  }

  const existingCode = CTFState.get(CTFState.KEYS.FINAL_CODE, null);
  if (existingCode) {
    document.getElementById('final-code').textContent = existingCode;
    document.getElementById('code-panel').classList.remove('hidden');
  }

  renderSummary();
  updateTrail();
}

document.addEventListener('DOMContentLoaded', () => {
  // Route guard: this page requires the IP to have been identified on
  // /activity first. If not, bounce back with an explanation banner.
  const allowed = CTFState.requireStep(
    CTFState.get(CTFState.KEYS.IP_IDENTIFIED, false),
    '/activity.html',
    'investigation-required'
  );
  if (!allowed) return;

  document.getElementById('page-body').style.display = '';

  document.getElementById('block-btn').addEventListener('click', handleBlockIp);
  document.getElementById('verify-btn').addEventListener('click', handleVerify);
  Object.keys(REQUIRED_CONFIG).forEach((id) => {
    document.getElementById(id).addEventListener('change', handleConfigChange);
  });

  restoreExistingProgress();
});
