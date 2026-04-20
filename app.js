// FFC IT PORTAL - Enterprise Workflow Frontend
// Pure ES module. Talks to Supabase via @supabase/supabase-js CDN.

const { createClient } = window.supabase;
const CFG = window.FFC_CONFIG;
const sb = createClient(CFG.SUPABASE_URL, CFG.SUPABASE_KEY, {
  auth: {
    persistSession: true,
    autoRefreshToken: true,
    detectSessionInUrl: true,
    storage: window.localStorage,
    storageKey: 'ffc-portal-auth'
  }
});

const $  = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);

let CURRENT_USER = null;   // profile row
let USER_ROLES = [];       // role codes
let USER_PERMS = [];       // permission codes
let CURRENT_VIEW = 'dashboard';

// =============================================================================
// UTILITIES
// =============================================================================
const toast = (msg, type='info', ms=2800) => {
  const t = $('#toast');
  t.className = `toast ${type} show`;
  t.textContent = msg;
  setTimeout(() => t.classList.remove('show'), ms);
};
const fmtDate = (d) => d ? new Date(d).toLocaleDateString('en-GB', { day:'2-digit', month:'short', year:'numeric' }) : '—';
const fmtDateTime = (d) => d ? new Date(d).toLocaleString('en-GB', { day:'2-digit', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' }) : '—';
const fmtRel = (d) => {
  if (!d) return '—';
  const diff = (Date.now() - new Date(d).getTime()) / 1000;
  if (diff < 60) return 'just now';
  if (diff < 3600) return Math.floor(diff/60)+'m ago';
  if (diff < 86400) return Math.floor(diff/3600)+'h ago';
  if (diff < 604800) return Math.floor(diff/86400)+'d ago';
  return fmtDate(d);
};
const escape = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const moduleLabel = (m) => ({change_request:'Change',sop:'SOP',leave:'Leave',overtime:'Overtime',comp_off:'Comp Off'}[m] || m);
const statusLabel = (s) => s.replace(/_/g,' ').replace(/\b\w/g, c => c.toUpperCase());
const initials = (name) => (name||'').split(/\s+/).map(s=>s[0]).filter(Boolean).slice(0,2).join('').toUpperCase() || '—';

const hasRole = (r) => USER_ROLES.includes(r);
const hasPerm = (p) => USER_PERMS.includes(p);
const isAdmin = () => hasRole('admin');
const isManager = () => hasRole('it_manager') || hasRole('department_head') || hasRole('admin');

// =============================================================================
// AUTH
// =============================================================================
async function login() {
  const email = $('#loginEmail').value.trim();
  const password = $('#loginPassword').value;

  // Clear old error first
  const errBox = $('#loginError');
  if (errBox) {
    errBox.textContent = '';
    errBox.classList.remove('show');
  }

  if (!email || !password) {
    showLoginErr('Enter email and password.');
    return;
  }

  const btn = $('#btnLogin');
  btn.disabled = true;
  btn.innerHTML = '<span class="spin"></span> Signing in…';

  // Retry wrapper: if Supabase is warming up from idle (free tier),
  // first request can fail. Auto-retry up to 3 times with backoff.
  const attemptSignIn = async (attempt = 1) => {
    try {
      const { error } = await sb.auth.signInWithPassword({ email, password });
      if (error) throw error;
      return { success: true };
    } catch (e) {
      const isNetworkError =
        e.message?.includes('fetch') ||
        e.message?.includes('network') ||
        e.message?.includes('NetworkError') ||
        e.name === 'TypeError';

      if (isNetworkError && attempt < 3) {
        btn.innerHTML = `<span class="spin"></span> Connecting (${attempt}/3)…`;
        await new Promise(r => setTimeout(r, 1000 * Math.pow(2, attempt - 1)));
        return attemptSignIn(attempt + 1);
      }

      return { success: false, error: e };
    }
  };

  try {
    const result = await attemptSignIn();
    if (!result.success) {
      const err = result.error;
      let msg = err.message || 'Sign-in failed.';
      if (msg.includes('fetch') || msg.includes('network')) {
        msg = 'Cannot connect to the server. Check your internet connection and try again. If this persists, the server may be waking up — wait 30 seconds and retry.';
      } else if (msg.includes('Invalid login') || msg.includes('credentials')) {
        msg = 'Email or password is incorrect.';
      }
      showLoginErr(msg);
      return;
    }

    // MFA check removed from here.
    // bootstrap() already handles MFA centrally.
    await logAuthEvent('login');
    await bootstrap();
  } catch (e) {
    showLoginErr(e.message || 'Sign-in failed.');
  } finally {
    btn.disabled = false;
    btn.innerHTML = 'Sign in →';
  }
}
const showLoginErr = (m) => { const e = $('#loginError'); e.textContent = m; e.classList.add('show'); };

// =============================================================================
// MFA (TOTP — Authenticator app)
// =============================================================================

async function logAuthEvent(eventType, metadata = {}) {
  try {
    const { data: { user } } = await sb.auth.getUser();
    if (!user) return;
    await sb.from('auth_events').insert({
      user_id: user.id,
      event_type: eventType,
      user_agent: navigator.userAgent.substring(0, 200),
      metadata: metadata
    });
  } catch(e) { console.warn('Auth event log failed', e); }
}

// Returns true if user can proceed to bootstrap, false if MFA screen is now showing
async function handleMfaIfNeeded() {
  try {
    // Check user's current authentication level
    const { data: aalData } = await sb.auth.mfa.getAuthenticatorAssuranceLevel();
    const current = aalData?.currentLevel;
    const next = aalData?.nextLevel;

    // If next is aal2 and current is aal1 → MFA factor exists, user needs to verify
    if (next === 'aal2' && current === 'aal1') {
      await showMfaChallenge();
      return false;  // MFA challenge now showing
    }

    // User has no MFA factor yet — check if their profile requires it
    const { data: { user } } = await sb.auth.getUser();
    if (!user) return true;

    const { data: profile } = await sb.from('profiles')
      .select('mfa_required, mfa_enrolled')
      .eq('id', user.id)
      .single();

    if (profile?.mfa_required && !profile?.mfa_enrolled) {
      // User must enroll MFA before proceeding
      await showMfaEnrollment();
      return false;
    }

    return true;
  } catch(e) {
    console.warn('MFA check failed:', e);
    return true;  // Fail-open: don't lock users out if MFA service has an issue
  }
}

async function showMfaChallenge() {
  const screen = $('#loginScreen');
  if (!screen) return;

  // Replace login form with MFA challenge UI
  const form = screen.querySelector('.login-form') || screen.querySelector('form') || screen.querySelector('[class*="login"]');
  // Easier: overlay a modal inside the login screen
  const existing = document.getElementById('mfaModal');
  if (existing) existing.remove();

  const modal = document.createElement('div');
  modal.id = 'mfaModal';
  modal.innerHTML = `
    <div class="mfa-panel">
      <div class="mfa-icon">🔐</div>
      <h2>Two-Factor Authentication</h2>
      <p>Open your authenticator app and enter the 6-digit code.</p>
      <input id="mfaCode" maxlength="6" inputmode="numeric" pattern="[0-9]*" placeholder="000000" autofocus />
      <div id="mfaError" class="error-msg"></div>
      <button id="mfaSubmit" class="btn ok">Verify</button>
      <button id="mfaCancel" class="btn secondary btn-sm" style="margin-top:10px">Cancel</button>
    </div>`;
  document.body.appendChild(modal);

  // Get challenge factor
  const { data: factors } = await sb.auth.mfa.listFactors();
  const totpFactor = factors?.totp?.[0];
  if (!totpFactor) {
    document.getElementById('mfaError').textContent = 'No MFA factor found. Contact IT.';
    return;
  }

  const submitMfa = async () => {
    const code = document.getElementById('mfaCode').value.trim();
    if (code.length !== 6) {
      document.getElementById('mfaError').textContent = 'Enter the 6-digit code.';
      return;
    }
    const btn = document.getElementById('mfaSubmit');
    btn.disabled = true; btn.innerHTML = '<span class="spin"></span> Verifying…';
    try {
      const { data: challenge, error: cErr } = await sb.auth.mfa.challenge({ factorId: totpFactor.id });
      if (cErr) throw cErr;

      const { error: vErr } = await sb.auth.mfa.verify({
        factorId: totpFactor.id,
        challengeId: challenge.id,
        code: code
      });
      if (vErr) throw vErr;

      await logAuthEvent('mfa_success');
      modal.remove();
      await bootstrap();
    } catch(e) {
      await logAuthEvent('mfa_failed', { error: e.message });
      document.getElementById('mfaError').textContent = e.message || 'Code invalid.';
      btn.disabled = false; btn.innerHTML = 'Verify';
    }
  };

  document.getElementById('mfaSubmit').addEventListener('click', submitMfa);
  document.getElementById('mfaCode').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') submitMfa();
  });
  document.getElementById('mfaCancel').addEventListener('click', async () => {
    await sb.auth.signOut();
    modal.remove();
  });
}

async function showMfaEnrollment() {
  const existing = document.getElementById('mfaModal');
  if (existing) existing.remove();

  // Start enrollment
  const { data: factor, error } = await sb.auth.mfa.enroll({
    factorType: 'totp',
    friendlyName: 'FFC IT Portal'
  });
  if (error) {
    alert('Could not start MFA enrollment: ' + error.message);
    return;
  }

  const modal = document.createElement('div');
  modal.id = 'mfaModal';
  modal.innerHTML = `
    <div class="mfa-panel" style="max-width:480px">
      <div class="mfa-icon">🔐</div>
      <h2>Set Up Two-Factor Authentication</h2>
      <p style="margin-bottom:16px">Your account requires MFA. Follow these steps:</p>
      <ol style="text-align:left;font-size:13px;line-height:1.8;margin:0 auto 20px;max-width:380px">
        <li>Install <b>Microsoft Authenticator</b> or <b>Google Authenticator</b> on your phone</li>
        <li>Open the app and tap "Add account" → "Work or school"</li>
        <li>Scan the QR code below</li>
        <li>Enter the 6-digit code your app shows</li>
      </ol>
      <div style="background:white;padding:16px;border:1px solid #e3ebd8;border-radius:8px;display:inline-block;margin-bottom:16px">
        <img src="${factor.totp.qr_code}" alt="MFA QR code" style="width:200px;height:200px;display:block" />
      </div>
      <details style="margin-bottom:16px;font-size:11px;color:#7a8775">
        <summary style="cursor:pointer">Can't scan? Enter secret manually</summary>
        <code style="display:block;margin-top:8px;padding:10px;background:#f8faf3;border-radius:4px;font-size:11px;word-break:break-all">${factor.totp.secret}</code>
      </details>
      <input id="mfaCode" maxlength="6" inputmode="numeric" pattern="[0-9]*" placeholder="000000" autofocus />
      <div id="mfaError" class="error-msg"></div>
      <button id="mfaSubmit" class="btn ok">Complete Setup</button>
      <button id="mfaCancel" class="btn secondary btn-sm" style="margin-top:10px">Cancel (sign out)</button>
    </div>`;
  document.body.appendChild(modal);

  const submitEnroll = async () => {
    const code = document.getElementById('mfaCode').value.trim();
    if (code.length !== 6) {
      document.getElementById('mfaError').textContent = 'Enter the 6-digit code from your app.';
      return;
    }
    const btn = document.getElementById('mfaSubmit');
    btn.disabled = true; btn.innerHTML = '<span class="spin"></span> Verifying…';
    try {
      const { data: challenge, error: cErr } = await sb.auth.mfa.challenge({ factorId: factor.id });
      if (cErr) throw cErr;

      const { error: vErr } = await sb.auth.mfa.verify({
        factorId: factor.id,
        challengeId: challenge.id,
        code: code
      });
      if (vErr) throw vErr;

      // Mark profile as enrolled
      const { data: { user } } = await sb.auth.getUser();
      if (user) {
        await sb.from('profiles').update({
          mfa_enrolled: true,
          mfa_enrolled_at: new Date().toISOString()
        }).eq('id', user.id);
      }

      await logAuthEvent('mfa_enrolled');
      modal.remove();
      alert('MFA setup complete! You will be asked for the code on next login.');
      await bootstrap();
    } catch(e) {
      document.getElementById('mfaError').textContent = e.message || 'Code invalid — try again.';
      btn.disabled = false; btn.innerHTML = 'Complete Setup';
    }
  };

  document.getElementById('mfaSubmit').addEventListener('click', submitEnroll);
  document.getElementById('mfaCode').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') submitEnroll();
  });
  document.getElementById('mfaCancel').addEventListener('click', async () => {
    await sb.auth.signOut();
    modal.remove();
    $('#loginScreen').style.display = 'grid';
  });
}

// Let user enable MFA voluntarily from their profile
window.enableMfa = async function() {
  await showMfaEnrollment();
};

// Let user disable MFA (only if not required)
window.disableMfa = async function() {
  const { data: { user } } = await sb.auth.getUser();
  if (!user) return;
  const { data: profile } = await sb.from('profiles').select('mfa_required').eq('id', user.id).single();
  if (profile?.mfa_required) {
    alert('MFA is required for your account and cannot be disabled. Contact admin.');
    return;
  }
  if (!confirm('Disable MFA? You will only need your password to sign in.')) return;
  const { data: factors } = await sb.auth.mfa.listFactors();
  for (const f of (factors?.totp || [])) {
    await sb.auth.mfa.unenroll({ factorId: f.id });
  }
  await sb.from('profiles').update({ mfa_enrolled: false, mfa_enrolled_at: null }).eq('id', user.id);
  alert('MFA disabled.');
};

async function logout() {
  try { await sb.auth.signOut(); } catch(e) { console.warn('signOut error', e); }
  // Clear local state before reload
  CURRENT_USER = null;
  USER_ROLES = [];
  USER_PERMS = [];
  location.reload();
}

async function loadCurrentUser() {
  const { data: { user }, error: userErr } = await sb.auth.getUser();
  if (userErr || !user) {
    console.warn('No authenticated user', userErr);
    return null;
  }

  try {
    const { data: profile, error } = await sb
      .from('profiles')
      .select('*, department:departments(*)')
      .eq('id', user.id)
      .single();
    if (error || !profile) {
      console.error('Profile load failed', error);
      toast('Your profile is not set up. Ask the IT admin.', 'error', 6000);
      return null;
    }

    // Load roles — if this fails, fall back to empty array but keep the session
    try {
      const { data: roles } = await sb
        .from('user_roles')
        .select('role:roles(code,name)')
        .eq('user_id', user.id);
      USER_ROLES = (roles||[]).map(r => r.role?.code).filter(Boolean);
    } catch(e) { console.warn('Roles load failed, defaulting to empty', e); USER_ROLES = []; }

    // Load permissions — same resilience
    try {
      const { data: rp } = await sb
        .from('role_permissions')
        .select('permission:permissions(code), role:roles!inner(code)')
        .in('role.code', USER_ROLES.length ? USER_ROLES : ['__none__']);
      USER_PERMS = [...new Set((rp||[]).map(r => r.permission?.code).filter(Boolean))];
    } catch(e) { console.warn('Perms load failed, defaulting to empty', e); USER_PERMS = []; }

    CURRENT_USER = profile;
    return profile;
  } catch(e) {
    console.error('loadCurrentUser unexpected error', e);
    toast('Could not load your profile. Please try again.', 'error', 6000);
    return null;
  }
}

async function bootstrap() {
  try {
    // Check MFA status first for returning sessions
    const mfaOK = await handleMfaIfNeeded();
    if (!mfaOK) return;  // MFA flow is showing, bootstrap will resume after verification

    const profile = await loadCurrentUser();
    if (!profile) {
      // Show login screen explicitly
      $('#loginScreen').style.display = 'grid';
      $('#app').classList.remove('show');
      return;
    }

    $('#loginScreen').style.display = 'none';
    $('#app').classList.add('show');
    $('#userName').textContent = profile.full_name;
    $('#userRole').textContent = USER_ROLES.join(', ') || 'staff';
    $('#userAvatar').textContent = initials(profile.full_name);

    if (isAdmin() || hasRole('it_manager')) $('#adminGroup').style.display = 'block';

    // Hide IT-Manager-only checklist items from engineers
    const canManageChk = isAdmin() || hasRole('it_manager');
    const tplBtn = document.querySelector('[data-view="chk-templates"]');
    if (tplBtn && !canManageChk) tplBtn.style.display = 'none';

  // Hide Review Queue from engineers (only reviewer sees it)
  const reviewBtn = document.querySelector('[data-view="chk-review-queue"]');
  if (reviewBtn && !canManageChk) reviewBtn.style.display = 'none';

  // Hide All Tasks (admin view) from engineers
  const allTasksBtn = document.querySelector('[data-view="chk-all-tasks"]');
  if (allTasksBtn && !canManageChk) allTasksBtn.style.display = 'none';

  // Hide Compliance from engineers (reports for managers)
  const compBtn = document.querySelector('[data-view="chk-compliance"]');
  if (compBtn && !canManageChk) compBtn.style.display = 'none';

    await Promise.all([refreshBadges(), route('dashboard')]);
  } catch(e) {
    console.error('Bootstrap failed', e);
    toast('Could not start the app. Check console for details.', 'error', 6000);
    $('#loginScreen').style.display = 'grid';
    $('#app').classList.remove('show');
  }
}

// =============================================================================
// ROUTING
// =============================================================================
async function route(view) {
  CURRENT_VIEW = view;
  $$('.nav-item').forEach(n => n.classList.toggle('active', n.dataset.view === view));
  const titles = {
    'dashboard': ['Dashboard', 'Workspace'],
    'my-requests': ['My Requests', 'Workspace'],
    'approvals': ['My Approvals', 'Workspace'],
    'notifications': ['Notifications', 'Workspace'],
    'new-change': ['New Change Request', 'New Request'],
    'new-sop': ['New SOP', 'New Request'],
    'new-leave': ['New Leave Request', 'New Request'],
    'new-overtime': ['New Overtime Request', 'New Request'],
    'new-comp': ['New Comp-Off Request', 'New Request'],
    'sop-library': ['SOP Library', 'Library'],
    'change-calendar': ['Change Calendar', 'Library'],
    'chk-my-tasks': ['My Checklist Tasks', 'Checklists'],
    'chk-all-tasks': ['All Checklist Tasks', 'Checklists'],
    'chk-review-queue': ['Review Queue', 'Checklists'],
    'chk-templates': ['Checklist Templates', 'Checklists'],
    'chk-compliance': ['Compliance Reports', 'Checklists'],
    'new-onboarding': ['New Onboarding', 'Governance'],
    'new-offboarding': ['New Offboarding', 'Governance'],
    'new-access': ['New Access Request', 'Governance'],
    'new-handover': ['New Asset Handover', 'Governance'],
    'onb-tasks': ['My Onboarding Tasks', 'Governance'],
    'assets-registry': ['Asset Registry', 'Governance'],
    'licenses': ['License Tracker', 'Governance'],
    'licenses-new': ['Add License', 'Governance'],
    'vendors': ['Vendors & AMC', 'Governance'],
    'dr-tracker': ['DR Tracker', 'Governance'],
    'capas': ['CAPA Register', 'Governance'],
    'branch-compliance': ['Branch Compliance', 'Governance'],
    'all-requests': ['All Requests', 'Admin'],
    'reports': ['Reports', 'Admin']
  };
  const [title, crumb] = titles[view] || ['', ''];
  $('#pageTitle').textContent = title;
  $('#crumbs').textContent = `FFC IT · ${crumb}`;
  $('#viewContent').innerHTML = '<div class="loading">Loading…</div>';

  try {
    switch (view) {
      case 'dashboard': await renderDashboard(); break;
      case 'my-requests': await renderMyRequests(); break;
      case 'approvals': await renderApprovals(); break;
      case 'notifications': await renderNotifications(); break;
      case 'new-change': renderNewChange(); break;
      case 'new-sop': renderNewSop(); break;
      case 'new-leave': await renderNewLeave(); break;
      case 'new-overtime': renderNewOvertime(); break;
      case 'new-comp': await renderNewComp(); break;
      case 'sop-library': await renderSopLibrary(); break;
      case 'change-calendar': await renderChangeCalendar(); break;
      case 'it-projects': await renderITProjects(); break;
      case 'chk-my-tasks': await renderMyChecklistTasks(); break;
      case 'chk-all-tasks': await renderAllChecklistTasks(); break;
      case 'chk-review-queue': await renderChecklistReviewQueue(); break;
      case 'chk-templates':
        if (!isAdmin() && !hasRole('it_manager')) {
          $('#viewContent').innerHTML = '<div class="empty"><h4>Restricted</h4><p>Templates are managed by IT Manager only.</p></div>';
          return;
        }
        await renderChecklistTemplates(); break;
      case 'chk-compliance': await renderChecklistCompliance(); break;
      case 'new-onboarding': renderNewOnboarding('onboarding'); break;
      case 'new-offboarding': renderNewOnboarding('offboarding'); break;
      case 'new-access': await renderNewAccess(); break;
      case 'new-handover': await renderNewHandover(); break;
      case 'onb-tasks': await renderMyOnboardingTasks(); break;
      case 'assets-registry': await renderAssetsRegistry(); break;
      case 'licenses': await renderLicenses(); break;
      case 'licenses-new': renderLicenseForm(); break;
      case 'vendors': await renderVendors(); break;
      case 'dr-tracker': await renderDRTracker(); break;
      case 'capas': await renderCAPAs(); break;
      case 'branch-compliance': await renderBranchCompliance(); break;
      case 'all-requests': await renderAllRequests(); break;
      case 'reports': await renderReports(); break;
    }
  } catch (e) {
    console.error(e);
    $('#viewContent').innerHTML = `<div class="empty"><h4>Could not load</h4><p>${escape(e.message)}</p></div>`;
  }
}

// =============================================================================
// BADGES / NOTIFS POLLING
// =============================================================================
async function refreshBadges() {
  try {
    const { data: m } = await sb.rpc('dashboard_metrics');
    if (m) {
      setBadge('approvalBadge', m.awaiting_my_approval);
      setBadge('notifBadge',    m.unread_notifications);
    }
    const { data: c } = await sb.rpc('checklist_metrics');
    if (c) {
      setBadge('chkMyBadge',    c.my_pending + c.my_overdue);
      setBadge('chkRevBadge',   c.awaiting_my_review);
    }
  } catch(e) { console.warn(e); }
}
const setBadge = (id, n) => {
  const el = $('#'+id);
  if (!el) return;
  el.textContent = n || 0;
  el.dataset.zero = (!n || n === 0) ? 'true' : 'false';
};

// =============================================================================
// VIEW: DASHBOARD
// =============================================================================
async function renderDashboard() {
  const today = new Date();
  const todayISO = today.toISOString().slice(0,10);
  const startOfToday = new Date(today.getFullYear(), today.getMonth(), today.getDate()).toISOString();
  const in30d = new Date(Date.now() + 30*86400000).toISOString().slice(0,10);

  const isMgr = isAdmin() || hasRole('it_manager');

  // ===== PHASE 1: Render skeleton IMMEDIATELY with placeholder cards =====
  // This means the user sees the layout in <50ms, not waiting for all queries
  $('#viewContent').innerHTML = `
    <div id="dashAlertSlot"></div>

    <div class="stats-grid" id="dashStatsMine">
      <div class="stat accent"><div class="label">My Approvals</div><div class="value">—</div><div class="sub">&nbsp;</div></div>
      <div class="stat"><div class="label">My Checklists</div><div class="value">—</div><div class="sub">&nbsp;</div></div>
      <div class="stat"><div class="label">My CAPAs</div><div class="value">0</div><div class="sub">none overdue</div></div>
      <div class="stat"><div class="label">My Onb. Tasks</div><div class="value">0</div><div class="sub">assigned to me</div></div>
      <div class="stat"><div class="label">Unread</div><div class="value">—</div><div class="sub">&nbsp;</div></div>
    </div>

    ${isMgr ? `
    <div class="stats-grid" id="dashStatsOrg" style="margin-top:0">
      <div class="stat"><div class="label">Requests In Flight</div><div class="value">—</div><div class="sub">&nbsp;</div></div>
      <div class="stat"><div class="label">Critical CAPAs</div><div class="value">—</div><div class="sub">&nbsp;</div></div>
      <div class="stat"><div class="label">Licenses Expiring</div><div class="value">—</div><div class="sub">&nbsp;</div></div>
      <div class="stat"><div class="label">Vendor Contracts</div><div class="value">—</div><div class="sub">&nbsp;</div></div>
      <div class="stat"><div class="label">DR Tests</div><div class="value">—</div><div class="sub">&nbsp;</div></div>
    </div>` : ''}

    <div style="display:grid;grid-template-columns:1.3fr 1fr;gap:16px;margin-top:16px" id="dashGrid">
      <div style="display:flex;flex-direction:column;gap:16px">
        ${isMgr ? `
        <div class="panel" id="dashActivityPanel">
          <div class="panel-head"><h3>Today's activity</h3></div>
          <div class="panel-body" style="padding:14px 20px"><p style="color:var(--muted);font-size:12px">Loading…</p></div>
        </div>
        <div class="panel" id="dashExpiringPanel">
          <div class="panel-head"><h3>Expiring soon — next 30 days</h3></div>
          <div class="panel-body" style="padding:14px 20px"><p style="color:var(--muted);font-size:12px">Loading…</p></div>
        </div>
        <div class="panel" id="dashOverduePanel">
          <div class="panel-head"><h3>Overdue across org</h3></div>
          <div class="panel-body" style="padding:14px 20px"><p style="color:var(--muted);font-size:12px">Loading…</p></div>
        </div>` : ''}
      </div>
      <div style="display:flex;flex-direction:column;gap:16px">
        <div class="panel" id="dashApprovalsPanel" style="display:none">
          <div class="panel-head"><h3>Awaiting your decision</h3>
            <div class="right"><button class="btn secondary btn-sm" data-goto="approvals">View all</button></div>
          </div>
          <div class="panel-body" style="padding:8px 14px" id="dashApprovalsBody"></div>
        </div>
        <div class="panel" id="dashChkPanel" style="display:none">
          <div class="panel-head"><h3>My checklist tasks</h3>
            <div class="right"><button class="btn secondary btn-sm" data-goto="chk-my-tasks">View all</button></div>
          </div>
          <div class="panel-body" style="padding:8px 14px" id="dashChkBody"></div>
        </div>
        <div class="panel" id="dashOnbPanel" style="display:none">
          <div class="panel-head"><h3>My onboarding tasks</h3>
            <div class="right"><button class="btn secondary btn-sm" data-goto="onb-tasks">View all</button></div>
          </div>
          <div class="panel-body" style="padding:8px 14px" id="dashOnbBody"></div>
        </div>
        <div class="panel">
          <div class="panel-head"><h3>My recent requests</h3>
            <div class="right"><button class="btn secondary btn-sm" data-goto="my-requests">View all</button></div>
          </div>
          <div class="panel-body" style="padding:8px 14px" id="dashRecentBody">
            <p style="color:var(--muted);font-size:12px;padding:10px 0">Loading…</p>
          </div>
        </div>
        ${isMgr ? `<div id="dashTeamPresence"></div>` : ''}
      </div>
    </div>
  `;

  // Wire navigation immediately (works even before data loads)
  $$('[data-goto]').forEach(b => b.addEventListener('click', () => route(b.dataset.goto)));

  // ===== PHASE 2: Fire essential queries, render top stats FIRST =====
  const metricsPromises = [
    sb.rpc('dashboard_metrics'),
    sb.rpc('checklist_metrics')
  ];

  const personalQueries = [
    sb.from('request_approvals')
      .select('id, due_at, decision, request:request_master(id, ref_no, title, module, status, priority, created_at)')
      .eq('approver_id', CURRENT_USER.id).eq('decision', 'pending')
      .order('due_at', { ascending: true, nullsFirst: false }).limit(5),
    sb.from('request_master').select('id, ref_no, title, module, status, created_at')
      .eq('requester_id', CURRENT_USER.id)
      .order('created_at', { ascending: false }).limit(5),
    sb.from('checklist_instances').select('id, instance_code, name_snapshot, period_label, status, due_at')
      .eq('assigned_to', CURRENT_USER.id)
      .in('status', ['pending','in_progress','overdue','escalated'])
      .order('due_at', { ascending: true }).limit(8),
    sb.from('onboarding_tasks').select('id, task_title, status, onb:onboarding_requests(employee_full_name, request_type)')
      .eq('assigned_to', CURRENT_USER.id)
      .in('status', ['pending','in_progress']).limit(8),
    // My CAPAs count — personal, fast, doesn't need manager RPC
    sb.from('capas').select('id, status, target_date')
      .eq('owner_id', CURRENT_USER.id)
      .in('status', ['open','assigned','in_progress','pending_evidence','pending_verification','overdue']),
  ];

  // Render top stats as soon as metrics arrive (fastest queries)
  Promise.allSettled(metricsPromises).then(results => {
    const m = results[0]?.value?.data || {};
    const mc = results[1]?.value?.data || {};
    const statsMine = $('#dashStatsMine');
    if (statsMine) {
      statsMine.innerHTML = `
        <div class="stat accent">
          <div class="label">My Approvals</div>
          <div class="value">${m.awaiting_my_approval ?? 0}</div>
          <div class="sub">${m.overdue_approvals ?? 0} overdue</div>
        </div>
        <div class="stat ${(mc.my_overdue||0) > 0 ? 'danger' : ''}">
          <div class="label">My Checklists</div>
          <div class="value">${(mc.my_pending ?? 0) + (mc.my_overdue ?? 0)}</div>
          <div class="sub">${mc.my_overdue ?? 0} overdue · ${mc.my_today ?? 0} today</div>
        </div>
        <div class="stat">
          <div class="label">My CAPAs</div>
          <div class="value">0</div>
          <div class="sub">none overdue</div>
        </div>
        <div class="stat">
          <div class="label">My Onb. Tasks</div>
          <div class="value">0</div>
          <div class="sub">assigned to me</div>
        </div>
        <div class="stat ${(m.unread_notifications||0) > 0 ? 'warn' : ''}">
          <div class="label">Unread</div>
          <div class="value">${m.unread_notifications ?? 0}</div>
          <div class="sub">notifications</div>
        </div>
      `;
    }
  });

  // Render personal queues as they arrive
  Promise.allSettled(personalQueries).then(results => {
    const pending    = results[0]?.value?.data || [];
    const myRecent   = results[1]?.value?.data || [];
    const myChkToday = results[2]?.value?.data || [];
    const myOnbTasks = results[3]?.value?.data || [];
    const myCapas    = results[4]?.value?.data || [];

    const myCapasOpen    = myCapas.length;
    const myCapasOverdue = myCapas.filter(c => c.status === 'overdue' || (c.target_date && new Date(c.target_date) < new Date())).length;

    // Update ALL 5 personal stat cards at once — no more loading placeholders
    const statsMine = $('#dashStatsMine');
    if (statsMine) {
      // Get current content to preserve approvals + checklists from phase 1 metrics
      // Just update the CAPAs and Onb cards (positions 3 and 4)
      const cards = statsMine.querySelectorAll('.stat');
      if (cards.length >= 4) {
        // My CAPAs card
        cards[2].className = 'stat' + (myCapasOverdue > 0 ? ' danger' : '');
        cards[2].innerHTML = `
          <div class="label">My CAPAs</div>
          <div class="value">${myCapasOpen}</div>
          <div class="sub">${myCapasOverdue > 0 ? myCapasOverdue + ' overdue' : 'none overdue'}</div>
        `;
        // My Onb Tasks card
        cards[3].className = 'stat';
        cards[3].innerHTML = `
          <div class="label">My Onb. Tasks</div>
          <div class="value">${myOnbTasks.length}</div>
          <div class="sub">assigned to me</div>
        `;
      }
    }

    // Approvals panel
    if (pending.length) {
      $('#dashApprovalsPanel').style.display = '';
      $('#dashApprovalsBody').innerHTML = pending.map(a => miniApprovalRow(a)).join('');
    }

    // Checklist panel
    if (myChkToday.length) {
      $('#dashChkPanel').style.display = '';
      $('#dashChkBody').innerHTML = myChkToday.map(c => miniChkRow(c)).join('');
    }

    // Onboarding panel
    if (myOnbTasks.length) {
      $('#dashOnbPanel').style.display = '';
      $('#dashOnbBody').innerHTML = myOnbTasks.map(t => miniOnbTaskRow(t)).join('');
    }

    // Recent requests
    const recentBody = $('#dashRecentBody');
    if (recentBody) {
      recentBody.innerHTML = myRecent.length
        ? myRecent.map(r => miniRequestRow(r)).join('')
        : '<p style="color:var(--muted);font-size:12.5px;padding:10px 0">No requests yet.</p>';
    }

    // Wire click handlers
    $$('[data-open-request]').forEach(b => b.addEventListener('click', () => openRequest(b.dataset.openRequest)));
    $$('[data-open-chk]').forEach(b => b.addEventListener('click', () => openChecklistInstance(b.dataset.openChk)));
    $$('[data-open-onb-task]').forEach(b => b.addEventListener('click', () => openOnbTask(b.dataset.openOnbTask)));

    // Load team presence widget for managers (non-blocking)
    if (isMgr) {
      const presenceSlot = $('#dashTeamPresence');
      if (presenceSlot) {
        renderTeamPresenceWidget().then(html => {
          if (presenceSlot) presenceSlot.innerHTML = html;
        });
      }
    }
  });

  // ===== PHASE 3: Manager-only queries (fire last, lowest priority) =====
  if (!isMgr) return;   // Engineers: we're done

  const mgrMetricsPromises = [
    sb.rpc('governance_metrics'),
    sb.rpc('governance2_metrics')
  ];

  const mgrListPromises = [
    sb.from('request_history')
      .select('action, occurred_at, actor:profiles(full_name), request:request_master(ref_no, title, module, status)')
      .gte('occurred_at', startOfToday)
      .order('occurred_at', { ascending: false }).limit(15),
    sb.from('license_items').select('id, item_name, vendor, item_code, expiry_date')
      .in('status', ['active','expiring_soon'])
      .lte('expiry_date', in30d)
      .order('expiry_date', { ascending: true }).limit(10),
    sb.from('vendor_contracts').select('id, contract_title, contract_code, end_date, vendor:vendors(name)')
      .in('status', ['active','expiring_soon'])
      .lte('end_date', in30d)
      .order('end_date', { ascending: true }).limit(10),
    sb.from('dr_services').select('id, service_name, service_code, criticality, next_test_due')
      .eq('is_active', true)
      .lte('next_test_due', in30d)
      .order('next_test_due', { ascending: true }).limit(10),
    sb.from('capas').select('id, capa_code, title, severity, target_date, owner:profiles!capas_owner_id_fkey(full_name)')
      .in('status', ['open','assigned','in_progress','pending_evidence','pending_verification','overdue'])
      .lte('target_date', todayISO)
      .order('target_date', { ascending: true }).limit(10),
    sb.from('checklist_instances').select('id, instance_code, name_snapshot, due_at, assignee:profiles!checklist_instances_assigned_to_fkey(full_name)')
      .in('status', ['overdue','escalated'])
      .order('due_at', { ascending: true }).limit(10)
  ];

  // Render org stats as soon as they arrive
  Promise.allSettled(mgrMetricsPromises).then(results => {
    const mg = results[0]?.value?.data || {};
    const mg2 = results[1]?.value?.data || {};
    const statsOrg = $('#dashStatsOrg');
    if (statsOrg) {
      statsOrg.innerHTML = `
        <div class="stat">
          <div class="label">Requests In Flight</div>
          <div class="value">${(mg.onb_open ?? 0) + (mg.access_open ?? 0) + (mg.handover_open ?? 0)}</div>
          <div class="sub">onboarding · access · handover</div>
        </div>
        <div class="stat ${(mg2.capas_critical_open||0) > 0 ? 'danger' : ''}">
          <div class="label">Critical CAPAs</div>
          <div class="value">${mg2.capas_critical_open ?? 0}</div>
          <div class="sub">${mg2.capas_total_open ?? 0} total open</div>
        </div>
        <div class="stat warn">
          <div class="label">Licenses Expiring</div>
          <div class="value">${mg.licenses_expiring_soon ?? 0}</div>
          <div class="sub">${mg.licenses_expired ?? 0} expired</div>
        </div>
        <div class="stat warn">
          <div class="label">Vendor Contracts</div>
          <div class="value">${mg2.vendor_contracts_expiring ?? 0}</div>
          <div class="sub">expiring soon</div>
        </div>
        <div class="stat ${(mg2.dr_tests_overdue||0) > 0 ? 'danger' : ''}">
          <div class="label">DR Tests</div>
          <div class="value">${mg2.dr_tests_overdue ?? 0}</div>
          <div class="sub">overdue · ${mg2.dr_tests_upcoming ?? 0} upcoming</div>
        </div>
      `;
    }

    // Also update "My CAPAs" card in personal stats
    const statCards = document.querySelectorAll('#dashStatsMine .stat');
    if (statCards.length >= 3) {
      const capaCard = statCards[2];
      if (capaCard) {
        capaCard.className = 'stat' + ((mg2.my_capas_overdue||0) > 0 ? ' danger' : '');
        capaCard.innerHTML = `
          <div class="label">My CAPAs</div>
          <div class="value">${mg2.my_capas_open ?? 0}</div>
          <div class="sub">${mg2.my_capas_overdue ?? 0} overdue</div>
        `;
      }
    }

    // Show alert banner if things need attention
    const { data: mTop } = { data: {} };  // not perfect but close enough
    const needsAttention = (mg2.my_capas_overdue||0);
    if (needsAttention > 0) {
      const slot = $('#dashAlertSlot');
      if (slot) slot.innerHTML = `
        <div style="background:linear-gradient(90deg,#fff5eb,#fdedd5);border:1px solid #f5a02a;border-radius:8px;padding:12px 16px;margin-bottom:14px;display:flex;align-items:center;gap:12px">
          <div style="width:30px;height:30px;border-radius:50%;background:#F5A02A;color:white;display:flex;align-items:center;justify-content:center;font-weight:600">!</div>
          <div style="flex:1">
            <div style="font-weight:600;color:#7a4a10;font-size:13px">${needsAttention} item${needsAttention!==1?'s':''} need${needsAttention===1?'s':''} your attention</div>
            <div style="font-size:11.5px;color:#9a6520">Overdue CAPAs</div>
          </div>
        </div>`;
    }
  });

  // Render manager panels as they arrive
  Promise.allSettled(mgrListPromises).then(results => {
    const todayActivity = results[0]?.value?.data || [];
    // ... remaining file content continues unchanged ...
