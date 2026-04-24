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
  if (!email || !password) { showLoginErr('Enter email and password.'); return; }
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
      const isNetworkError = e.message?.includes('fetch') ||
                             e.message?.includes('network') ||
                             e.message?.includes('NetworkError') ||
                             e.name === 'TypeError';

      if (isNetworkError && attempt < 3) {
        // Wait a bit longer each retry (1s → 2s → 4s) for cold-start warmup
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
        msg = 'Cannot connect to the server. Check your internet connection and try again.';
      } else if (msg.includes('Invalid login') || msg.includes('credentials')) {
        msg = 'Email or password is incorrect.';
      }
      showLoginErr(msg);
      return;
    }

    // FIX: No MFA check here — bootstrap() handles it
    // FIX: logAuthEvent is fire-and-forget — don't await it on the critical path
    logAuthEvent('login'); // intentionally not awaited

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
    // FIX: Run profile + roles + permissions ALL IN PARALLEL
    // Previous code was fully sequential: getUser → profile → roles → perms
    // Now it's one round trip for all three
    const [profileRes, rolesRes, permsRes] = await Promise.all([
      sb.from('profiles')
        .select('*, department:departments(*)')
        .eq('id', user.id)
        .single(),
      sb.from('user_roles')
        .select('role:roles(code,name)')
        .eq('user_id', user.id),
      sb.from('role_permissions')
        .select('permission:permissions(code), role:roles!inner(code)')
        .neq('role.code', '__none__')   // get all — filter by role below
    ]);

    const profile = profileRes.data;
    if (profileRes.error || !profile) {
      console.error('Profile load failed', profileRes.error);
      toast('Your profile is not set up. Ask the IT admin.', 'error', 6000);
      return null;
    }

    // Set roles
    USER_ROLES = (rolesRes.data || []).map(r => r.role?.code).filter(Boolean);

    // Filter permissions to only those matching this user's roles
    USER_PERMS = [...new Set(
      (permsRes.data || [])
        .filter(r => USER_ROLES.includes(r.role?.code))
        .map(r => r.permission?.code)
        .filter(Boolean)
    )];

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
    // FIX: MFA check only happens here (removed duplicate from login())
    // login() calls bootstrap() directly after sign-in
    // bootstrap() handles MFA for returning sessions (page refresh)
    const mfaOK = await handleMfaIfNeeded();
    if (!mfaOK) return;

    const profile = await loadCurrentUser();
    if (!profile) {
      $('#loginScreen').style.display = 'grid';
      $('#app').classList.remove('show');
      return;
    }

    // FIX: Show app shell IMMEDIATELY after profile loads
    // Don't wait for badges or dashboard — show the UI now
    $('#loginScreen').style.display = 'none';
    $('#app').classList.add('show');
    $('#userName').textContent = profile.full_name;
    $('#userRole').textContent = USER_ROLES.join(', ') || 'staff';
    $('#userAvatar').textContent = initials(profile.full_name);

    if (isAdmin() || hasRole('it_manager')) $('#adminGroup').style.display = 'block';

    const canManageChk = isAdmin() || hasRole('it_manager');
    const tplBtn = document.querySelector('[data-view="chk-templates"]');
    if (tplBtn && !canManageChk) tplBtn.style.display = 'none';
    const reviewBtn = document.querySelector('[data-view="chk-review-queue"]');
    if (reviewBtn && !canManageChk) reviewBtn.style.display = 'none';
    const allTasksBtn = document.querySelector('[data-view="chk-all-tasks"]');
    if (allTasksBtn && !canManageChk) allTasksBtn.style.display = 'none';
    const compBtn = document.querySelector('[data-view="chk-compliance"]');
    if (compBtn && !canManageChk) compBtn.style.display = 'none';

    // FIX: Route to dashboard immediately, fire badges in background
    // No more waiting for both to finish before showing anything
    route('dashboard');
    refreshBadges(); // fire and forget — don't await

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
      case 'it-agent': await renderITAgent(); break;
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
    const licExp        = results[1]?.value?.data || [];
    const vendorExp     = results[2]?.value?.data || [];
    const drDue         = results[3]?.value?.data || [];
    const overdueCapas  = results[4]?.value?.data || [];
    const overdueChk    = results[5]?.value?.data || [];

    // Today's activity
    const actPanel = $('#dashActivityPanel');
    if (actPanel) {
      actPanel.querySelector('.panel-body').innerHTML = todayActivity.length
        ? `<div class="activity-feed">${todayActivity.slice(0, 15).map(h => activityItem(h)).join('')}</div>`
        : '<p style="color:var(--muted);font-size:12.5px;padding:10px 0">No activity yet today.</p>';
    }

    // Expiring soon
    const expPanel = $('#dashExpiringPanel');
    if (expPanel) expPanel.querySelector('.panel-body').innerHTML = renderExpiringSoon(licExp, vendorExp, drDue);

    // Overdue panel — hide if nothing
    const ovrPanel = $('#dashOverduePanel');
    if (ovrPanel) {
      if (overdueCapas.length === 0 && overdueChk.length === 0) {
        ovrPanel.style.display = 'none';
      } else {
        ovrPanel.querySelector('.panel-body').innerHTML = renderOverdueList(overdueCapas, overdueChk);
      }
    }

    // Wire all click handlers on the new content
    $$('[data-open-request]').forEach(b => b.addEventListener('click', () => openRequest(b.dataset.openRequest)));
    $$('[data-open-chk]').forEach(b => b.addEventListener('click', () => openChecklistInstance(b.dataset.openChk)));
    $$('[data-open-onb-task]').forEach(b => b.addEventListener('click', () => openOnbTask(b.dataset.openOnbTask)));
    $$('[data-open-lic]').forEach(b => b.addEventListener('click', () => openLicenseEditor(b.dataset.openLic)));
    $$('[data-open-contract]').forEach(b => b.addEventListener('click', () => openContractEditor(b.dataset.openContract)));
    $$('[data-open-drsvc]').forEach(b => b.addEventListener('click', () => openDRService(b.dataset.openDrsvc, isMgr)));
    $$('[data-open-capa]').forEach(b => b.addEventListener('click', () => openCAPAEditor(b.dataset.openCapa)));
  });
}
// ---- Dashboard helper renderers ----

function activityItem(h) {
  const req = h.request;
  const actor = h.actor?.full_name || 'System';
  const actionLabel = (h.action || '').replace(/_/g, ' ');
  const time = fmtRel(h.occurred_at);
  const modIcon = ({
    change_request:'◈', sop:'§', leave:'☾', overtime:'⊕', comp_off:'⊖',
    onboarding:'⚑', offboarding:'⚐', access_request:'◎', asset_handover:'⬡'
  })[req?.module] || '•';

  return `<div class="activity-row" ${req ? `data-open-request="${req?.id||''}" style="cursor:pointer"` : ''}>
    <div class="activity-icon">${modIcon}</div>
    <div class="activity-main">
      <div class="activity-line"><b>${escape(actor)}</b> ${escape(actionLabel)}${req?.ref_no ? ` <span class="mono" style="color:var(--muted)">· ${escape(req.ref_no)}</span>` : ''}</div>
      ${req?.title ? `<div class="activity-title">${escape(req.title)}</div>` : ''}
    </div>
    <div class="activity-time mono">${time}</div>
  </div>`;
}

function miniApprovalRow(a) {
  const r = a.request;
  if (!r) return '';
  const due = a.due_at ? Math.floor((new Date(a.due_at) - new Date())/86400000) : null;
  return `<div class="mini-row" data-open-request="${r.id}">
    <div class="mini-main">
      <div class="mini-title">${escape(r.title || r.ref_no)}</div>
      <div class="mini-sub mono">${escape(r.ref_no)} · ${escape(moduleLabel(r.module))}</div>
    </div>
    <div class="mini-right">
      ${due !== null ? `<span class="status ${due<0?'s-rejected':due<=1?'s-pending_approval':'s-in_progress'}" style="font-size:10px"><span class="dot"></span>${due<0?`${Math.abs(due)}d overdue`:`${due}d`}</span>` : ''}
    </div>
  </div>`;
}

function miniRequestRow(r) {
  return `<div class="mini-row" data-open-request="${r.id}">
    <div class="mini-main">
      <div class="mini-title">${escape(r.title || r.ref_no)}</div>
      <div class="mini-sub mono">${escape(r.ref_no)} · ${escape(moduleLabel(r.module))} · ${fmtRel(r.created_at)}</div>
    </div>
    <div class="mini-right">
      <span class="status s-${r.status}" style="font-size:10px"><span class="dot"></span>${escape(statusLabel(r.status))}</span>
    </div>
  </div>`;
}

function miniChkRow(c) {
  const overdue = c.status === 'overdue' || c.status === 'escalated';
  return `<div class="mini-row" data-open-chk="${c.id}">
    <div class="mini-main">
      <div class="mini-title">${escape(c.name_snapshot)}</div>
      <div class="mini-sub mono">${escape(c.instance_code)} · ${escape(c.period_label || '')}</div>
    </div>
    <div class="mini-right">
      <span class="status ${overdue?'s-rejected':'s-pending_approval'}" style="font-size:10px"><span class="dot"></span>${fmtRel(c.due_at)}</span>
    </div>
  </div>`;
}

function miniOnbTaskRow(t) {
  return `<div class="mini-row" data-open-onb-task="${t.id}">
    <div class="mini-main">
      <div class="mini-title">${escape(t.task_title)}</div>
      <div class="mini-sub">For ${escape(t.onb?.employee_full_name || '—')} · ${escape(t.onb?.request_type || '')}</div>
    </div>
    <div class="mini-right">
      <span class="status s-${t.status==='in_progress'?'in_progress':'pending_approval'}" style="font-size:10px"><span class="dot"></span>${escape(t.status)}</span>
    </div>
  </div>`;
}

function renderExpiringSoon(licenses, contracts, drServices) {
  const items = [];

  licenses.forEach(l => {
    const days = Math.floor((new Date(l.expiry_date) - new Date())/86400000);
    items.push({
      sortKey: days, type: 'License', icon: '§',
      title: l.item_name, sub: `${l.vendor} · ${l.item_code}`,
      days, dataAttr: `data-open-lic="${l.id}"`
    });
  });

  contracts.forEach(c => {
    const days = Math.floor((new Date(c.end_date) - new Date())/86400000);
    items.push({
      sortKey: days, type: 'Contract', icon: '⌘',
      title: c.contract_title, sub: `${c.vendor?.name || ''} · ${c.contract_code}`,
      days, dataAttr: `data-open-contract="${c.id}"`
    });
  });

  drServices.forEach(s => {
    const days = s.next_test_due ? Math.floor((new Date(s.next_test_due) - new Date())/86400000) : null;
    items.push({
      sortKey: days ?? 999, type: 'DR Test', icon: '◎',
      title: s.service_name, sub: `${s.service_code} · ${s.criticality}`,
      days, dataAttr: `data-open-drsvc="${s.id}"`
    });
  });

  if (items.length === 0) {
    return '<p style="color:var(--muted);font-size:12.5px;padding:10px 0">Nothing expiring in the next 30 days.</p>';
  }

  items.sort((a, b) => a.sortKey - b.sortKey);

  return items.slice(0, 12).map(item => {
    const color = item.days < 0 ? 'var(--red-deep)' : item.days < 7 ? 'var(--orange-deep)' : 'var(--ink)';
    const daysText = item.days < 0 ? `${Math.abs(item.days)}d overdue` : `${item.days}d left`;
    return `<div class="mini-row" ${item.dataAttr}>
      <div class="mini-main">
        <div class="mini-title">
          <span style="display:inline-block;width:18px;color:var(--muted)">${item.icon}</span>
          ${escape(item.title)}
          <span style="font-size:10px;color:var(--muted);margin-left:6px">${item.type}</span>
        </div>
        <div class="mini-sub">${escape(item.sub)}</div>
      </div>
      <div class="mini-right mono" style="color:${color};font-size:11px;font-weight:600">${daysText}</div>
    </div>`;
  }).join('');
}

function renderOverdueList(capas, checklists) {
  const items = [];
  capas.forEach(c => {
    const days = c.target_date ? Math.floor((new Date() - new Date(c.target_date))/86400000) : 0;
    items.push({
      sortKey: -days, type: 'CAPA', icon: '⚠',
      title: c.title, sub: `${c.capa_code} · ${c.owner?.full_name || 'unassigned'}`,
      days, severity: c.severity, dataAttr: `data-open-capa="${c.id}"`
    });
  });
  checklists.forEach(c => {
    const days = c.due_at ? Math.floor((new Date() - new Date(c.due_at))/86400000) : 0;
    items.push({
      sortKey: -days, type: 'Checklist', icon: '✓',
      title: c.name_snapshot, sub: `${c.instance_code} · ${c.assignee?.full_name || 'unassigned'}`,
      days, dataAttr: `data-open-chk="${c.id}"`
    });
  });

  if (items.length === 0) return '<p style="color:var(--muted);font-size:12.5px;padding:10px 0">Nothing overdue. Good job!</p>';

  items.sort((a, b) => a.sortKey - b.sortKey);  // most overdue first

  return items.slice(0, 10).map(item => {
    const sevColor = item.severity === 'critical' ? 'var(--red-deep)' : item.severity === 'high' ? 'var(--orange-deep)' : 'var(--ink)';
    return `<div class="mini-row" ${item.dataAttr}>
      <div class="mini-main">
        <div class="mini-title">
          <span style="display:inline-block;width:18px;color:var(--red-deep)">${item.icon}</span>
          ${escape(item.title)}
          ${item.severity ? `<span style="font-size:10px;color:${sevColor};margin-left:6px;text-transform:uppercase">${item.severity}</span>` : ''}
          <span style="font-size:10px;color:var(--muted);margin-left:6px">${item.type}</span>
        </div>
        <div class="mini-sub">${escape(item.sub)}</div>
      </div>
      <div class="mini-right mono" style="color:var(--red-deep);font-size:11px;font-weight:600">${item.days}d overdue</div>
    </div>`;
  }).join('');
}

function openRequest(requestId) {
  // Reuse existing drawer logic — navigate to the relevant list then open
  // Simpler: just jump to the request directly via my-requests or approvals view
  // For now, open the drawer by triggering the existing openRequestDrawer pattern
  if (typeof openRequestDrawer === 'function') return openRequestDrawer(requestId);
  // Fallback: go to my-requests and let user click
  route('my-requests');
}

function renderRowsHeader() {
  return `<div class="req-row head">
    <div>Ref</div><div>Title</div><div>Module</div><div>Status</div><div>Updated</div><div></div>
  </div>`;
}
function reqRow(r) {
  return `<div class="req-row" data-req="${r.id}">
    <div class="req-id">${escape(r.ref_no)}</div>
    <div class="req-title">${escape(r.title)}${r.summary?`<small>${escape(r.summary)}</small>`:''}</div>
    <div class="req-cell"><span class="module-pill m-${r.module}">${moduleLabel(r.module)}</span></div>
    <div class="req-cell"><span class="status s-${r.status}"><span class="dot"></span>${statusLabel(r.status)}</span></div>
    <div class="req-cell mono">${fmtRel(r.updated_at || r.created_at)}</div>
    <div class="req-cell" style="text-align:right">›</div>
  </div>`;
}
function reqRowApproval(a) {
  const r = a.request;
  const overdue = a.due_at && new Date(a.due_at) < new Date();
  return `<div class="req-row" data-req="${r.id}">
    <div class="req-id">${escape(r.ref_no)}</div>
    <div class="req-title">${escape(r.title)}<small>Step ${a.step_no} — ${escape(a.step_name)}</small></div>
    <div class="req-cell"><span class="module-pill m-${r.module}">${moduleLabel(r.module)}</span></div>
    <div class="req-cell"><span class="status s-${r.status}"><span class="dot"></span>${statusLabel(r.status)}</span></div>
    <div class="req-cell mono" ${overdue?'style="color:var(--red-deep)"':''}>${a.due_at ? (overdue?'Overdue · ':'Due ') + fmtRel(a.due_at) : '—'}</div>
    <div class="req-cell" style="text-align:right">›</div>
  </div>`;
}
const emptyRow = (msg) => `<div class="empty"><p>${msg}</p></div>`;

function wireRows() {
  $$('[data-req]').forEach(el => el.addEventListener('click', () => openDrawer(el.dataset.req)));
  $$('[data-goto]').forEach(el => el.addEventListener('click', () => route(el.dataset.goto)));
}

// =============================================================================
// VIEW: MY REQUESTS
// =============================================================================
async function renderMyRequests() {
  const { data } = await sb
    .from('request_master')
    .select('*')
    .eq('requester_id', CURRENT_USER.id)
    .order('created_at', { ascending: false });

  $('#viewContent').innerHTML = `
    <div class="filter-bar">
      <select id="fltModule"><option value="">All modules</option>
        <option value="change_request">Change</option><option value="sop">SOP</option>
        <option value="leave">Leave</option><option value="overtime">Overtime</option>
        <option value="comp_off">Comp Off</option></select>
      <select id="fltStatus"><option value="">All statuses</option>
        <option value="draft">Draft</option><option value="submitted">Submitted</option>
        <option value="pending_approval">Pending</option><option value="approved">Approved</option>
        <option value="rejected">Rejected</option><option value="scheduled">Scheduled</option>
        <option value="completed">Completed</option></select>
      <input id="fltSearch" placeholder="Search by title or ref no…" />
      <span class="count" id="resultCount">${(data||[]).length} records</span>
    </div>
    <div class="panel"><div class="panel-body" id="reqList">
      ${renderRowsHeader()}
      ${(data||[]).length ? data.map(reqRow).join('') : emptyRow('No requests yet — start a new one from the left.')}
    </div></div>
  `;
  wireRows();

  const applyFilters = () => {
    const m = $('#fltModule').value;
    const s = $('#fltStatus').value;
    const q = $('#fltSearch').value.toLowerCase().trim();
    const filtered = (data||[]).filter(r =>
      (!m || r.module === m) && (!s || r.status === s) &&
      (!q || r.title.toLowerCase().includes(q) || r.ref_no.toLowerCase().includes(q))
    );
    $('#reqList').innerHTML = renderRowsHeader() + (filtered.length ? filtered.map(reqRow).join('') : emptyRow('No matching requests'));
    $('#resultCount').textContent = `${filtered.length} records`;
    wireRows();
  };
  ['fltModule','fltStatus','fltSearch'].forEach(id => $('#'+id).addEventListener('input', applyFilters));
}

// =============================================================================
// VIEW: APPROVALS
// =============================================================================
async function renderApprovals() {
  const { data } = await sb
    .from('request_approvals')
    .select('*, request:request_master(*)')
    .eq('approver_id', CURRENT_USER.id)
    .order('decided_at', { ascending: false, nullsFirst: true });

  const pending = (data||[]).filter(a => a.decision === 'pending');
  const done = (data||[]).filter(a => a.decision !== 'pending');

  $('#viewContent').innerHTML = `
    <div class="panel">
      <div class="panel-head"><h3>Pending — ${pending.length}</h3></div>
      <div class="panel-body">${renderRowsHeader()}${pending.length ? pending.map(reqRowApproval).join('') : emptyRow('Nothing awaits your decision.')}</div>
    </div>
    <div class="panel">
      <div class="panel-head"><h3>History — ${done.length}</h3></div>
      <div class="panel-body">${renderRowsHeader()}${done.length ? done.map(a => {
        const r = a.request;
        return `<div class="req-row" data-req="${r.id}">
          <div class="req-id">${escape(r.ref_no)}</div>
          <div class="req-title">${escape(r.title)}<small>Step ${a.step_no} — you ${a.decision}</small></div>
          <div class="req-cell"><span class="module-pill m-${r.module}">${moduleLabel(r.module)}</span></div>
          <div class="req-cell"><span class="status s-${a.decision === 'approved' ? 'approved' : 'rejected'}"><span class="dot"></span>${a.decision}</span></div>
          <div class="req-cell mono">${fmtRel(a.decided_at)}</div>
          <div class="req-cell" style="text-align:right">›</div>
        </div>`;
      }).join('') : emptyRow('No history yet')}</div>
    </div>
  `;
  wireRows();
}

// =============================================================================
// VIEW: NOTIFICATIONS
// =============================================================================
async function renderNotifications() {
  const { data } = await sb
    .from('notifications')
    .select('*, request:request_master(ref_no,title,module,status)')
    .order('created_at', { ascending: false })
    .limit(300);

  $('#viewContent').innerHTML = `
    <div class="panel"><div class="panel-body">
      ${(data||[]).length ? (data||[]).map(n => `
        <div class="notif ${n.is_read?'':'unread'}" data-id="${n.id}" data-req="${n.request_id || ''}">
          <span class="dot"></span>
          <div class="body">
            <h5>${escape(n.title)} ${n.request ? `<code style="margin-left:6px">${escape(n.request.ref_no)}</code>` : ''}</h5>
            <p>${escape(n.body || '')}</p>
          </div>
          <time>${fmtRel(n.created_at)}</time>
        </div>
      `).join('') : emptyRow('Nothing new')}
    </div></div>
  `;

  $$('.notif').forEach(el => el.addEventListener('click', async () => {
    const id = el.dataset.id; const reqId = el.dataset.req;
    await sb.from('notifications').update({ is_read: true, read_at: new Date().toISOString() }).eq('id', id);
    el.classList.remove('unread');
    if (reqId) openDrawer(reqId);
    refreshBadges();
  }));
}

// =============================================================================
// DRAWER — request detail with timeline, comments, attachments, decide
// =============================================================================
async function openDrawer(requestId) {
  $('#drawerBg').classList.add('show');
  $('#drawerBody').innerHTML = '<div class="loading">Loading…</div>';
  $('#drawerTitle').textContent = 'Loading…';
  $('#drawerRef').textContent = '';

  const { data: r, error } = await sb
    .from('request_master')
    .select('*, requester:profiles!request_master_requester_id_fkey(*)')
    .eq('id', requestId)
    .single();
  if (error || !r) {
    $('#drawerBody').innerHTML = `<div class="empty"><h4>Not found</h4><p>${escape(error?.message || '')}</p></div>`;
    return;
  }
  $('#drawerTitle').textContent = r.title;
  $('#drawerRef').textContent = `${r.ref_no} · ${moduleLabel(r.module)} · <span class="status s-${r.status}">${statusLabel(r.status)}</span>`;
  $('#drawerRef').innerHTML = `${r.ref_no} · ${moduleLabel(r.module)} · <span class="status s-${r.status}"><span class="dot"></span>${statusLabel(r.status)}</span>`;

  // Fetch module-specific detail + approvals + comments + attachments + history
  const [
    moduleRow,
    { data: approvals },
    { data: comments },
    { data: attachments },
    { data: history },
    { data: myPending }
  ] = await Promise.all([
    fetchModuleDetail(r.module, r.module_record_id),
    sb.from('request_approvals').select('*, approver:profiles(full_name,email)').eq('request_id', requestId).order('step_no').order('created_at'),
    sb.from('request_comments').select('*, author:profiles(full_name)').eq('request_id', requestId).order('created_at'),
    sb.from('request_attachments').select('*').eq('request_id', requestId).order('created_at'),
    sb.from('request_history').select('*, actor:profiles(full_name)').eq('request_id', requestId).order('occurred_at'),
    sb.from('request_approvals').select('id').eq('request_id', requestId).eq('approver_id', CURRENT_USER.id).eq('decision','pending').limit(1)
  ]);

  const canDecide = (myPending||[]).length > 0;
  const canWithdraw = r.requester_id === CURRENT_USER.id && ['submitted','pending_approval','draft'].includes(r.status);

  // Can this user close out a scheduled change?
  // Allowed for: requester, admin, it_manager, or anyone with change execution role
  const canCompleteCR = r.module === 'change_request'
    && r.status === 'scheduled'
    && (r.requester_id === CURRENT_USER.id || isAdmin() || hasRole('it_manager') || hasRole('sysadmin') || hasRole('network_admin'));

  // Can SOP be marked published?
  const canPublishSOP = r.module === 'sop'
    && r.status === 'scheduled'
    && (r.requester_id === CURRENT_USER.id || isAdmin() || hasRole('it_manager'));

  $('#drawerBody').innerHTML = `
    <div class="detail-meta">
      <div class="m-item"><label>Requested by</label><span>${escape(r.requester?.full_name || '—')}</span></div>
      <div class="m-item"><label>Submitted</label><span>${fmtDateTime(r.submitted_at || r.created_at)}</span></div>
      <div class="m-item"><label>Priority</label><span>${escape(r.priority || '—')}</span></div>
      <div class="m-item"><label>Due</label><span>${r.due_date ? fmtDate(r.due_date) : '—'}</span></div>
    </div>

    ${r.summary ? `<div class="detail-section"><h4>Summary</h4><p>${escape(r.summary)}</p></div>` : ''}

    ${renderModuleDetail(r.module, moduleRow)}

    <div class="detail-section">
      <h4>Approval Flow</h4>
      <div class="timeline">${renderTimeline(approvals||[], r.current_step_no, r.status)}</div>
    </div>

    ${canDecide ? `
      <div class="form-card" style="background:var(--green-50);border-color:var(--green-500)">
        <h3 style="font-size:16px">Your Decision Required</h3>
        <div class="field">
          <label>Comment</label>
          <textarea id="decComment" rows="3" placeholder="Optional reasoning or conditions…"></textarea>
        </div>
        <div class="btn-row">
          <button class="btn ok" id="btnApprove">✓ Approve</button>
          <button class="btn danger" id="btnReject">✕ Reject</button>
        </div>
      </div>` : ''}

    ${canCompleteCR ? `
      <div class="form-card" style="background:linear-gradient(180deg,#fff5eb,#fdedd5);border-color:var(--orange)">
        <h3 style="font-size:16px">🔧 Change Execution</h3>
        <p style="font-size:12.5px;color:var(--ink-soft);margin-bottom:10px">
          This change is approved and scheduled. Once you've executed it, record the outcome.
        </p>
        <div class="field">
          <label>Execution notes (what was done, any deviations)</label>
          <textarea id="crCompleteNotes" rows="3" placeholder="e.g. Firmware upgraded from 7.2.13 to 7.2.14. No downtime. Config backed up before and after."></textarea>
        </div>
        <div class="btn-row">
          <button class="btn ok" id="btnCRComplete">✓ Mark Completed</button>
          <button class="btn secondary" id="btnCRRolledBack">↶ Rolled Back</button>
          <button class="btn danger" id="btnCRFailed">✕ Failed</button>
        </div>
      </div>` : ''}

    ${canPublishSOP ? `
      <div class="form-card" style="background:linear-gradient(180deg,#edf7e0,#e3ebd8);border-color:var(--green-500)">
        <h3 style="font-size:16px">📄 Publish SOP</h3>
        <p style="font-size:12.5px;color:var(--ink-soft);margin-bottom:10px">
          This SOP is approved. Publish it to the SOP Library so it becomes accessible to the team.
        </p>
        <div class="btn-row">
          <button class="btn ok" id="btnSOPPublish">✓ Publish SOP</button>
        </div>
      </div>` : ''}

    <div class="detail-section">
      <h4>Attachments (${(attachments||[]).length})</h4>
      ${(attachments||[]).map(a => `
        <div class="attachment">
          <div class="info">
            ${escape(a.file_name)}
            <small>${a.file_size ? (a.file_size/1024).toFixed(1) + ' KB · ' : ''}${fmtRel(a.created_at)}</small>
          </div>
          <button class="btn secondary btn-sm" data-download="${escape(a.storage_path)}" data-name="${escape(a.file_name)}">Download</button>
        </div>
      `).join('') || `<p style="color:var(--muted);font-size:12px">No attachments</p>`}
      <div class="field" style="margin-top:10px">
        <input type="file" id="attachUpload" />
      </div>
    </div>

    <div class="detail-section">
      <h4>Comments (${(comments||[]).length})</h4>
      ${(comments||[]).map(c => `
        <div class="comment ${c.is_internal?'internal':''}">
          <div class="comment-head">
            <div><span class="comment-author">${escape(c.author?.full_name || '—')}</span>${c.is_internal ? '<span class="comment-flag">internal</span>' : ''}</div>
            <span class="comment-time">${fmtDateTime(c.created_at)}</span>
          </div>
          <div class="comment-body">${escape(c.body)}</div>
        </div>
      `).join('') || `<p style="color:var(--muted);font-size:12px">No comments yet</p>`}
      <div class="field" style="margin-top:10px">
        <textarea id="cmtBody" rows="2" placeholder="Write a comment…"></textarea>
        <div style="display:flex;gap:10px;align-items:center;margin-top:8px">
          <label style="font-size:12px;display:flex;align-items:center;gap:6px"><input type="checkbox" id="cmtInternal" /> Internal (hidden from requester)</label>
          <button class="btn btn-sm" id="btnComment" style="margin-left:auto">Post comment</button>
        </div>
      </div>
    </div>

    ${canWithdraw ? `<div style="margin-top:18px"><button class="btn danger btn-sm" id="btnWithdraw">Withdraw request</button></div>` : ''}

    <div class="detail-section" style="margin-top:24px">
      <h4>Audit Trail</h4>
      <div class="timeline">
        ${(history||[]).map(h => `
          <div class="tl-step done">
            <h5>${escape(h.action)} ${h.to_status ? `→ <span class="status s-${h.to_status}">${statusLabel(h.to_status)}</span>` : ''}</h5>
            <div class="meta">${escape(h.actor?.full_name || 'system')} · ${fmtDateTime(h.occurred_at)}</div>
          </div>
        `).join('') || `<p style="color:var(--muted);font-size:12px">No audit records</p>`}
      </div>
    </div>
  `;

  if (canDecide) {
    $('#btnApprove').addEventListener('click', () => decide(requestId, 'approved'));
    $('#btnReject').addEventListener('click', () => decide(requestId, 'rejected'));
  }
  if (canWithdraw) {
    $('#btnWithdraw').addEventListener('click', () => withdraw(requestId));
  }
  if (canCompleteCR) {
    $('#btnCRComplete').addEventListener('click', () => completeChangeRequest(requestId, 'completed'));
    $('#btnCRRolledBack').addEventListener('click', () => completeChangeRequest(requestId, 'rolled_back'));
    $('#btnCRFailed').addEventListener('click', () => completeChangeRequest(requestId, 'failed'));
  }
  if (canPublishSOP) {
    $('#btnSOPPublish').addEventListener('click', () => publishSOP(requestId));
  }
  $('#btnComment').addEventListener('click', () => postComment(requestId));
  $('#attachUpload').addEventListener('change', (e) => uploadAttachment(requestId, e.target.files[0]));
  $$('[data-download]').forEach(b => b.addEventListener('click', () => downloadAttachment(b.dataset.download, b.dataset.name)));
}

function renderTimeline(approvals, currentStep, status) {
  if (!approvals.length) return `<p style="color:var(--muted);font-size:12px">No approvals required / not yet submitted</p>`;
  // Group by step_no
  const groups = {};
  approvals.forEach(a => { (groups[a.step_no] ||= []).push(a); });
  const steps = Object.keys(groups).map(Number).sort((a,b)=>a-b);

  return steps.map(sn => {
    const rows = groups[sn];
    const step = rows[0];
    const allDecided = rows.every(r => r.decision !== 'pending');
    const anyRejected = rows.some(r => r.decision === 'rejected');
    let cls = 'done';
    if (sn > currentStep) cls = '';
    else if (anyRejected) cls = 'rejected';
    else if (!allDecided) cls = 'current';

    return `<div class="tl-step ${cls}">
      <h5>Step ${sn}: ${escape(step.step_name)}</h5>
      <div class="meta">
        ${rows.map(r => `${escape(r.approver?.full_name || '—')} <b style="color:${r.decision==='approved'?'var(--green-700)':r.decision==='rejected'?'var(--red-deep)':'var(--orange)'}">· ${r.decision}</b>${r.decided_at?` · ${fmtRel(r.decided_at)}`:''}`).join(' &nbsp;|&nbsp; ')}
      </div>
      ${rows.filter(r=>r.comment).map(r => `<div class="note"><b>${escape(r.approver?.full_name)}:</b> ${escape(r.comment)}</div>`).join('')}
    </div>`;
  }).join('');
}

async function fetchModuleDetail(module, id) {
  const table = { change_request:'change_requests', sop:'sops', leave:'leave_requests', overtime:'overtime_requests', comp_off:'comp_off_requests' }[module];
  if (!table) return null;
  const { data } = await sb.from(table).select('*').eq('id', id).maybeSingle();
  return data;
}

function renderModuleDetail(module, d) {
  if (!d) return '';
  if (module === 'change_request') {
    return `
      <div class="detail-section"><h4>Classification</h4>
        <div class="field-grid">
          <div class="m-item"><label>Type</label><span>${escape(d.change_type)}</span></div>
          <div class="m-item"><label>Risk</label><span>${escape(d.risk)}</span></div>
          <div class="m-item"><label>Impact</label><span>${escape(d.impact)}</span></div>
          <div class="m-item"><label>Priority</label><span>${escape(d.priority)}</span></div>
          <div class="m-item"><label>Category</label><span>${escape(d.category || '—')}</span></div>
          <div class="m-item"><label>Affected Users</label><span>${d.affected_users_count ?? '—'}</span></div>
        </div>
      </div>
      <div class="detail-section"><h4>Schedule</h4>
        <div class="field-grid">
          <div class="m-item"><label>Start</label><span>${fmtDateTime(d.scheduled_start)}</span></div>
          <div class="m-item"><label>End</label><span>${fmtDateTime(d.scheduled_end)}</span></div>
          <div class="m-item"><label>CAB required</label><span>${d.cab_required?'Yes':'No'}</span></div>
          <div class="m-item"><label>Systems</label><span>${(d.affected_systems||[]).join(', ') || '—'}</span></div>
        </div>
      </div>
      <div class="detail-section"><h4>Business Justification</h4><p>${escape(d.business_justification)}</p></div>
      <div class="detail-section"><h4>Implementation Plan</h4><p>${escape(d.implementation_plan)}</p></div>
      <div class="detail-section"><h4>Test Plan</h4><p>${escape(d.test_plan)}</p></div>
      <div class="detail-section"><h4>Validation Plan</h4><p>${escape(d.validation_plan)}</p></div>
      <div class="detail-section"><h4>Rollback Plan</h4><p>${escape(d.rollback_plan)}</p></div>
      ${d.communication_plan ? `<div class="detail-section"><h4>Communication Plan</h4><p>${escape(d.communication_plan)}</p></div>` : ''}
    `;
  }
  if (module === 'sop') {
    return `
      <div class="detail-section"><h4>SOP Metadata</h4>
        <div class="field-grid">
          <div class="m-item"><label>SOP No.</label><span>${escape(d.sop_number)}</span></div>
          <div class="m-item"><label>Version</label><span>${escape(d.version)}</span></div>
          <div class="m-item"><label>Category</label><span>${escape(d.category || '—')}</span></div>
          <div class="m-item"><label>Effective</label><span>${fmtDate(d.effective_date)}</span></div>
          <div class="m-item"><label>Next Review</label><span>${fmtDate(d.next_review_date)}</span></div>
          <div class="m-item"><label>Status</label><span>${escape(d.status)}</span></div>
        </div>
      </div>
      ${d.scope ? `<div class="detail-section"><h4>Scope</h4><p>${escape(d.scope)}</p></div>` : ''}
      ${d.purpose ? `<div class="detail-section"><h4>Purpose</h4><p>${escape(d.purpose)}</p></div>` : ''}
      ${d.body ? `<div class="detail-section"><h4>Body</h4><p>${escape(d.body)}</p></div>` : ''}
    `;
  }
  if (module === 'leave') {
    return `
      <div class="detail-section"><h4>Leave Details</h4>
        <div class="field-grid">
          <div class="m-item"><label>Type</label><span>${escape(d.leave_type)}</span></div>
          <div class="m-item"><label>Start</label><span>${fmtDate(d.start_date)}</span></div>
          <div class="m-item"><label>End</label><span>${fmtDate(d.end_date)}</span></div>
          <div class="m-item"><label>Total Days</label><span>${d.total_days}</span></div>
          <div class="m-item"><label>Half-Day</label><span>${d.is_half_day ? d.half_day_period : 'No'}</span></div>
          <div class="m-item"><label>Balance at request</label><span>${d.balance_at_request ?? '—'}</span></div>
        </div>
      </div>
      <div class="detail-section"><h4>Reason</h4><p>${escape(d.reason)}</p></div>
      ${d.handover_notes ? `<div class="detail-section"><h4>Handover Notes</h4><p>${escape(d.handover_notes)}</p></div>` : ''}
      ${d.contact_during_leave ? `<div class="detail-section"><h4>Contact</h4><p>${escape(d.contact_during_leave)}</p></div>` : ''}
    `;
  }
  if (module === 'overtime') {
    return `
      <div class="detail-section"><h4>Overtime Details</h4>
        <div class="field-grid">
          <div class="m-item"><label>Type</label><span>${escape(d.ot_type)}${d.is_post_facto?' · post-facto':''}</span></div>
          <div class="m-item"><label>Date</label><span>${fmtDate(d.ot_date)}</span></div>
          <div class="m-item"><label>From</label><span>${escape(d.start_time)}</span></div>
          <div class="m-item"><label>To</label><span>${escape(d.end_time)}</span></div>
          <div class="m-item"><label>Break (min)</label><span>${d.break_minutes || 0}</span></div>
          <div class="m-item"><label>Computed Hours</label><span><b>${d.computed_hours}</b></span></div>
          <div class="m-item"><label>Outcome</label><span>${escape(d.outcome)}</span></div>
        </div>
      </div>
      <div class="detail-section"><h4>Reason</h4><p>${escape(d.reason)}</p></div>
      <div class="detail-section"><h4>Task</h4><p>${escape(d.task_description)}</p></div>
      ${d.emergency_justification ? `<div class="detail-section"><h4>Emergency Justification</h4><p>${escape(d.emergency_justification)}</p></div>` : ''}
    `;
  }
  if (module === 'comp_off') {
    return `
      <div class="detail-section"><h4>Comp-Off Details</h4>
        <div class="field-grid">
          <div class="m-item"><label>Date</label><span>${fmtDate(d.comp_off_date)}</span></div>
          <div class="m-item"><label>Hours</label><span>${d.hours_requested}</span></div>
          <div class="m-item"><label>Full day</label><span>${d.is_full_day?'Yes':'No'}</span></div>
          <div class="m-item"><label>Balance at request</label><span>${d.balance_at_request ?? '—'}</span></div>
        </div>
      </div>
      ${d.reason ? `<div class="detail-section"><h4>Reason</h4><p>${escape(d.reason)}</p></div>` : ''}
    `;
  }
  return '';
}

async function decide(requestId, decision) {
  const comment = $('#decComment')?.value?.trim() || null;
  if (decision === 'rejected' && !comment) {
    toast('A comment is required when rejecting.', 'error'); return;
  }
  const btn = decision === 'approved' ? $('#btnApprove') : $('#btnReject');
  if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spin"></span> Processing…'; }

  const { error } = await sb.rpc('decide_request', { p_request_id: requestId, p_decision: decision, p_comment: comment });
  if (error) {
    if (btn) { btn.disabled = false; btn.textContent = decision === 'approved' ? '✓ Approve' : '✕ Reject'; }
    toast(error.message, 'error');
    return;
  }
  toast(`Decision recorded: ${decision}`, 'success');
  await refreshBadges();
  await openDrawer(requestId);
  route(CURRENT_VIEW);
}
async function withdraw(requestId) {
  if (!confirm('Withdraw this request? This cannot be undone.')) return;
  const { error } = await sb.from('request_master').update({ status: 'withdrawn', closed_at: new Date().toISOString() }).eq('id', requestId);
  if (error) { toast(error.message, 'error'); return; }
  toast('Request withdrawn.', 'success');
  closeDrawer();
  await refreshBadges();
  route(CURRENT_VIEW);
}

// Mark a Change Request as completed / rolled_back / failed after execution
async function completeChangeRequest(requestId, outcome) {
  const labels = { completed: 'Completed', rolled_back: 'Rolled Back', failed: 'Failed' };
  const outcomeLabel = labels[outcome] || outcome;
  const notes = ($('#crCompleteNotes')?.value || '').trim();

  if (!notes && outcome !== 'completed') {
    toast('Please add notes explaining what happened.', 'error');
    return;
  }

  if (!confirm(`Mark this change as "${outcomeLabel}"?\n\nThis will close out the change request and cannot be easily reversed.`)) return;

  const btnIds = ['btnCRComplete', 'btnCRRolledBack', 'btnCRFailed'];
  btnIds.forEach(id => { const b = $('#' + id); if (b) b.disabled = true; });

  try {
    // Update request_master status
    const now = new Date().toISOString();
    const { error: updErr } = await sb.from('request_master').update({
      status: outcome,
      closed_at: now,
      updated_at: now
    }).eq('id', requestId);

    if (updErr) throw updErr;

    // Log to request_history
    await sb.from('request_history').insert({
      request_id: requestId,
      actor_id: CURRENT_USER.id,
      action: `change_${outcome}`,
      from_status: 'scheduled',
      to_status: outcome,
      notes: notes || null
    });

    // Post execution notes as a comment (so they're visible in the comments thread)
    if (notes) {
      await sb.from('request_comments').insert({
        request_id: requestId,
        author_id: CURRENT_USER.id,
        body: `[Execution — ${outcomeLabel}] ${notes}`,
        is_internal: false
      });
    }

    // Notify key stakeholders
    try {
      // Find approvers + requester
      const { data: approvers } = await sb.from('request_approvals')
        .select('approver_id').eq('request_id', requestId);
      const { data: req } = await sb.from('request_master')
        .select('requester_id, title, ref_no').eq('id', requestId).single();

      const recipients = new Set([req?.requester_id, ...(approvers || []).map(a => a.approver_id)]);
      recipients.delete(CURRENT_USER.id);   // don't notify myself

      for (const userId of recipients) {
        if (!userId) continue;
        await sb.from('notifications').insert({
          user_id: userId,
          kind: 'change_completed',
          title: `CR ${outcomeLabel}: ${req?.ref_no}`,
          body: `"${req?.title}" was marked as ${outcomeLabel} by ${CURRENT_USER.full_name}.`,
          link_ref: requestId
        });
      }
    } catch(e) { console.warn('Notification dispatch failed', e); }

    toast(`Change marked as ${outcomeLabel}.`, 'success');
    closeDrawer();
    await refreshBadges();
    route(CURRENT_VIEW);
  } catch(e) {
    toast(e.message || 'Could not update change request', 'error');
    btnIds.forEach(id => { const b = $('#' + id); if (b) b.disabled = false; });
  }
}

// Mark an SOP as published (scheduled → published)
async function publishSOP(requestId) {
  if (!confirm('Publish this SOP to the SOP Library?')) return;

  const btn = $('#btnSOPPublish');
  if (btn) { btn.disabled = true; btn.textContent = 'Publishing…'; }

  try {
    const now = new Date().toISOString();

    // Get the module_record_id (the sops table row)
    const { data: master } = await sb.from('request_master')
      .select('module_record_id, ref_no, title').eq('id', requestId).single();

    // Update sops table: mark as published
    if (master?.module_record_id) {
      await sb.from('sops').update({
        status: 'published',
        published_at: now,
        updated_at: now
      }).eq('id', master.module_record_id);
    }

    // Update request_master status
    await sb.from('request_master').update({
      status: 'completed',
      closed_at: now,
      updated_at: now
    }).eq('id', requestId);

    // History
    await sb.from('request_history').insert({
      request_id: requestId,
      actor_id: CURRENT_USER.id,
      action: 'sop_published',
      from_status: 'scheduled',
      to_status: 'completed'
    });

    toast('SOP published to the library.', 'success');
    closeDrawer();
    await refreshBadges();
    route(CURRENT_VIEW);
  } catch(e) {
    toast(e.message || 'Could not publish SOP', 'error');
    if (btn) { btn.disabled = false; btn.textContent = '✓ Publish SOP'; }
  }
}
async function postComment(requestId) {
  const body = $('#cmtBody').value.trim();
  if (!body) return;
  const is_internal = $('#cmtInternal').checked;
  const btn = $('#btnComment');
  if (btn) { btn.disabled = true; btn.textContent = 'Posting…'; }

  const { error } = await sb.from('request_comments').insert({ request_id: requestId, author_id: CURRENT_USER.id, body, is_internal });

  if (btn) { btn.disabled = false; btn.textContent = 'Post comment'; }
  if (error) { toast(error.message, 'error'); return; }
  toast('Comment posted', 'success');
  await openDrawer(requestId);
}
async function uploadAttachment(requestId, file) {
  if (!file) return;
  toast('Uploading…', 'info');
  const path = `${requestId}/${Date.now()}_${file.name}`;
  const { error: upErr } = await sb.storage.from(CFG.STORAGE_BUCKET).upload(path, file);
  if (upErr) { toast(upErr.message, 'error'); return; }
  const { error } = await sb.from('request_attachments').insert({
    request_id: requestId, uploaded_by: CURRENT_USER.id,
    storage_path: path, file_name: file.name, file_size: file.size, mime_type: file.type
  });
  if (error) { toast(error.message, 'error'); return; }
  toast('Uploaded', 'success');
  await openDrawer(requestId);
}
async function downloadAttachment(path, name) {
  const { data, error } = await sb.storage.from(CFG.STORAGE_BUCKET).createSignedUrl(path, 60);
  if (error) { toast(error.message, 'error'); return; }
  const a = document.createElement('a'); a.href = data.signedUrl; a.download = name; a.click();
}
const closeDrawer = () => $('#drawerBg').classList.remove('show');

// =============================================================================
// CHANGE REQUEST FORM
// =============================================================================
function renderNewChange() {
  $('#viewContent').innerHTML = `
    <div class="form-card">
      <h3>New Change Request</h3>

      <div class="form-section">
        <h4>Overview</h4>
        <div class="grid-2">
          <div class="field"><label class="required">Title</label><input id="cr-title" placeholder="e.g. FortiGate firmware upgrade 7.2.13 → 7.4.x" /></div>
          <div class="field"><label>Category</label><select id="cr-category">
            <option value="">Select</option><option>network</option><option>server</option>
            <option>application</option><option>security</option><option>identity</option><option>database</option>
          </select></div>
        </div>
        <div class="field"><label>Summary</label><textarea id="cr-summary" rows="2" placeholder="One-line summary"></textarea></div>
      </div>

      <div class="form-section">
        <h4>Classification</h4>
        <div class="grid-3">
          <div class="field"><label class="required">Change Type</label><select id="cr-type">
            <option value="standard">Standard (pre-approved / low risk)</option>
            <option value="normal" selected>Normal</option>
            <option value="emergency">Emergency</option>
            <option value="major">Major</option>
          </select></div>
          <div class="field"><label class="required">Risk</label><select id="cr-risk">
            <option value="low">Low</option><option value="medium" selected>Medium</option>
            <option value="high">High</option><option value="critical">Critical</option>
          </select></div>
          <div class="field"><label class="required">Impact</label><select id="cr-impact">
            <option value="low">Low</option><option value="medium" selected>Medium</option>
            <option value="high">High</option><option value="critical">Critical</option>
          </select></div>
          <div class="field"><label class="required">Priority</label><select id="cr-priority">
            <option value="low">Low</option><option value="medium" selected>Medium</option>
            <option value="high">High</option><option value="urgent">Urgent</option>
          </select></div>
          <div class="field"><label>Affected systems</label><input id="cr-systems" placeholder="Comma-separated" /></div>
          <div class="field"><label>Affected users</label><input id="cr-users" type="number" min="0" /></div>
        </div>
        <div class="warn-box" id="cr-route-hint">The workflow will be selected based on your Type and Risk. High/critical risk Normal changes require CAB review. Major changes always require CAB.</div>
      </div>

      <div class="form-section">
        <h4>Schedule</h4>
        <div class="grid-2">
          <div class="field"><label>Scheduled start</label><input id="cr-start" type="datetime-local" /></div>
          <div class="field"><label>Scheduled end</label><input id="cr-end" type="datetime-local" /></div>
        </div>
      </div>

      <div class="form-section">
        <h4>Plans (all required)</h4>
        <div class="field"><label class="required">Business justification</label><textarea id="cr-just" rows="3"></textarea></div>
        <div class="field"><label class="required">Implementation plan</label><textarea id="cr-impl" rows="4"></textarea></div>
        <div class="field"><label class="required">Test plan</label><textarea id="cr-test" rows="3"></textarea></div>
        <div class="field"><label class="required">Validation plan</label><textarea id="cr-val" rows="3"></textarea></div>
        <div class="field"><label class="required">Rollback plan</label><textarea id="cr-rb" rows="3"></textarea></div>
        <div class="field"><label>Communication plan</label><textarea id="cr-comm" rows="2"></textarea></div>
      </div>

      <div class="btn-row">
        <button class="btn ok" id="cr-submit">Submit for approval</button>
        <button class="btn secondary" id="cr-draft">Save as draft</button>
      </div>
    </div>
  `;
  $('#cr-submit').addEventListener('click', () => submitChange(true));
  $('#cr-draft').addEventListener('click', () => submitChange(false));
}

async function submitChange(submit=true) {
  const btnId = submit ? 'cr-submit' : 'cr-draft';
  const btn = document.getElementById(btnId);
  if (btn.disabled) return;
  btn.disabled = true;
  const originalText = btn.textContent;
  btn.innerHTML = '<span class="spin"></span> Submitting…';

  try {
    const get = (id) => document.getElementById(id).value.trim();
    const title = get('cr-title');
    if (!title) { toast('Title is required', 'error'); return; }
    const required = ['cr-just','cr-impl','cr-test','cr-val','cr-rb'];
    if (submit) {
      for (const r of required) { if (!get(r)) { toast(`${r} is required`, 'error'); return; } }
    }
    const systems = get('cr-systems').split(',').map(s => s.trim()).filter(Boolean);

    // 1. insert module row
    const { data: cr, error: e1 } = await sb.from('change_requests').insert({
      request_id: null,
      change_type: get('cr-type'), risk: get('cr-risk'), impact: get('cr-impact'), priority: get('cr-priority'),
      category: get('cr-category') || null,
      affected_systems: systems, affected_users_count: parseInt(get('cr-users'))||null,
      business_justification: get('cr-just'), implementation_plan: get('cr-impl'),
      test_plan: get('cr-test'), validation_plan: get('cr-val'),
      rollback_plan: get('cr-rb'), communication_plan: get('cr-comm') || null,
      scheduled_start: get('cr-start') || null, scheduled_end: get('cr-end') || null,
      cab_required: ['high','critical'].includes(get('cr-risk')) || get('cr-type')==='major',
      pir_required: ['emergency','major'].includes(get('cr-type'))
    }).select().single();
    if (e1) { toast(e1.message, 'error'); return; }

    // 2. insert master
    const { data: ref } = await sb.rpc('generate_ref_no', { p_module: 'change_request' });
    const { data: rm, error: e2 } = await sb.from('request_master').insert({
      ref_no: ref, module: 'change_request', module_record_id: cr.id,
      title, summary: get('cr-summary') || null,
      requester_id: CURRENT_USER.id, department_id: CURRENT_USER.department_id,
      priority: get('cr-priority'),
      status: 'draft'
    }).select().single();
    if (e2) { toast(e2.message, 'error'); return; }

    // 3. link back (checked!)
    const { error: eLink } = await sb.from('change_requests').update({ request_id: rm.id }).eq('id', cr.id);
    if (eLink) { toast('Link-back failed: ' + eLink.message, 'error'); return; }
    await sb.from('request_history').insert({ request_id: rm.id, actor_id: CURRENT_USER.id, action: 'created', to_status: 'draft' });

    if (submit) {
      const { error: e3 } = await sb.rpc('submit_request', { p_request_id: rm.id });
      if (e3) { toast(e3.message, 'error'); return; }
      toast(`${ref} submitted for approval`, 'success');
    } else {
      toast(`${ref} saved as draft`, 'success');
    }
    await refreshBadges();
    route('my-requests');
  } catch (err) {
    toast(err.message || 'Submit failed', 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = originalText;
  }
}

// =============================================================================
// SOP FORM
// =============================================================================
function renderNewSop() {
  $('#viewContent').innerHTML = `
    <div class="form-card">
      <h3>New SOP</h3>
      <div class="form-section"><h4>Metadata</h4>
        <div class="grid-2">
          <div class="field"><label class="required">SOP Number</label><input id="sop-num" placeholder="FFC-IT-SOP-0042" /></div>
          <div class="field"><label class="required">Version</label><input id="sop-ver" placeholder="1.0" value="1.0" /></div>
          <div class="field"><label class="required">Title</label><input id="sop-title" /></div>
          <div class="field"><label>Category</label><select id="sop-cat">
            <option value="">Select</option>
            <option>security</option><option>backup</option><option>network</option>
            <option>identity</option><option>operations</option><option>erp</option>
          </select></div>
          <div class="field"><label>Effective date</label><input id="sop-eff" type="date" /></div>
          <div class="field"><label>Review cycle (months)</label><input id="sop-cycle" type="number" value="12" min="1" max="60" /></div>
        </div>
        <div class="field"><label>Tags (comma-separated)</label><input id="sop-tags" /></div>
      </div>
      <div class="form-section"><h4>Content</h4>
        <div class="field"><label>Scope</label><textarea id="sop-scope" rows="2"></textarea></div>
        <div class="field"><label>Purpose</label><textarea id="sop-purp" rows="2"></textarea></div>
        <div class="field"><label>Body (markdown)</label><textarea id="sop-body" rows="10"></textarea></div>
      </div>
      <div class="btn-row">
        <button class="btn ok" id="sop-submit">Submit for review</button>
        <button class="btn secondary" id="sop-draft">Save as draft</button>
      </div>
    </div>
  `;
  $('#sop-submit').addEventListener('click', () => submitSop(true));
  $('#sop-draft').addEventListener('click', () => submitSop(false));
}
async function submitSop(submit=true) {
  const g = (id) => document.getElementById(id).value.trim();
  if (!g('sop-num') || !g('sop-ver') || !g('sop-title')) return toast('SOP Number, Version, Title required', 'error');
  const tags = g('sop-tags').split(',').map(s=>s.trim()).filter(Boolean);

  const { data: s, error: e1 } = await sb.from('sops').insert({
    request_id: null, sop_number: g('sop-num'), version: g('sop-ver'),
    title: g('sop-title'), category: g('sop-cat')||null,
    scope: g('sop-scope')||null, purpose: g('sop-purp')||null, body: g('sop-body')||null,
    effective_date: g('sop-eff')||null, review_cycle_months: parseInt(g('sop-cycle'))||12,
    owner_id: CURRENT_USER.id, tags, status: 'draft'
  }).select().single();
  if (e1) return toast(e1.message, 'error');

  const { data: ref } = await sb.rpc('generate_ref_no', { p_module: 'sop' });
  const { data: rm, error: e2 } = await sb.from('request_master').insert({
    ref_no: ref, module: 'sop', module_record_id: s.id, title: g('sop-title'),
    summary: g('sop-num') + ' v' + g('sop-ver'), requester_id: CURRENT_USER.id,
    department_id: CURRENT_USER.department_id, status: 'draft'
  }).select().single();
  if (e2) return toast(e2.message, 'error');

  await sb.from('sops').update({ request_id: rm.id }).eq('id', s.id);
  await sb.from('request_history').insert({ request_id: rm.id, actor_id: CURRENT_USER.id, action: 'created', to_status: 'draft' });

  if (submit) {
    const { error: e3 } = await sb.rpc('submit_request', { p_request_id: rm.id });
    if (e3) return toast(e3.message, 'error');
    toast(`${ref} submitted for review`, 'success');
  } else toast(`${ref} saved`, 'success');
  await refreshBadges();
  route('my-requests');
}

// =============================================================================
// LEAVE FORM
// =============================================================================
async function renderNewLeave() {
  const { data: bal } = await sb.from('leave_balances').select('*').eq('user_id', CURRENT_USER.id).eq('year', new Date().getFullYear());
  const balMap = {};
  (bal||[]).forEach(b => { balMap[b.leave_type] = b; });
  const balAvail = (type) => {
    const b = balMap[type];
    if (!b) return 0;
    return (Number(b.entitled_days)+Number(b.carried_forward||0)-Number(b.used_days||0)-Number(b.pending_days||0)).toFixed(1);
  };

  $('#viewContent').innerHTML = `
    <div class="form-card">
      <h3>New Leave Request</h3>
      <div class="balance-box" id="bal-box">
        <b>Available balances:</b>
        Annual <b>${balAvail('annual')}</b>d &nbsp; · &nbsp;
        Sick <b>${balAvail('sick')}</b>d &nbsp; · &nbsp;
        Casual <b>${balAvail('casual')}</b>d &nbsp; · &nbsp;
        Unpaid <b>unlimited</b>
      </div>
      <div class="grid-3">
        <div class="field"><label class="required">Type</label><select id="lv-type">
          <option value="annual">Annual</option><option value="sick">Sick</option>
          <option value="casual">Casual</option><option value="unpaid">Unpaid</option>
          <option value="maternity">Maternity</option><option value="paternity">Paternity</option>
          <option value="bereavement">Bereavement</option><option value="hajj">Hajj</option>
        </select></div>
        <div class="field"><label class="required">Start date</label><input id="lv-start" type="date" /></div>
        <div class="field"><label class="required">End date</label><input id="lv-end" type="date" /></div>
      </div>
      <div class="grid-3">
        <div class="field"><label>Total days</label><input id="lv-days" type="number" step="0.5" readonly /></div>
        <div class="field"><label>Half day?</label><select id="lv-half">
          <option value="">No</option><option value="first">First half</option><option value="second">Second half</option>
        </select></div>
        <div class="field"><label>Delegate to</label><input id="lv-delegate" placeholder="Name" /></div>
      </div>
      <div class="field"><label class="required">Reason</label><textarea id="lv-reason" rows="2"></textarea></div>
      <div class="field"><label>Handover notes</label><textarea id="lv-handover" rows="3"></textarea></div>
      <div class="field"><label>Contact during leave</label><input id="lv-contact" /></div>
      <div id="lv-overlap-warn"></div>
      <div class="btn-row">
        <button class="btn ok" id="lv-submit">Submit</button>
        <button class="btn secondary" id="lv-draft">Save as draft</button>
      </div>
    </div>
  `;
  const calcDays = () => {
    const s = $('#lv-start').value; const e = $('#lv-end').value;
    const half = $('#lv-half').value;
    if (!s || !e) return;
    const d = Math.floor((new Date(e) - new Date(s))/86400000) + 1;
    $('#lv-days').value = half ? 0.5 : d;
  };
  $('#lv-start').addEventListener('change', calcDays);
  $('#lv-end').addEventListener('change', calcDays);
  $('#lv-half').addEventListener('change', calcDays);
  $('#lv-start').addEventListener('change', checkOverlap);
  $('#lv-end').addEventListener('change', checkOverlap);

  async function checkOverlap() {
    const s = $('#lv-start').value, e = $('#lv-end').value;
    if (!s || !e) return;
    const { data } = await sb.rpc('check_leave_overlap', {
      p_user: CURRENT_USER.id, p_start: s, p_end: e
    });
    $('#lv-overlap-warn').innerHTML = data
      ? `<div class="warn-box">⚠ You already have leave requests overlapping with this period. You may still submit, but approval may be blocked.</div>`
      : '';
  }

  $('#lv-submit').addEventListener('click', () => submitLeave(true));
  $('#lv-draft').addEventListener('click', () => submitLeave(false));
}

async function submitLeave(submit=true) {
  const g = (id) => document.getElementById(id).value.trim();
  const type = g('lv-type'), s = g('lv-start'), e = g('lv-end');
  if (!s || !e || !g('lv-reason')) return toast('Start, end and reason required', 'error');
  const days = parseFloat(g('lv-days')) || 0;
  if (days <= 0) return toast('Invalid duration', 'error');

  // balance check (except unpaid/maternity/paternity/bereavement/hajj — HR-controlled)
  if (['annual','sick','casual'].includes(type)) {
    const { data: bal } = await sb.rpc('get_leave_balance', {
      p_user: CURRENT_USER.id, p_type: type, p_year: new Date().getFullYear()
    });
    if (Number(bal) < days) return toast(`Insufficient ${type} balance: ${bal} available, ${days} requested`, 'error');
  }

  const { data: lr, error: e1 } = await sb.from('leave_requests').insert({
    request_id: null, leave_type: type,
    start_date: s, end_date: e, total_days: days,
    is_half_day: !!g('lv-half'), half_day_period: g('lv-half') || null,
    reason: g('lv-reason'),
    contact_during_leave: g('lv-contact')||null, handover_notes: g('lv-handover')||null,
    balance_at_request: null
  }).select().single();
  if (e1) return toast(e1.message, 'error');

  const { data: ref } = await sb.rpc('generate_ref_no', { p_module: 'leave' });
  const { data: rm, error: e2 } = await sb.from('request_master').insert({
    ref_no: ref, module: 'leave', module_record_id: lr.id,
    title: `${type[0].toUpperCase()+type.slice(1)} leave: ${days}d (${fmtDate(s)} → ${fmtDate(e)})`,
    summary: g('lv-reason').slice(0,200),
    requester_id: CURRENT_USER.id, department_id: CURRENT_USER.department_id,
    status: 'draft'
  }).select().single();
  if (e2) return toast(e2.message, 'error');

  await sb.from('leave_requests').update({ request_id: rm.id }).eq('id', lr.id);
  await sb.from('request_history').insert({ request_id: rm.id, actor_id: CURRENT_USER.id, action: 'created', to_status: 'draft' });

  if (submit) {
    const { error: e3 } = await sb.rpc('submit_request', { p_request_id: rm.id });
    if (e3) return toast(e3.message, 'error');
    toast(`${ref} submitted`, 'success');
  } else toast(`${ref} saved`, 'success');
  await refreshBadges();
  route('my-requests');
}

// =============================================================================
// OVERTIME FORM
// =============================================================================
function renderNewOvertime() {
  $('#viewContent').innerHTML = `
    <div class="form-card">
      <h3>New Overtime Request</h3>
      <div class="grid-2">
        <div class="field"><label class="required">OT Type</label><select id="ot-type">
          <option value="planned">Planned (pre-approval)</option>
          <option value="emergency">Emergency (post-facto)</option>
        </select></div>
        <div class="field"><label class="required">Date</label><input id="ot-date" type="date" /></div>
        <div class="field"><label class="required">Start time</label><input id="ot-s" type="time" /></div>
        <div class="field"><label class="required">End time</label><input id="ot-e" type="time" /></div>
        <div class="field"><label>Break (minutes)</label><input id="ot-break" type="number" min="0" value="0" /></div>
        <div class="field"><label>Computed hours</label><input id="ot-hrs" readonly /></div>
      </div>
      <div class="field"><label class="required">Reason</label><textarea id="ot-reason" rows="2"></textarea></div>
      <div class="field"><label class="required">Task description</label><textarea id="ot-task" rows="3"></textarea></div>
      <div class="field"><label>Related change ref / incident ref</label><input id="ot-related" placeholder="e.g. CR-2026-00012 or INC-9823" /></div>
      <div class="field"><label>Preferred outcome</label><select id="ot-outcome">
        <option value="comp_off">Credit to comp-off (90-day expiry)</option>
        <option value="payroll">Process through payroll</option>
      </select></div>
      <div id="ot-emergency-block" style="display:none">
        <div class="warn-box">Emergency OT is filed AFTER the work. It requires manager acknowledgement + IT Manager exception approval.</div>
        <div class="field"><label class="required">Emergency justification</label><textarea id="ot-just" rows="3"></textarea></div>
      </div>
      <div class="btn-row">
        <button class="btn ok" id="ot-submit">Submit</button>
        <button class="btn secondary" id="ot-draft">Save as draft</button>
      </div>
    </div>
  `;
  const calc = () => {
    const s = $('#ot-s').value, e = $('#ot-e').value, b = parseInt($('#ot-break').value)||0;
    if (!s || !e) return;
    const [sh,sm] = s.split(':').map(Number), [eh,em] = e.split(':').map(Number);
    const hrs = ((eh*60+em) - (sh*60+sm) - b)/60;
    $('#ot-hrs').value = hrs.toFixed(2);
  };
  ['ot-s','ot-e','ot-break'].forEach(id => $('#'+id).addEventListener('change', calc));
  $('#ot-type').addEventListener('change', () => {
    $('#ot-emergency-block').style.display = $('#ot-type').value === 'emergency' ? 'block' : 'none';
  });
  $('#ot-submit').addEventListener('click', () => submitOt(true));
  $('#ot-draft').addEventListener('click', () => submitOt(false));
}

async function submitOt(submit=true) {
  const g = (id) => document.getElementById(id).value.trim();
  const type = g('ot-type');
  if (!g('ot-date') || !g('ot-s') || !g('ot-e') || !g('ot-reason') || !g('ot-task')) return toast('Fill required fields', 'error');
  if (type === 'emergency' && !g('ot-just')) return toast('Emergency justification required', 'error');

  const { data: ot, error: e1 } = await sb.from('overtime_requests').insert({
    request_id: null, ot_type: type, ot_date: g('ot-date'),
    start_time: g('ot-s'), end_time: g('ot-e'), break_minutes: parseInt(g('ot-break'))||0,
    reason: g('ot-reason'), task_description: g('ot-task'),
    related_incident_ref: g('ot-related')||null,
    is_post_facto: type === 'emergency',
    emergency_justification: type === 'emergency' ? g('ot-just') : null,
    outcome: g('ot-outcome')
  }).select().single();
  if (e1) return toast(e1.message, 'error');

  const { data: ref } = await sb.rpc('generate_ref_no', { p_module: 'overtime' });
  const { data: rm, error: e2 } = await sb.from('request_master').insert({
    ref_no: ref, module: 'overtime', module_record_id: ot.id,
    title: `${type[0].toUpperCase()+type.slice(1)} OT · ${ot.computed_hours}h on ${fmtDate(g('ot-date'))}`,
    summary: g('ot-reason').slice(0,200),
    requester_id: CURRENT_USER.id, department_id: CURRENT_USER.department_id,
    status: 'draft'
  }).select().single();
  if (e2) return toast(e2.message, 'error');

  await sb.from('overtime_requests').update({ request_id: rm.id }).eq('id', ot.id);
  await sb.from('request_history').insert({ request_id: rm.id, actor_id: CURRENT_USER.id, action: 'created', to_status: 'draft' });

  if (submit) {
    const { error: e3 } = await sb.rpc('submit_request', { p_request_id: rm.id });
    if (e3) return toast(e3.message, 'error');
    toast(`${ref} submitted`, 'success');
  } else toast(`${ref} saved`, 'success');
  await refreshBadges();
  route('my-requests');
}

// =============================================================================
// COMP OFF FORM
// =============================================================================
async function renderNewComp() {
  const { data: bal } = await sb.from('comp_off_balances').select('*').eq('user_id', CURRENT_USER.id).maybeSingle();
  const { data: credits } = await sb.from('comp_off_credits')
    .select('*').eq('user_id', CURRENT_USER.id).eq('is_expired', false).order('expires_on');
  const available = bal ? Number(bal.earned_hours)-Number(bal.used_hours)-Number(bal.expired_hours) : 0;

  $('#viewContent').innerHTML = `
    <div class="form-card">
      <h3>New Comp-Off Request</h3>
      <div class="balance-box">
        <b>Available: ${available.toFixed(2)} hours</b>
        ${(credits||[]).length ? `<div style="margin-top:8px;font-size:12px">Credits expiring: ${credits.map(c =>
          `${(c.hours-c.used_hours).toFixed(1)}h → ${fmtDate(c.expires_on)}`).join(' · ')}</div>` : ''}
      </div>
      <div class="grid-2">
        <div class="field"><label class="required">Comp-off date</label><input id="co-date" type="date" /></div>
        <div class="field"><label class="required">Hours requested</label><input id="co-hrs" type="number" step="0.5" min="0.5" /></div>
      </div>
      <div class="field"><label>Full day?</label><select id="co-full">
        <option value="true">Full day</option><option value="false">Partial</option>
      </select></div>
      <div class="field"><label>Reason</label><textarea id="co-reason" rows="2"></textarea></div>
      <div class="btn-row">
        <button class="btn ok" id="co-submit" ${available<=0?'disabled':''}>Submit</button>
      </div>
      ${available<=0 ? '<div class="warn-box" style="margin-top:10px">You have no comp-off balance available. Earn hours via approved overtime with "comp-off" outcome.</div>' : ''}
    </div>
  `;
  $('#co-submit').addEventListener('click', () => submitComp(available));
}

async function submitComp(available) {
  const g = (id) => document.getElementById(id).value.trim();
  const hrs = parseFloat(g('co-hrs'));
  if (!g('co-date') || !hrs || hrs <= 0) return toast('Date and hours required', 'error');
  if (hrs > available) return toast(`Requested ${hrs}h exceeds your balance of ${available.toFixed(2)}h`, 'error');

  const { data: co, error: e1 } = await sb.from('comp_off_requests').insert({
    request_id: null, comp_off_date: g('co-date'),
    hours_requested: hrs, is_full_day: g('co-full') === 'true',
    reason: g('co-reason') || null, balance_at_request: available
  }).select().single();
  if (e1) return toast(e1.message, 'error');

  const { data: ref } = await sb.rpc('generate_ref_no', { p_module: 'comp_off' });
  const { data: rm, error: e2 } = await sb.from('request_master').insert({
    ref_no: ref, module: 'comp_off', module_record_id: co.id,
    title: `Comp-off ${hrs}h on ${fmtDate(g('co-date'))}`,
    summary: g('co-reason')?.slice(0,200) || null,
    requester_id: CURRENT_USER.id, department_id: CURRENT_USER.department_id,
    status: 'draft'
  }).select().single();
  if (e2) return toast(e2.message, 'error');

  await sb.from('comp_off_requests').update({ request_id: rm.id }).eq('id', co.id);
  await sb.from('request_history').insert({ request_id: rm.id, actor_id: CURRENT_USER.id, action: 'created', to_status: 'draft' });

  const { error: e3 } = await sb.rpc('submit_request', { p_request_id: rm.id });
  if (e3) return toast(e3.message, 'error');
  toast(`${ref} submitted`, 'success');
  await refreshBadges();
  route('my-requests');
}

// =============================================================================
// SOP LIBRARY
// =============================================================================
async function renderSopLibrary() {
  $('#viewContent').innerHTML = `
    <div class="filter-bar">
      <input id="sopSearch" placeholder="Search SOPs by number, title, keyword…" />
      <select id="sopStatus">
        <option value="published">Published</option><option value="">All statuses</option>
        <option value="draft">Draft</option><option value="in_review">In Review</option>
        <option value="expired">Expired</option><option value="archived">Archived</option>
        <option value="superseded">Superseded</option>
      </select>
      <span class="count" id="sopCount">—</span>
    </div>
    <div id="sopResults"><div class="loading">Loading SOPs…</div></div>
  `;
  const doSearch = async () => {
    const q = $('#sopSearch').value.trim();
    const s = $('#sopStatus').value;
    let query = sb.from('sops').select('*, owner:profiles!sops_owner_id_fkey(full_name)').order('sop_number');
    if (s) query = query.eq('status', s);
    if (q) query = query.textSearch('search_vector', q, { config: 'english' });
    const { data, error } = await query;
    if (error) { $('#sopResults').innerHTML = `<div class="empty"><h4>Error</h4><p>${escape(error.message)}</p></div>`; return; }
    $('#sopCount').textContent = `${(data||[]).length} SOPs`;
    $('#sopResults').innerHTML = (data||[]).length ? `
      <div class="sop-grid">
        ${data.map(s => `
          <div class="sop-card" data-req="${s.request_id || ''}">
            <div class="num">${escape(s.sop_number)} · v${escape(s.version)}</div>
            <h4>${escape(s.title)}</h4>
            <div style="font-size:12px;color:var(--ink-soft)">${escape((s.purpose||'').slice(0,140))}${(s.purpose||'').length>140?'…':''}</div>
            <div class="meta">
              <span class="status s-${s.status}"><span class="dot"></span>${statusLabel(s.status)}</span>
              <span>${s.category || ''}</span>
            </div>
          </div>
        `).join('')}
      </div>
    ` : emptyRow('No SOPs match your query');
    $$('[data-req]').forEach(el => el.addEventListener('click', () => { if (el.dataset.req) openDrawer(el.dataset.req); }));
  };
  $('#sopSearch').addEventListener('input', () => { clearTimeout(window.__sopDebounce); window.__sopDebounce = setTimeout(doSearch, 300); });
  $('#sopStatus').addEventListener('change', doSearch);
  await doSearch();
}

// =============================================================================
// CHANGE CALENDAR (monthly grid)
// =============================================================================
async function renderChangeCalendar() {
  const today = new Date();
  let month = today.getMonth(), year = today.getFullYear();

  const render = async () => {
    const first = new Date(year, month, 1);
    const last = new Date(year, month+1, 0);
    const { data } = await sb.from('change_calendar').select('*')
      .gte('scheduled_start', first.toISOString())
      .lte('scheduled_start', last.toISOString());

    const byDay = {};
    (data||[]).forEach(e => {
      const d = new Date(e.scheduled_start).getDate();
      (byDay[d] ||= []).push(e);
    });

    const days = last.getDate();
    const startWeekday = first.getDay();
    const cells = [];
    for (let i=0;i<startWeekday;i++) cells.push('<div class="cal-day empty"></div>');
    for (let d=1; d<=days; d++) {
      const evs = byDay[d] || [];
      const isToday = d===today.getDate() && month===today.getMonth() && year===today.getFullYear();
      cells.push(`<div class="cal-day ${isToday?'today':''}">
        <div class="num">${d}</div>
        ${evs.map(e => `<div class="cal-event r-${escape(e.risk)}" data-req="${e.id}" title="${escape(e.ref_no)} · ${escape(e.title)}">${escape(e.ref_no)}</div>`).join('')}
      </div>`);
    }

    $('#viewContent').innerHTML = `
      <div class="panel">
        <div class="panel-head">
          <div style="display:flex;align-items:center;gap:10px">
            <button class="btn secondary btn-sm" id="calPrev">←</button>
            <h3 style="min-width:180px;text-align:center">${first.toLocaleString('en-GB',{month:'long',year:'numeric'})}</h3>
            <button class="btn secondary btn-sm" id="calNext">→</button>
          </div>
          <div class="right">
            <span style="font-size:11px;color:var(--muted)"><span style="display:inline-block;width:12px;height:12px;background:var(--blue);border-radius:2px;vertical-align:middle"></span> Normal &nbsp;
            <span style="display:inline-block;width:12px;height:12px;background:var(--orange);border-radius:2px;vertical-align:middle"></span> High &nbsp;
            <span style="display:inline-block;width:12px;height:12px;background:var(--red-deep);border-radius:2px;vertical-align:middle"></span> Critical</span>
          </div>
        </div>
        <div class="calendar">
          <div class="cal-grid">
            ${['Sun','Mon','Tue','Wed','Thu','Fri','Sat'].map(d => `<div class="cal-day-head">${d}</div>`).join('')}
            ${cells.join('')}
          </div>
        </div>
      </div>
    `;
    $('#calPrev').addEventListener('click', () => { month--; if (month<0) { month=11; year--; } render(); });
    $('#calNext').addEventListener('click', () => { month++; if (month>11) { month=0; year++; } render(); });
    $$('.cal-event').forEach(el => {
      const id = el.dataset.req;
      el.addEventListener('click', async () => {
        // Look up request_master id from change_requests id
        const { data } = await sb.from('change_requests').select('request_id').eq('id', id).single();
        if (data?.request_id) openDrawer(data.request_id);
      });
    });
  };
  await render();
}

// =============================================================================
// ADMIN: ALL REQUESTS
// =============================================================================
async function renderAllRequests() {
  const { data } = await sb.from('request_master')
    .select('*, requester:profiles(full_name)')
    .order('created_at', { ascending: false }).limit(300);
  $('#viewContent').innerHTML = `
    <div class="filter-bar">
      <select id="aMod"><option value="">All modules</option>
        <option value="change_request">Change</option><option value="sop">SOP</option>
        <option value="leave">Leave</option><option value="overtime">Overtime</option><option value="comp_off">Comp Off</option>
      </select>
      <select id="aStatus"><option value="">All statuses</option>
        <option value="submitted">Submitted</option><option value="pending_approval">Pending</option>
        <option value="approved">Approved</option><option value="rejected">Rejected</option>
      </select>
      <input id="aSearch" placeholder="Search title, ref, requester…" />
      <span class="count">${(data||[]).length} records</span>
    </div>
    <div class="panel"><div class="panel-body" id="aList">
      ${renderRowsHeader()}
      ${(data||[]).map(reqRow).join('')}
    </div></div>
  `;
  wireRows();
  const apply = () => {
    const m = $('#aMod').value, s = $('#aStatus').value, q = $('#aSearch').value.toLowerCase().trim();
    const f = (data||[]).filter(r =>
      (!m || r.module===m) && (!s || r.status===s) &&
      (!q || r.title.toLowerCase().includes(q) || r.ref_no.toLowerCase().includes(q) || (r.requester?.full_name||'').toLowerCase().includes(q))
    );
    $('#aList').innerHTML = renderRowsHeader() + (f.length ? f.map(reqRow).join('') : emptyRow('No results'));
    wireRows();
  };
  ['aMod','aStatus','aSearch'].forEach(id => $('#'+id).addEventListener('input', apply));
}

// =============================================================================
// REPORTS
// =============================================================================
async function renderReports() {
  const [byModule, byStatus, avgTime, topApprovers] = await Promise.all([
    sb.from('request_master').select('module', { count:'exact', head:false }),
    sb.from('request_master').select('status', { count:'exact', head:false }),
    sb.from('request_master').select('submitted_at,closed_at,module').not('closed_at','is',null).not('submitted_at','is',null).limit(300),
    sb.from('request_approvals').select('approver:profiles(full_name), decision').not('decided_at','is',null).limit(500)
  ]);

  const countBy = (rows, field) => {
    const m = {};
    (rows||[]).forEach(r => { m[r[field]] = (m[r[field]]||0) + 1; });
    return m;
  };
  const cModule = countBy(byModule.data, 'module');
  const cStatus = countBy(byStatus.data, 'status');
  const approverCounts = {};
  (topApprovers.data || []).forEach(r => {
    const name = r.approver?.full_name; if (!name) return;
    approverCounts[name] = (approverCounts[name] || 0) + 1;
  });
  const avgByModule = {};
  (avgTime.data || []).forEach(r => {
    const hrs = (new Date(r.closed_at) - new Date(r.submitted_at)) / 3600000;
    (avgByModule[r.module] ||= { total:0, n:0 }).total += hrs;
    avgByModule[r.module].n++;
  });

  const bar = (m, color) => {
    const max = Math.max(1, ...Object.values(m));
    return Object.entries(m).sort((a,b)=>b[1]-a[1]).map(([k,v]) =>
      `<div class="bar-row"><div class="bar-label">${escape(statusLabel(k))}</div>
       <div class="bar-track"><div class="bar-fill" style="width:${(v/max*100)}%;${color?'background:'+color:''}">${v}</div></div></div>`
    ).join('');
  };

  $('#viewContent').innerHTML = `
    <div class="stats-grid">
      <div class="stat"><div class="label">Total Requests</div><div class="value">${(byModule.data||[]).length}</div></div>
      <div class="stat"><div class="label">Approved</div><div class="value">${cStatus['approved']||0}</div></div>
      <div class="stat"><div class="label">Rejected</div><div class="value">${cStatus['rejected']||0}</div></div>
      <div class="stat"><div class="label">In Flight</div><div class="value">${(cStatus['submitted']||0)+(cStatus['pending_approval']||0)}</div></div>
    </div>
    <div class="panel"><div class="panel-head"><h3>Requests by module</h3></div><div class="bar-chart">${bar(cModule)}</div></div>
    <div class="panel"><div class="panel-head"><h3>Requests by status</h3></div><div class="bar-chart">${bar(cStatus)}</div></div>
    <div class="panel"><div class="panel-head"><h3>Average cycle time (hours, submitted → closed)</h3></div><div class="bar-chart">${
      Object.entries(avgByModule).map(([k,v]) => {
        const avg = (v.total/v.n).toFixed(1);
        return `<div class="bar-row"><div class="bar-label">${moduleLabel(k)}</div>
         <div class="bar-track"><div class="bar-fill" style="width:${Math.min(100, avg/24*100)}%">${avg}h</div></div></div>`;
      }).join('') || '<p style="color:var(--muted);font-size:12px;padding:10px">No closed requests yet</p>'
    }</div></div>
    <div class="panel"><div class="panel-head"><h3>Top approvers (decisions rendered)</h3></div><div class="bar-chart">${bar(approverCounts) || '<p style="color:var(--muted);font-size:12px;padding:10px">No decisions yet</p>'}</div></div>
  `;
}

// =============================================================================
// CHECKLIST MODULE
// =============================================================================

const CHK_STATUS_LABEL = {
  scheduled:'Scheduled', pending:'Pending', in_progress:'In Progress', submitted:'Submitted',
  reviewed:'Reviewed', completed:'Completed', overdue:'Overdue', missed:'Missed',
  escalated:'Escalated', cancelled:'Cancelled'
};
const CHK_RESP_LABEL = {
  pending:'Pending', done:'Done', not_applicable:'N/A',
  issue_found:'Issue Found', failed:'Failed', deferred:'Deferred'
};

function renderChkRowsHeader() {
  return `<div class="req-row head" style="grid-template-columns:110px 1fr 140px 130px 110px 100px">
    <div>Code</div><div>Checklist</div><div>Period</div><div>Status</div><div>Due</div><div></div>
  </div>`;
}

function chkInstanceRow(i) {
  const overdue = i.due_at && new Date(i.due_at) < new Date() && !['completed','cancelled','missed'].includes(i.status);
  return `<div class="req-row" data-chk="${i.id}" style="grid-template-columns:110px 1fr 140px 130px 110px 100px">
    <div class="req-id">${escape(i.instance_code)}</div>
    <div class="req-title">${escape(i.name_snapshot)}<small>${escape(i.category?.name || '')}</small></div>
    <div class="req-cell mono">${escape(i.period_label || '—')}</div>
    <div class="req-cell"><span class="status s-${i.status}"><span class="dot"></span>${CHK_STATUS_LABEL[i.status]||i.status}</span></div>
    <div class="req-cell mono" ${overdue?'style="color:var(--red-deep)"':''}>${fmtRel(i.due_at)}</div>
    <div class="req-cell" style="text-align:right">›</div>
  </div>`;
}

function wireChkRows() {
  $$('[data-chk]').forEach(el => el.addEventListener('click', () => openChecklistInstance(el.dataset.chk)));
}

async function renderMyChecklistTasks() {
  const { data: m } = await sb.rpc('checklist_metrics');
  const metrics = m || {};

  const { data: instances } = await sb.from('checklist_instances')
    .select('*, category:checklist_categories(name,code)')
    .eq('assigned_to', CURRENT_USER.id)
    .order('due_at', { ascending: true, nullsFirst: false });

  const active = (instances||[]).filter(i => !['completed','cancelled','missed'].includes(i.status));
  const history = (instances||[]).filter(i => ['completed','cancelled','missed'].includes(i.status)).slice(0, 25);

  $('#viewContent').innerHTML = `
    <div class="stats-grid">
      <div class="stat accent"><div class="label">Due Today</div><div class="value">${metrics.my_today ?? 0}</div><div class="sub">scheduled for today</div></div>
      <div class="stat warn"><div class="label">Pending / In Progress</div><div class="value">${metrics.my_pending ?? 0}</div></div>
      <div class="stat danger"><div class="label">Overdue / Escalated</div><div class="value">${metrics.my_overdue ?? 0}</div></div>
      <div class="stat"><div class="label">Completed this month</div><div class="value">${metrics.completed_this_month ?? 0}</div></div>
      <div class="stat"><div class="label">7-day Compliance</div><div class="value">${Number(metrics.compliance_7d ?? 0).toFixed(0)}%</div><div class="sub">rolling average</div></div>
    </div>
    <div class="panel">
      <div class="panel-head"><h3>Active tasks — ${active.length}</h3></div>
      <div class="panel-body">${renderChkRowsHeader()}${active.length ? active.map(chkInstanceRow).join('') : emptyRow('Nothing on your plate. Well done.')}</div>
    </div>
    <div class="panel">
      <div class="panel-head"><h3>History (last 25)</h3></div>
      <div class="panel-body">${renderChkRowsHeader()}${history.length ? history.map(chkInstanceRow).join('') : emptyRow('No history yet')}</div>
    </div>
  `;
  wireChkRows();
}

async function renderAllChecklistTasks() {
  const { data: instances } = await sb.from('checklist_instances')
    .select('*, category:checklist_categories(name), assignee:profiles!checklist_instances_assigned_to_fkey(full_name)')
    .order('scheduled_for', { ascending: false }).limit(300);

  $('#viewContent').innerHTML = `
    <div class="filter-bar">
      <select id="chkfStatus"><option value="">All statuses</option>
        ${Object.entries(CHK_STATUS_LABEL).map(([k,v])=>`<option value="${k}">${v}</option>`).join('')}
      </select>
      <input id="chkfSearch" placeholder="Search code, name, assignee…" />
      <span class="count" id="chkfCount">${(instances||[]).length} tasks</span>
    </div>
    <div class="panel"><div class="panel-body" id="chkList">
      ${renderChkRowsHeader()}
      ${(instances||[]).length ? (instances||[]).map(i => {
        // augment with assignee name in subtitle
        const row = chkInstanceRow(i);
        return row.replace(/<small>[^<]*<\/small>/, `<small>${escape(i.category?.name || '')} · ${escape(i.assignee?.full_name || '—')}</small>`);
      }).join('') : emptyRow('No checklists yet')}
    </div></div>
  `;
  wireChkRows();

  const apply = () => {
    const s = $('#chkfStatus').value;
    const q = $('#chkfSearch').value.toLowerCase().trim();
    const f = (instances||[]).filter(i =>
      (!s || i.status === s) &&
      (!q || i.instance_code.toLowerCase().includes(q)
          || i.name_snapshot.toLowerCase().includes(q)
          || (i.assignee?.full_name||'').toLowerCase().includes(q))
    );
    $('#chkList').innerHTML = renderChkRowsHeader() + (f.length ? f.map(i => {
      const row = chkInstanceRow(i);
      return row.replace(/<small>[^<]*<\/small>/, `<small>${escape(i.category?.name || '')} · ${escape(i.assignee?.full_name || '—')}</small>`);
    }).join('') : emptyRow('No matches'));
    $('#chkfCount').textContent = `${f.length} tasks`;
    wireChkRows();
  };
  ['chkfStatus','chkfSearch'].forEach(id => $('#'+id).addEventListener('input', apply));
}

async function renderChecklistReviewQueue() {
  const { data: pending } = await sb.from('checklist_instances')
    .select('*, category:checklist_categories(name), assignee:profiles!checklist_instances_assigned_to_fkey(full_name)')
    .eq('reviewer_id', CURRENT_USER.id)
    .eq('status', 'submitted')
    .order('submitted_at', { ascending: true });

  const { data: recent } = await sb.from('checklist_instances')
    .select('*, category:checklist_categories(name), assignee:profiles!checklist_instances_assigned_to_fkey(full_name)')
    .eq('reviewer_id', CURRENT_USER.id)
    .in('status', ['completed','cancelled'])
    .order('reviewed_at', { ascending: false }).limit(20);

  $('#viewContent').innerHTML = `
    <div class="panel">
      <div class="panel-head"><h3>Awaiting your review — ${(pending||[]).length}</h3></div>
      <div class="panel-body">${renderChkRowsHeader()}${(pending||[]).length ? pending.map(i => {
        const row = chkInstanceRow(i);
        return row.replace(/<small>[^<]*<\/small>/, `<small>${escape(i.category?.name || '')} · submitted by ${escape(i.assignee?.full_name || '—')}</small>`);
      }).join('') : emptyRow('Nothing awaiting review')}</div>
    </div>
    <div class="panel">
      <div class="panel-head"><h3>Recently reviewed</h3></div>
      <div class="panel-body">${renderChkRowsHeader()}${(recent||[]).length ? recent.map(chkInstanceRow).join('') : emptyRow('No history yet')}</div>
    </div>
  `;
  wireChkRows();
}

async function renderChecklistTemplates() {
  const canManage = isAdmin() || hasRole('it_manager');
  const [{ data: tpls }, { data: cats }] = await Promise.all([
    sb.from('checklist_templates').select('*, category:checklist_categories(name,code)').order('template_code'),
    sb.from('checklist_categories').select('*').eq('is_active', true).order('sort_order')
  ]);

  $('#viewContent').innerHTML = `
    <div class="filter-bar">
      <select id="tplfCat"><option value="">All categories</option>
        ${(cats||[]).map(c => `<option value="${c.id}">${escape(c.name)}</option>`).join('')}
      </select>
      <select id="tplfFreq"><option value="">All frequencies</option>
        <option value="daily">Daily</option><option value="weekly">Weekly</option>
        <option value="monthly">Monthly</option><option value="quarterly">Quarterly</option>
        <option value="one_time">One-time</option><option value="custom">Custom</option>
      </select>
      <input id="tplfSearch" placeholder="Search template…" />
      <span class="count" id="tplfCount">${(tpls||[]).length} templates</span>
      ${canManage ? `<button class="btn btn-sm ok" id="btnNewTpl" style="margin-left:8px">+ New Template</button>
                     <button class="btn btn-sm secondary" id="btnGenToday">Generate Today</button>` : ''}
    </div>
    <div class="panel"><div class="panel-body" id="tplList">
      ${renderTplRowsHeader()}
      ${(tpls||[]).length ? (tpls||[]).map(tplRow).join('') : emptyRow('No templates yet')}
    </div></div>
  `;
  wireTplRows();

  const apply = () => {
    const c = $('#tplfCat').value;
    const fq = $('#tplfFreq').value;
    const q = $('#tplfSearch').value.toLowerCase().trim();
    const f = (tpls||[]).filter(t =>
      (!c || t.category_id === c) &&
      (!fq || t.frequency === fq) &&
      (!q || t.template_code.toLowerCase().includes(q) || t.name.toLowerCase().includes(q))
    );
    $('#tplList').innerHTML = renderTplRowsHeader() + (f.length ? f.map(tplRow).join('') : emptyRow('No matches'));
    $('#tplfCount').textContent = `${f.length} templates`;
    wireTplRows();
  };
  ['tplfCat','tplfFreq','tplfSearch'].forEach(id => $('#'+id).addEventListener('input', apply));

  if (canManage) {
    $('#btnNewTpl').addEventListener('click', () => openTemplateEditor(null));
    $('#btnGenToday').addEventListener('click', async () => {
      if (!confirm('Generate checklist instances for today?')) return;
      const { data, error } = await sb.rpc('generate_checklist_instances', { p_date: new Date().toISOString().slice(0,10) });
      if (error) { toast(error.message, 'error'); return; }
      toast(`Generated ${data ?? 0} instance(s) for today`, 'success');
      route('chk-my-tasks');
    });
  }
}
function renderTplRowsHeader() {
  return `<div class="req-row head" style="grid-template-columns:140px 1fr 140px 100px 110px 80px">
    <div>Code</div><div>Template</div><div>Category</div><div>Frequency</div><div>Due</div><div>Active</div>
  </div>`;
}
function tplRow(t) {
  return `<div class="req-row" data-tpl="${t.id}" style="grid-template-columns:140px 1fr 140px 100px 110px 80px">
    <div class="req-id">${escape(t.template_code)}</div>
    <div class="req-title">${escape(t.name)}<small>${escape((t.description||'').slice(0,80))}</small></div>
    <div class="req-cell">${escape(t.category?.name || '—')}</div>
    <div class="req-cell mono">${escape(t.frequency)}</div>
    <div class="req-cell mono">${t.due_time ? escape(t.due_time.slice(0,5)) : '—'}</div>
    <div class="req-cell">${t.is_active ? '<span class="status s-approved"><span class="dot"></span>Active</span>' : '<span class="status s-cancelled"><span class="dot"></span>Off</span>'}</div>
  </div>`;
}
function wireTplRows() {
  $$('[data-tpl]').forEach(el => el.addEventListener('click', () => openTemplateViewer(el.dataset.tpl)));
}

async function openTemplateViewer(templateId) {
  $('#drawerBg').classList.add('show');
  $('#drawerBody').innerHTML = '<div class="loading">Loading…</div>';
  $('#drawerTitle').textContent = 'Loading…';

  const [{ data: t }, { data: items }] = await Promise.all([
    sb.from('checklist_templates').select('*, category:checklist_categories(name,code), assigned_user:profiles!checklist_templates_assigned_user_id_fkey(full_name), assigned_role:roles!checklist_templates_assigned_role_id_fkey(name), reviewer_user:profiles!checklist_templates_reviewer_user_id_fkey(full_name), reviewer_role:roles!checklist_templates_reviewer_role_id_fkey(name)').eq('id', templateId).single(),
    sb.from('checklist_template_items').select('*').eq('template_id', templateId).order('seq')
  ]);
  if (!t) return;

  $('#drawerTitle').textContent = t.name;
  $('#drawerRef').innerHTML = `${escape(t.template_code)} · ${escape(t.category?.name || '')}`;

  const canManage = isAdmin() || hasRole('it_manager');

  $('#drawerBody').innerHTML = `
    <div class="detail-meta">
      <div class="m-item"><label>Frequency</label><span>${escape(t.frequency)}</span></div>
      <div class="m-item"><label>Due time</label><span>${t.due_time ? t.due_time.slice(0,5) : '—'}</span></div>
      <div class="m-item"><label>Assigned to</label><span>${escape(t.assigned_user?.full_name || t.assigned_role?.name || '—')}</span></div>
      <div class="m-item"><label>Reviewer</label><span>${escape(t.reviewer_user?.full_name || t.reviewer_role?.name || '—')}</span></div>
      <div class="m-item"><label>Grace hours</label><span>${t.grace_period_hours ?? '—'}</span></div>
      <div class="m-item"><label>Status</label><span>${t.is_active ? 'Active' : 'Inactive'}</span></div>
    </div>
    ${t.description ? `<div class="detail-section"><h4>Description</h4><p>${escape(t.description)}</p></div>` : ''}
    <div class="detail-section">
      <h4>Checklist Items (${(items||[]).length})</h4>
      ${(items||[]).map(it => `
        <div class="comment">
          <div class="comment-head">
            <div><span class="comment-author">${it.seq}. ${escape(it.title)}</span>
            ${it.is_required ? '<span class="comment-flag">required</span>' : ''}
            ${it.evidence_mandatory ? '<span class="comment-flag" style="background:var(--blue)">evidence</span>' : ''}
            </div>
            <span class="comment-time">${escape(it.response_type)}</span>
          </div>
          ${it.description ? `<div class="comment-body">${escape(it.description)}</div>` : ''}
          ${it.expected_value ? `<div style="margin-top:4px;font-size:11px;color:var(--muted)">Expected: <code>${escape(it.expected_value)}</code></div>` : ''}
        </div>`).join('') || '<p style="color:var(--muted);font-size:12px">No items defined</p>'}
    </div>
    ${canManage ? `<div class="btn-row">
      <button class="btn ok btn-sm" id="btnEditTpl">Edit Template</button>
      <button class="btn warn btn-sm" id="btnGenThis">Generate instance now</button>
      <button class="btn ${t.is_active?'secondary':'ok'} btn-sm" id="btnToggleTpl">${t.is_active ? 'Deactivate' : 'Activate'}</button>
      <button class="btn danger btn-sm" id="btnDeleteTpl">Delete</button>
    </div>` : ''}
  `;

  if (canManage) {
    $('#btnEditTpl').addEventListener('click', () => openTemplateEditor(templateId));
    $('#btnGenThis').addEventListener('click', async () => {
      const { error } = await sb.rpc('generate_checklist_instances', { p_date: new Date().toISOString().slice(0,10) });
      if (error) { toast(error.message, 'error'); return; }
      toast('Instance generation triggered', 'success');
    });
    $('#btnToggleTpl').addEventListener('click', async () => {
      const { error } = await sb.from('checklist_templates').update({ is_active: !t.is_active }).eq('id', t.id);
      if (error) { toast(error.message, 'error'); return; }
      toast(`Template ${t.is_active ? 'deactivated' : 'activated'}`, 'success');
      openTemplateViewer(templateId);
    });
    $('#btnDeleteTpl').addEventListener('click', async () => {
      if (!confirm(`Delete template "${t.name}"?\n\nThis will also delete all of its items. Existing instances are preserved.`)) return;
      const { error } = await sb.from('checklist_templates').delete().eq('id', t.id);
      if (error) { toast(error.message, 'error'); return; }
      toast('Template deleted', 'success');
      closeDrawer();
      route('chk-templates');
    });
  }
}

// ========== TEMPLATE EDITOR (Create / Edit) — IT Manager only ==========
async function openTemplateEditor(templateId) {
  if (!isAdmin() && !hasRole('it_manager')) {
    toast('Only IT Manager can manage templates', 'error');
    return;
  }

  $('#drawerBg').classList.add('show');
  $('#drawerBody').innerHTML = '<div class="loading">Loading…</div>';
  $('#drawerTitle').textContent = templateId ? 'Edit Template' : 'New Template';
  $('#drawerRef').innerHTML = templateId ? 'Editing…' : 'Create a recurring checklist';

  // Load reference data
  const [{ data: cats }, { data: engineers }, tplRes, itemsRes] = await Promise.all([
    sb.from('checklist_categories').select('*').eq('is_active', true).order('sort_order'),
    sb.from('profiles').select('id, full_name, email, designation').eq('is_active', true).order('full_name'),
    templateId ? sb.from('checklist_templates').select('*').eq('id', templateId).single() : Promise.resolve({ data: null }),
    templateId ? sb.from('checklist_template_items').select('*').eq('template_id', templateId).order('seq') : Promise.resolve({ data: [] })
  ]);
  const t = tplRes.data || {};
  let items = itemsRes.data || [];

  // Start with one blank item if creating new
  if (!templateId && items.length === 0) {
    items = [{ seq: 1, title: '', description: '', response_type: 'yes_no', is_required: true, remarks_mandatory: false, evidence_mandatory: false, expected_value: '' }];
  }

  $('#drawerBody').innerHTML = `
    <div class="form-section">
      <h4>Template Basics</h4>
      <div class="grid-2">
        <div class="field"><label>Template Code <span style="font-weight:400;color:var(--muted)">(optional — auto-generated if blank)</span></label>
          <input id="te-code" value="${escape(t.template_code || '')}" placeholder="Auto-generated if blank (e.g. TPL-BACKUP-DAILY)" />
        </div>
        <div class="field"><label class="required">Template Name</label>
          <input id="te-name" value="${escape(t.name || '')}" placeholder="Daily Backup Verification" />
        </div>
        <div class="field"><label class="required">Category</label>
          <select id="te-cat">
            <option value="">— select —</option>
            ${(cats||[]).map(c => `<option value="${c.id}" ${t.category_id===c.id?'selected':''}>${escape(c.name)}</option>`).join('')}
          </select>
        </div>
        <div class="field"><label class="required">Frequency</label>
          <select id="te-freq">
            ${['daily','weekly','monthly','quarterly','one_time'].map(f =>
              `<option value="${f}" ${t.frequency===f?'selected':''}>${f.charAt(0).toUpperCase()+f.slice(1).replace('_',' ')}</option>`
            ).join('')}
          </select>
        </div>
        <div class="field"><label>Due time (local)</label>
          <input id="te-due" type="time" value="${t.due_time ? t.due_time.slice(0,5) : '10:00'}" />
        </div>
        <div class="field"><label>Grace period (hours)</label>
          <input id="te-grace" type="number" min="0" max="72" value="${t.grace_period_hours ?? 4}" />
        </div>
      </div>
      <div class="field"><label>Description</label>
        <textarea id="te-desc" rows="2">${escape(t.description || '')}</textarea>
      </div>
    </div>

    <div class="form-section">
      <h4>Assignment</h4>
      <div class="grid-2">
        <div class="field"><label class="required">Assigned Engineer</label>
          <select id="te-engineer">
            <option value="">— select engineer —</option>
            ${(engineers||[]).filter(e => e.id !== CURRENT_USER.id).map(e =>
              `<option value="${e.id}" ${t.assigned_user_id===e.id?'selected':''}>${escape(e.full_name)} — ${escape(e.designation||'')}</option>`
            ).join('')}
          </select>
          <div class="help">This engineer will receive the checklist automatically per the frequency above.</div>
        </div>
        <div class="field"><label>Reviewer / Approver</label>
          <input value="${escape(CURRENT_USER.full_name)} (IT Manager)" readonly style="background:var(--green-50)" />
          <div class="help">All checklists are reviewed by the IT Manager — fixed by policy.</div>
        </div>
      </div>
      <div class="grid-2">
        <div class="field"><label><input type="checkbox" id="te-evidence" ${t.evidence_required?'checked':''}/> Evidence required by default</label></div>
        <div class="field"><label><input type="checkbox" id="te-remarks" ${t.remarks_required?'checked':''}/> Remarks required by default</label></div>
      </div>
      <div class="field"><label><input type="checkbox" id="te-active" ${t.is_active !== false ? 'checked' : ''}/> Active (generates instances)</label></div>
    </div>

    <div class="form-section">
      <h4>Checklist Items</h4>
      <div id="te-items"></div>
      <div class="btn-row">
        <button class="btn secondary btn-sm" id="btnAddItem">+ Add item</button>
      </div>
    </div>

    <div class="btn-row" style="border-top:1px solid var(--line);padding-top:14px;margin-top:18px">
      <button class="btn ok" id="btnSaveTpl">${templateId ? 'Save Changes' : 'Create Template'}</button>
      <button class="btn secondary" id="btnCancelTpl">Cancel</button>
    </div>
  `;

  // Render items editor
  const itemsContainer = $('#te-items');
  let editingItems = [...items];

  const renderItems = () => {
    itemsContainer.innerHTML = editingItems.map((it, idx) => `
      <div class="comment" data-idx="${idx}" style="margin-bottom:10px">
        <div class="comment-head">
          <div><span class="comment-author">#${idx+1}</span></div>
          <button class="btn danger btn-sm" data-remove="${idx}" style="padding:3px 10px;font-size:11px">Remove</button>
        </div>
        <div class="grid-2" style="margin-top:6px">
          <div class="field"><label>Title</label><input data-field="title" data-idx="${idx}" value="${escape(it.title||'')}" /></div>
          <div class="field"><label>Response type</label>
            <select data-field="response_type" data-idx="${idx}">
              ${['yes_no','pass_fail','done_not_done','text','number','datetime','dropdown'].map(r =>
                `<option value="${r}" ${it.response_type===r?'selected':''}>${r.replace(/_/g,' ')}</option>`
              ).join('')}
            </select>
          </div>
        </div>
        <div class="field"><label>Description (optional)</label>
          <textarea data-field="description" data-idx="${idx}" rows="1">${escape(it.description||'')}</textarea>
        </div>
        <div class="grid-3">
          <div class="field"><label>Expected value</label>
            <input data-field="expected_value" data-idx="${idx}" value="${escape(it.expected_value||'')}" placeholder="e.g. yes, pass" />
          </div>
          <div class="field"><label><input type="checkbox" data-field="is_required" data-idx="${idx}" ${it.is_required?'checked':''}/> Required</label></div>
          <div class="field"><label><input type="checkbox" data-field="evidence_mandatory" data-idx="${idx}" ${it.evidence_mandatory?'checked':''}/> Evidence required</label></div>
        </div>
      </div>
    `).join('') || '<p style="color:var(--muted);font-size:12px;padding:8px 0">No items. Click "Add item" below.</p>';

    // Wire inputs
    itemsContainer.querySelectorAll('[data-field]').forEach(el => {
      el.addEventListener('change', (e) => {
        const idx = parseInt(e.target.dataset.idx);
        const field = e.target.dataset.field;
        const val = e.target.type === 'checkbox' ? e.target.checked : e.target.value;
        editingItems[idx][field] = val;
      });
      el.addEventListener('input', (e) => {
        const idx = parseInt(e.target.dataset.idx);
        const field = e.target.dataset.field;
        if (e.target.type !== 'checkbox') editingItems[idx][field] = e.target.value;
      });
    });
    itemsContainer.querySelectorAll('[data-remove]').forEach(el => {
      el.addEventListener('click', () => {
        editingItems.splice(parseInt(el.dataset.remove), 1);
        renderItems();
      });
    });
  };
  renderItems();

  $('#btnAddItem').addEventListener('click', () => {
    editingItems.push({
      seq: editingItems.length + 1,
      title: '', description: '', response_type: 'yes_no',
      is_required: true, remarks_mandatory: false, evidence_mandatory: false,
      expected_value: ''
    });
    renderItems();
  });

  $('#btnCancelTpl').addEventListener('click', closeDrawer);

  $('#btnSaveTpl').addEventListener('click', async () => {
    const btn = $('#btnSaveTpl');
    btn.disabled = true;
    btn.innerHTML = '<span class="spin"></span> Saving…';
    try {
      let code = $('#te-code').value.trim();
      const name = $('#te-name').value.trim();
      const catId = $('#te-cat').value;
      const freq = $('#te-freq').value;
      const engineerId = $('#te-engineer').value;
      if (!name || !catId || !freq || !engineerId) {
        toast('Name, category, frequency, and engineer are required', 'error');
        return;
      }
      if (editingItems.length === 0 || editingItems.some(i => !i.title?.trim())) {
        toast('At least one item required; every item must have a title', 'error');
        return;
      }

      // Auto-generate code if blank
      if (!code) {
        const year = new Date().getFullYear();
        const rand = Math.floor(Math.random() * 9000) + 1000;
        const prefix = name.replace(/[^a-zA-Z0-9]/g, '-').toUpperCase().substring(0, 8);
        code = `TPL-${prefix}-${year}-${rand}`;
        $('#te-code').value = code;
      }

      // Check for duplicate code (only on new templates)
      if (!templateId) {
        const { data: existing } = await sb.from('checklist_templates')
          .select('id').eq('template_code', code).maybeSingle();
        if (existing) {
          // Auto-fix: append random suffix
          code = code + '-' + Math.floor(Math.random() * 900 + 100);
          $('#te-code').value = code;
        }
      }

      const payload = {
        template_code: code,
        name: name,
        category_id: catId,
        description: $('#te-desc').value.trim() || null,
        frequency: freq,
        due_time: $('#te-due').value || null,
        grace_period_hours: parseInt($('#te-grace').value) || 4,
        assigned_user_id: engineerId,
        assigned_role_id: null,  // direct user assignment only
        evidence_required: $('#te-evidence').checked,
        remarks_required: $('#te-remarks').checked,
        is_active: $('#te-active').checked
      };

      let tplId = templateId;
      if (templateId) {
        const { error } = await sb.from('checklist_templates').update(payload).eq('id', templateId);
        if (error) { toast(error.message, 'error'); return; }
      } else {
        payload.created_by = CURRENT_USER.id;
        const { data, error } = await sb.from('checklist_templates').insert(payload).select().single();
        if (error) { toast(error.message, 'error'); return; }
        tplId = data.id;
      }

      // Save items atomically via RPC (handles existing instance references)
      const itemsPayload = editingItems.map(it => ({
        id: it.id || null,   // include ID if editing existing item, null if new
        title: it.title.trim(),
        description: it.description?.trim() || null,
        response_type: it.response_type,
        is_required: !!it.is_required,
        remarks_mandatory: !!it.remarks_mandatory,
        evidence_mandatory: !!it.evidence_mandatory,
        expected_value: it.expected_value?.trim() || null
      }));

      const { data: saveResult, error: iErr } = await sb.rpc('save_checklist_template_items', {
        p_template_id: tplId,
        p_items: itemsPayload
      });
      if (iErr) { toast('Items save failed: ' + iErr.message, 'error'); return; }

      // Show a helpful message if some items couldn't be deleted because they're in use
      if (saveResult?.kept_in_use > 0) {
        toast(`Template saved. ${saveResult.kept_in_use} old item(s) kept as they are referenced by existing checklist instances.`, 'info', 6000);
      }

      toast(templateId ? 'Template updated' : 'Template created', 'success');
      closeDrawer();
      route('chk-templates');
    } finally {
      btn.disabled = false;
      btn.textContent = templateId ? 'Save Changes' : 'Create Template';
    }
  });
}

async function openChecklistInstance(instanceId) {
  $('#drawerBg').classList.add('show');
  $('#drawerBody').innerHTML = '<div class="loading">Loading…</div>';
  $('#drawerTitle').textContent = 'Loading…';

  const [
    { data: inst },
    { data: items },
    { data: history },
    { data: reviews }
  ] = await Promise.all([
    sb.from('checklist_instances').select('*, category:checklist_categories(name), assignee:profiles!checklist_instances_assigned_to_fkey(full_name), reviewer:profiles!checklist_instances_reviewer_id_fkey(full_name)').eq('id', instanceId).single(),
    sb.from('checklist_instance_items').select('*').eq('instance_id', instanceId).order('seq'),
    sb.from('checklist_history').select('*, actor:profiles(full_name)').eq('instance_id', instanceId).order('occurred_at'),
    sb.from('checklist_reviews').select('*, reviewer:profiles(full_name)').eq('instance_id', instanceId).order('reviewed_at', { ascending: false })
  ]);
  if (!inst) return;

  const isAssignee = inst.assigned_to === CURRENT_USER.id;
  const isReviewer = inst.reviewer_id === CURRENT_USER.id;
  const canRespond = isAssignee && ['pending','in_progress','overdue','escalated'].includes(inst.status);
  const canReview = isReviewer && inst.status === 'submitted';

  $('#drawerTitle').textContent = inst.name_snapshot;
  $('#drawerRef').innerHTML = `${escape(inst.instance_code)} · ${escape(inst.category?.name || '')} · <span class="status s-${inst.status}"><span class="dot"></span>${CHK_STATUS_LABEL[inst.status]}</span>`;

  const totalItems = (items||[]).length;
  const doneItems = (items||[]).filter(i => i.response_status !== 'pending').length;

  $('#drawerBody').innerHTML = `
    <div class="detail-meta">
      <div class="m-item"><label>Period</label><span>${escape(inst.period_label || '—')}</span></div>
      <div class="m-item"><label>Due</label><span>${fmtDateTime(inst.due_at)}</span></div>
      <div class="m-item"><label>Assignee</label><span>${escape(inst.assignee?.full_name || '—')}</span></div>
      <div class="m-item"><label>Reviewer</label><span>${escape(inst.reviewer?.full_name || '—')}</span></div>
      <div class="m-item"><label>Progress</label><span>${doneItems} / ${totalItems} items</span></div>
      <div class="m-item"><label>Completion</label><span>${Number(inst.completion_pct || 0).toFixed(0)}%</span></div>
    </div>

    <div class="detail-section">
      <h4>Items</h4>
      <div id="chkItemsList">
        ${(items||[]).map(it => renderChkItem(it, canRespond)).join('')}
      </div>
    </div>

    ${canRespond ? `<div class="btn-row">
      <button class="btn ok" id="btnSubmitChk">Submit for Review</button>
    </div>` : ''}

    ${canReview ? `<div class="form-card" style="background:var(--green-50);border-color:var(--green-500)">
      <h3 style="font-size:16px">Review Decision</h3>
      <div class="field"><label>Comments</label><textarea id="revComments" rows="2"></textarea></div>
      <div class="btn-row">
        <button class="btn ok" id="btnApproveChk">✓ Approve</button>
        <button class="btn warn" id="btnReturnChk">↶ Return for rework</button>
        <button class="btn danger" id="btnRejectChk">✕ Reject</button>
      </div>
    </div>` : ''}

    ${(reviews||[]).length ? `<div class="detail-section">
      <h4>Reviews</h4>
      ${reviews.map(r => `<div class="comment">
        <div class="comment-head">
          <div><span class="comment-author">${escape(r.reviewer?.full_name)}</span> decided <b style="color:${r.decision==='approved'?'var(--green-700)':r.decision==='rejected'?'var(--red-deep)':'var(--orange)'}">${escape(r.decision)}</b></div>
          <span class="comment-time">${fmtDateTime(r.reviewed_at)}</span>
        </div>
        ${r.comments ? `<div class="comment-body">${escape(r.comments)}</div>` : ''}
      </div>`).join('')}
    </div>` : ''}

    <div class="detail-section">
      <h4>Audit Trail</h4>
      <div class="timeline">
        ${(history||[]).map(h => `<div class="tl-step done">
          <h5>${escape(h.action)}</h5>
          <div class="meta">${escape(h.actor?.full_name || 'system')} · ${fmtDateTime(h.occurred_at)}</div>
        </div>`).join('') || '<p style="color:var(--muted);font-size:12px">No events yet</p>'}
      </div>
    </div>
  `;

  // Wire item response inputs
  if (canRespond) {
    (items||[]).forEach(it => wireChkItemEvents(it, instanceId));
    $('#btnSubmitChk').addEventListener('click', () => submitChecklistInstance(instanceId));
  }
  if (canReview) {
    $('#btnApproveChk').addEventListener('click', () => reviewChecklistInstance(instanceId, 'approved'));
    $('#btnReturnChk').addEventListener('click', () => reviewChecklistInstance(instanceId, 'returned'));
    $('#btnRejectChk').addEventListener('click', () => reviewChecklistInstance(instanceId, 'rejected'));
  }
}

function renderChkItem(it, editable) {
  const status = it.response_status;
  const statusClass = `status s-${status==='done'?'approved':status==='issue_found'||status==='failed'?'rejected':status==='not_applicable'?'closed':'pending_approval'}`;

  let inputHtml = '';
  if (editable) {
    switch (it.response_type) {
      case 'yes_no':
        inputHtml = `<select data-item="${it.id}" data-field="response_value">
          <option value="">— select —</option>
          <option value="yes" ${it.response_value==='yes'?'selected':''}>Yes</option>
          <option value="no" ${it.response_value==='no'?'selected':''}>No</option>
        </select>`; break;
      case 'pass_fail':
        inputHtml = `<select data-item="${it.id}" data-field="response_value">
          <option value="">— select —</option>
          <option value="pass" ${it.response_value==='pass'?'selected':''}>Pass</option>
          <option value="fail" ${it.response_value==='fail'?'selected':''}>Fail</option>
        </select>`; break;
      case 'done_not_done':
        inputHtml = `<select data-item="${it.id}" data-field="response_value">
          <option value="">— select —</option>
          <option value="done" ${it.response_value==='done'?'selected':''}>Done</option>
          <option value="not_done" ${it.response_value==='not_done'?'selected':''}>Not Done</option>
        </select>`; break;
      case 'number':
        inputHtml = `<input type="number" step="0.01" data-item="${it.id}" data-field="response_number" value="${it.response_number ?? ''}" />`; break;
      case 'text':
        inputHtml = `<textarea rows="2" data-item="${it.id}" data-field="response_value">${escape(it.response_value||'')}</textarea>`; break;
      case 'datetime':
        inputHtml = `<input type="datetime-local" data-item="${it.id}" data-field="response_datetime" value="${it.response_datetime ? new Date(it.response_datetime).toISOString().slice(0,16) : ''}" />`; break;
      case 'dropdown':
        inputHtml = `<select data-item="${it.id}" data-field="response_value">
          <option value="">— select —</option>
          ${(it.options_snapshot||[]).map(o => `<option ${it.response_value===o?'selected':''}>${escape(o)}</option>`).join('')}
        </select>`; break;
      default:
        inputHtml = `<textarea rows="2" data-item="${it.id}" data-field="response_value">${escape(it.response_value||'')}</textarea>`;
    }
  } else {
    inputHtml = `<div style="font-size:13px;color:var(--ink-soft);padding:6px 0">
      ${escape(it.response_value ?? it.response_number ?? it.response_datetime ?? '(no response)')}
    </div>`;
  }

  return `<div class="comment" style="margin-bottom:14px">
    <div class="comment-head">
      <div>
        <span class="comment-author">${it.seq}. ${escape(it.title_snapshot)}</span>
        ${it.is_required ? '<span class="comment-flag">required</span>' : ''}
        ${it.evidence_mandatory ? '<span class="comment-flag" style="background:var(--blue)">evidence</span>' : ''}
        ${it.is_flagged ? '<span class="comment-flag" style="background:var(--red-deep)">flagged</span>' : ''}
      </div>
      <span class="${statusClass}"><span class="dot"></span>${CHK_RESP_LABEL[status]||status}</span>
    </div>
    <div style="margin-top:6px">${inputHtml}</div>
    ${editable ? `
      <div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap">
        <select data-item="${it.id}" data-field="response_status" style="width:auto;font-size:12px;padding:5px 8px">
          ${Object.entries(CHK_RESP_LABEL).map(([k,v]) => `<option value="${k}" ${it.response_status===k?'selected':''}>${v}</option>`).join('')}
        </select>
        ${it.evidence_mandatory ? `<input type="file" data-item="${it.id}" data-field="evidence" style="font-size:11px" />` : ''}
      </div>
      <textarea data-item="${it.id}" data-field="remarks" rows="1" placeholder="Remarks${it.remarks_mandatory?' (required)':''}" style="margin-top:6px;font-size:12px">${escape(it.remarks||'')}</textarea>
    ` : ''}
  </div>`;
}

function wireChkItemEvents(it, instanceId) {
  document.querySelectorAll(`[data-item="${it.id}"]`).forEach(el => {
    const field = el.dataset.field;
    if (field === 'evidence') {
      el.addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (!file) return;
        const path = `checklists/${instanceId}/${it.id}_${Date.now()}_${file.name}`;
        const { error: upErr } = await sb.storage.from(CFG.STORAGE_BUCKET).upload(path, file);
        if (upErr) { toast(upErr.message, 'error'); return; }
        await sb.from('checklist_instance_items').update({ evidence_path: path, evidence_filename: file.name }).eq('id', it.id);
        toast('Evidence uploaded', 'success');
      });
    } else {
      el.addEventListener('change', () => debouncedSave(it.id, field, el.value, instanceId));
      el.addEventListener('blur',   () => debouncedSave(it.id, field, el.value, instanceId));
    }
  });
}

const _saveTimers = {};
function debouncedSave(itemId, field, value, instanceId) {
  clearTimeout(_saveTimers[itemId + field]);
  _saveTimers[itemId + field] = setTimeout(() => persistItemResponse(itemId, field, value, instanceId), 400);
}

async function persistItemResponse(itemId, field, value, instanceId) {
  const patch = { responded_at: new Date().toISOString(), responded_by: CURRENT_USER.id };
  if (field === 'response_number') patch[field] = value === '' ? null : Number(value);
  else if (field === 'response_datetime') patch[field] = value || null;
  else patch[field] = value || null;

  const { error } = await sb.from('checklist_instance_items').update(patch).eq('id', itemId);
  if (error) { toast(error.message, 'error'); return; }

  // Also update parent instance status to in_progress if it's still pending
  await sb.from('checklist_instances').update({
    status: 'in_progress',
    started_at: new Date().toISOString()
  }).eq('id', instanceId).eq('status', 'pending');
}

async function submitChecklistInstance(instanceId) {
  const btn = $('#btnSubmitChk');
  btn.disabled = true;
  btn.innerHTML = '<span class="spin"></span> Submitting…';
  const { error } = await sb.rpc('submit_checklist_instance', { p_instance_id: instanceId });
  if (error) {
    btn.disabled = false; btn.textContent = 'Submit for Review';
    toast(error.message, 'error'); return;
  }
  toast('Submitted for review', 'success');
  await refreshBadges();
  await openChecklistInstance(instanceId);
  route(CURRENT_VIEW);
}

async function reviewChecklistInstance(instanceId, decision) {
  const comments = $('#revComments')?.value?.trim() || null;
  if ((decision === 'returned' || decision === 'rejected') && !comments) {
    toast('Please provide a comment', 'error'); return;
  }
  const btn = decision==='approved' ? $('#btnApproveChk') : decision==='returned' ? $('#btnReturnChk') : $('#btnRejectChk');
  if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spin"></span> Processing…'; }

  const { error } = await sb.rpc('review_checklist_instance',
    { p_instance_id: instanceId, p_decision: decision, p_comments: comments });
  if (error) { toast(error.message, 'error'); if (btn) btn.disabled = false; return; }
  toast(`Decision: ${decision}`, 'success');
  await refreshBadges();
  await openChecklistInstance(instanceId);
  route(CURRENT_VIEW);
}

async function renderChecklistCompliance() {
  const { data: all } = await sb.from('checklist_instances')
    .select('status, category:checklist_categories(name), scheduled_for, assigned_to, template_id, assignee:profiles!checklist_instances_assigned_to_fkey(full_name)')
    .gte('scheduled_for', new Date(Date.now() - 30*86400000).toISOString().slice(0,10))
    .limit(2000);

  const byStatus = {};
  const byCategory = {};
  const byUser = {};
  (all||[]).forEach(r => {
    byStatus[r.status] = (byStatus[r.status]||0) + 1;
    if (r.category) byCategory[r.category.name] = (byCategory[r.category.name]||0) + 1;
    if (r.assignee) {
      const key = r.assignee.full_name;
      byUser[key] = byUser[key] || { total:0, completed:0, overdue:0 };
      byUser[key].total++;
      if (r.status === 'completed') byUser[key].completed++;
      if (['overdue','escalated','missed'].includes(r.status)) byUser[key].overdue++;
    }
  });

  const bar = (m, max, fmt) => {
    const mx = max || Math.max(1, ...Object.values(m));
    return Object.entries(m).sort((a,b)=>b[1]-a[1]).map(([k,v]) =>
      `<div class="bar-row"><div class="bar-label">${escape(k)}</div>
       <div class="bar-track"><div class="bar-fill" style="width:${(v/mx*100)}%">${fmt?fmt(v):v}</div></div></div>`
    ).join('');
  };

  const total = (all||[]).length;
  const completed = byStatus['completed']||0;
  const overdue = (byStatus['overdue']||0) + (byStatus['escalated']||0) + (byStatus['missed']||0);
  const compliance = total > 0 ? ((completed / total) * 100).toFixed(1) : '—';

  $('#viewContent').innerHTML = `
    <div class="stats-grid">
      <div class="stat accent"><div class="label">30-day Compliance</div><div class="value">${compliance}%</div><div class="sub">${completed} / ${total}</div></div>
      <div class="stat"><div class="label">Total Tasks</div><div class="value">${total}</div></div>
      <div class="stat warn"><div class="label">In Flight</div><div class="value">${(byStatus['pending']||0)+(byStatus['in_progress']||0)+(byStatus['submitted']||0)}</div></div>
      <div class="stat danger"><div class="label">Overdue / Missed</div><div class="value">${overdue}</div></div>
    </div>
    <div class="panel"><div class="panel-head"><h3>By status</h3></div><div class="bar-chart">${bar(byStatus)}</div></div>
    <div class="panel"><div class="panel-head"><h3>By category</h3></div><div class="bar-chart">${bar(byCategory)}</div></div>
    <div class="panel"><div class="panel-head"><h3>Per-user compliance</h3></div><div class="bar-chart">${
      Object.entries(byUser).sort((a,b)=>b[1].total-a[1].total).map(([name, s]) => {
        const pct = s.total > 0 ? ((s.completed/s.total)*100).toFixed(0) : 0;
        return `<div class="bar-row"><div class="bar-label">${escape(name)}</div>
          <div class="bar-track"><div class="bar-fill" style="width:${pct}%">${pct}% (${s.completed}/${s.total})</div></div></div>`;
      }).join('') || '<p style="color:var(--muted);font-size:12px;padding:10px">No data</p>'
    }</div></div>
  `;
}

// =============================================================================
// GOVERNANCE MODULES: Onboarding/Offboarding, Access, Asset Handover, Licenses
// =============================================================================

const ONB_SERVICES = [
  ['email','Email / M365 mailbox'],['laptop','Laptop'],['desktop','Desktop'],
  ['vpn','VPN / SSL-VPN'],['erp_sap','SAP'],['erp_netsuite','NetSuite'],
  ['pos_compucash','CompuCash POS'],['printer','Printer'],['shared_folder','Shared folder'],
  ['phone_desk','Desk phone / Yeastar'],['phone_mobile','Mobile phone / SIM'],
  ['mfa_token','MFA registration'],['entra_account','Entra ID account'],
  ['domain_account','Domain account'],['ad_account','AD account'],
  ['intune_enrollment','Intune enrollment'],['teams','Teams channels'],
  ['sharepoint','SharePoint access'],['defender_license','Defender license'],
  ['copilot_license','Copilot license'],['contentverse','Contentverse DMS'],
  ['other','Other (specify)']
];

const ASSET_TYPES = [
  'laptop','desktop','monitor','phone','tablet','printer','scanner',
  'network_device','server','ups','docking_station','headset','keyboard_mouse',
  'accessory','sim_card','other'
];

const LIC_TYPES = [
  ['software_license','Software License'],['saas_subscription','SaaS Subscription'],
  ['domain','Domain'],['ssl_certificate','SSL Certificate'],
  ['cloud_service','Cloud Service'],['support_contract','Support Contract'],
  ['maintenance_contract','Maintenance Contract'],['antivirus','Antivirus'],
  ['backup_subscription','Backup Subscription'],['hosting','Hosting'],['other','Other']
];

// ---------------- ONBOARDING / OFFBOARDING ----------------
function renderNewOnboarding(kind) {
  const isOnb = kind === 'onboarding';
  $('#viewContent').innerHTML = `
    <div class="form-card">
      <h3>${isOnb ? 'New Employee Onboarding' : 'Employee Offboarding'}</h3>
      <div class="form-section">
        <h4>Employee Details</h4>
        <div class="grid-2">
          <div class="field"><label class="required">Full name</label><input id="onb-name" /></div>
          <div class="field"><label>Employee code</label><input id="onb-code" placeholder="EMP-XXX-000" /></div>
          <div class="field"><label>Email</label><input id="onb-email" type="email" /></div>
          <div class="field"><label>Mobile</label><input id="onb-mobile" /></div>
          <div class="field"><label>Designation</label><input id="onb-desig" /></div>
          <div class="field"><label>Location / Site</label>
            <select id="onb-site">
              <option value="">—</option>
              <option>FFC Head Office</option><option>TFM</option><option>Market Shop</option><option>VS</option>
            </select>
          </div>
          <div class="field"><label class="required">${isOnb ? 'Joining date' : 'Last working date'}</label>
            <input id="onb-date" type="date" />
          </div>
          <div class="field"><label>Reporting manager name</label><input id="onb-mgr" /></div>
        </div>
      </div>

      <div class="form-section">
        <h4>${isOnb ? 'Services Required' : 'Services to Revoke'}</h4>
        <div class="grid-3" id="onb-svc-grid">
          ${ONB_SERVICES.map(([v,label]) => `
            <label style="display:flex;gap:6px;align-items:center;font-size:12.5px;padding:4px 0">
              <input type="checkbox" value="${v}" class="onb-svc" /> ${escape(label)}
            </label>
          `).join('')}
        </div>
        <div class="field" style="margin-top:10px"><label>Other services (specify)</label><input id="onb-other" /></div>
      </div>

      ${!isOnb ? `
      <div class="form-section">
        <h4>Offboarding Specifics</h4>
        <div class="grid-2">
          <div class="field"><label>Mailbox action</label>
            <select id="onb-mbx">
              <option value="">—</option>
              <option value="delete">Delete</option>
              <option value="convert_shared">Convert to Shared</option>
              <option value="forward">Forward emails</option>
              <option value="keep_active">Keep active</option>
              <option value="archive">Archive</option>
              <option value="handover_access">Handover access</option>
            </select>
          </div>
          <div class="field"><label>Forward to / handover to email</label><input id="onb-mbx-target" /></div>
          <div class="field"><label>Mailbox retention (days)</label><input id="onb-mbx-days" type="number" min="0" value="90" /></div>
          <div class="field"><label><input type="checkbox" id="onb-backup" /> Data backup required before exit</label></div>
        </div>
      </div>` : ''}

      <div class="form-section">
        <h4>Notes</h4>
        <div class="field"><label>${isOnb ? 'Additional onboarding notes' : 'Clearance remarks'}</label>
          <textarea id="onb-notes" rows="3"></textarea>
        </div>
      </div>

      <div class="btn-row">
        <button class="btn ok" id="onb-submit">Submit for approval</button>
        <button class="btn secondary" id="onb-draft">Save as draft</button>
      </div>
    </div>
  `;
  $('#onb-submit').addEventListener('click', () => submitOnboarding(kind, true));
  $('#onb-draft').addEventListener('click', () => submitOnboarding(kind, false));
}

async function submitOnboarding(kind, submit=true) {
  const btnId = submit ? 'onb-submit' : 'onb-draft';
  const btn = $('#'+btnId);
  if (btn.disabled) return;
  btn.disabled = true;
  const origText = btn.textContent;
  btn.innerHTML = '<span class="spin"></span> Submitting…';

  try {
    const get = (id) => document.getElementById(id)?.value?.trim() || '';
    const services = Array.from(document.querySelectorAll('.onb-svc:checked')).map(c => c.value);
    const name = get('onb-name');
    const date = get('onb-date');
    if (!name || !date) { toast('Employee name and date are required', 'error'); return; }

    const isOnb = kind === 'onboarding';
    const payload = {
      request_type: kind,
      employee_full_name: name,
      employee_code: get('onb-code') || null,
      employee_email: get('onb-email') || null,
      employee_mobile: get('onb-mobile') || null,
      designation: get('onb-desig') || null,
      location_site: get('onb-site') || null,
      reporting_manager_name: get('onb-mgr') || null,
      joining_date: isOnb ? date : null,
      last_working_date: isOnb ? null : date,
      required_services: services,
      other_services: get('onb-other') || null,
      mailbox_action: !isOnb ? (get('onb-mbx') || null) : null,
      mailbox_forward_to: !isOnb ? (get('onb-mbx-target') || null) : null,
      mailbox_retention_days: !isOnb ? (parseInt(get('onb-mbx-days')) || null) : null,
      data_backup_required: !isOnb && document.getElementById('onb-backup')?.checked,
      final_clearance_remarks: get('onb-notes') || null
    };

    const { data: onb, error: e1 } = await sb.from('onboarding_requests').insert(payload).select().single();
    if (e1) { toast(e1.message, 'error'); return; }

    const { data: ref } = await sb.rpc('generate_ref_no', { p_module: kind });
    const { data: rm, error: e2 } = await sb.from('request_master').insert({
      ref_no: ref, module: kind, module_record_id: onb.id,
      title: `${isOnb?'Onboarding':'Offboarding'}: ${name}`,
      summary: `${services.length} service(s) · ${date}`,
      requester_id: CURRENT_USER.id, department_id: CURRENT_USER.department_id,
      status: 'draft'
    }).select().single();
    if (e2) { toast(e2.message, 'error'); return; }

    await sb.from('onboarding_requests').update({ request_id: rm.id }).eq('id', onb.id);
    await sb.from('request_history').insert({ request_id: rm.id, actor_id: CURRENT_USER.id, action: 'created', to_status: 'draft' });

    if (submit) {
      const { error: e3 } = await sb.rpc('submit_request', { p_request_id: rm.id });
      if (e3) { toast(e3.message, 'error'); return; }
      toast(`${ref} submitted for approval`, 'success');
    } else toast(`${ref} saved`, 'success');

    await refreshBadges();
    route('my-requests');
  } finally {
    btn.disabled = false;
    btn.textContent = origText;
  }
}

// ---------------- ACCESS REQUEST ----------------
async function renderNewAccess() {
  const { data: users } = await sb.from('profiles').select('id, full_name, email').eq('is_active', true).order('full_name');
  $('#viewContent').innerHTML = `
    <div class="form-card">
      <h3>New Access Request</h3>
      <div class="form-section">
        <h4>Target</h4>
        <div class="grid-2">
          <div class="field"><label class="required">Target user (who needs access)</label>
            <select id="acc-target">
              <option value="">— select —</option>
              ${(users||[]).map(u => `<option value="${u.id}">${escape(u.full_name)} · ${escape(u.email)}</option>`).join('')}
            </select>
          </div>
          <div class="field"><label class="required">System / Application</label>
            <input id="acc-system" placeholder="e.g. SAP, NetSuite, FortiGate admin, Defender XDR" />
          </div>
          <div class="field"><label>System module (optional)</label>
            <input id="acc-module" placeholder="e.g. FI Module, User Management" />
          </div>
          <div class="field"><label class="required">Access type</label>
            <select id="acc-type">
              <option value="new">New access</option><option value="modify">Modify</option>
              <option value="extend">Extend</option><option value="revoke">Revoke</option>
              <option value="privileged">Privileged</option>
              <option value="emergency">Emergency</option><option value="temporary">Temporary</option>
            </select>
          </div>
          <div class="field"><label class="required">Permission level</label>
            <select id="acc-perm">
              <option value="read">Read</option><option value="write">Write</option>
              <option value="admin">Admin</option><option value="full">Full</option>
              <option value="custom">Custom</option>
            </select>
          </div>
          <div class="field"><label>Roles / groups (comma-separated)</label>
            <input id="acc-roles" placeholder="e.g. FI_VIEWER, REPORT_EXTRACT" />
          </div>
        </div>
      </div>

      <div class="form-section">
        <h4>Timing</h4>
        <div class="grid-3">
          <div class="field"><label class="required">Start date</label><input id="acc-start" type="date" /></div>
          <div class="field"><label>End date (temporary only)</label><input id="acc-end" type="date" /></div>
          <div class="field">
            <label>Flags</label>
            <label style="display:flex;gap:6px;margin-top:6px;font-size:12.5px"><input type="checkbox" id="acc-priv" /> Privileged</label>
            <label style="display:flex;gap:6px;margin-top:4px;font-size:12.5px"><input type="checkbox" id="acc-urg" /> Urgent</label>
          </div>
        </div>
      </div>

      <div class="form-section">
        <h4>Justification</h4>
        <div class="field"><label class="required">Business justification</label>
          <textarea id="acc-just" rows="3" placeholder="Why does this user need this access?"></textarea>
        </div>
        <div class="field"><label>Implementation note (optional)</label>
          <textarea id="acc-impl" rows="2"></textarea>
        </div>
      </div>

      <div class="btn-row">
        <button class="btn ok" id="acc-submit">Submit for approval</button>
        <button class="btn secondary" id="acc-draft">Save as draft</button>
      </div>
    </div>
  `;
  $('#acc-submit').addEventListener('click', () => submitAccess(true));
  $('#acc-draft').addEventListener('click', () => submitAccess(false));
}

async function submitAccess(submit=true) {
  const btnId = submit ? 'acc-submit' : 'acc-draft';
  const btn = $('#'+btnId);
  if (btn.disabled) return;
  btn.disabled = true;
  const origText = btn.textContent;
  btn.innerHTML = '<span class="spin"></span> Submitting…';

  try {
    const get = (id) => document.getElementById(id)?.value?.trim() || '';
    const target = get('acc-target');
    const system = get('acc-system');
    const just = get('acc-just');
    const start = get('acc-start');
    const type = get('acc-type');

    if (!target || !system || !just || !start) {
      toast('Target, system, justification and start date are required', 'error');
      return;
    }
    if (type === 'temporary' && !get('acc-end')) {
      toast('End date required for temporary access', 'error');
      return;
    }

    const roles = get('acc-roles').split(',').map(s=>s.trim()).filter(Boolean);
    const { data: targetProfile } = await sb.from('profiles').select('full_name, email').eq('id', target).single();

    const payload = {
      target_user_id: target,
      target_user_name_snapshot: targetProfile?.full_name,
      target_user_email: targetProfile?.email,
      system_name: system,
      system_module: get('acc-module') || null,
      access_type: type,
      permission_level: get('acc-perm'),
      roles_groups: roles.length ? roles : null,
      justification: just,
      start_date: start,
      end_date: get('acc-end') || null,
      is_privileged: document.getElementById('acc-priv').checked,
      is_urgent: document.getElementById('acc-urg').checked,
      implementation_note: get('acc-impl') || null
    };

    const { data: ar, error: e1 } = await sb.from('access_requests').insert(payload).select().single();
    if (e1) { toast(e1.message, 'error'); return; }

    const { data: ref } = await sb.rpc('generate_ref_no', { p_module: 'access_request' });
    const { data: rm, error: e2 } = await sb.from('request_master').insert({
      ref_no: ref, module: 'access_request', module_record_id: ar.id,
      title: `Access: ${targetProfile?.full_name || 'user'} → ${system}`,
      summary: `${type} · ${get('acc-perm')}${payload.is_privileged?' · PRIVILEGED':''}`,
      requester_id: CURRENT_USER.id, department_id: CURRENT_USER.department_id,
      priority: payload.is_urgent ? 'high' : 'normal',
      status: 'draft'
    }).select().single();
    if (e2) { toast(e2.message, 'error'); return; }

    await sb.from('access_requests').update({ request_id: rm.id }).eq('id', ar.id);
    await sb.from('request_history').insert({ request_id: rm.id, actor_id: CURRENT_USER.id, action: 'created', to_status: 'draft' });

    if (submit) {
      const { error: e3 } = await sb.rpc('submit_request', { p_request_id: rm.id });
      if (e3) { toast(e3.message, 'error'); return; }
      toast(`${ref} submitted for approval`, 'success');
    } else toast(`${ref} saved`, 'success');

    await refreshBadges();
    route('my-requests');
  } finally {
    btn.disabled = false;
    btn.textContent = origText;
  }
}

// ---------------- ASSET HANDOVER ----------------
async function renderNewHandover() {
  const [{ data: users }, { data: assetList }] = await Promise.all([
    sb.from('profiles').select('id, full_name, email').eq('is_active', true).order('full_name'),
    sb.from('assets').select('id, asset_tag, asset_type, brand, model, serial_number, current_owner_id').eq('is_retired', false).order('asset_tag').limit(1000)
  ]);

  $('#viewContent').innerHTML = `
    <div class="form-card">
      <h3>New Asset Handover</h3>

      <div class="form-section">
        <h4>Asset</h4>
        <div class="grid-2">
          <div class="field"><label>Select existing asset</label>
            <select id="ho-asset">
              <option value="">— new / ad-hoc —</option>
              ${(assetList||[]).map(a => `<option value="${a.id}">${escape(a.asset_tag)} · ${escape(a.asset_type)} · ${escape(a.brand || '')} ${escape(a.model || '')}</option>`).join('')}
            </select>
            <div class="help">Or leave blank and enter details manually below</div>
          </div>
          <div class="field"><label>Asset tag</label><input id="ho-tag" /></div>
          <div class="field"><label>Serial number</label><input id="ho-serial" /></div>
          <div class="field"><label>Type</label>
            <select id="ho-type">${ASSET_TYPES.map(t => `<option value="${t}">${t.replace(/_/g,' ')}</option>`).join('')}</select>
          </div>
          <div class="field"><label>Brand / Model</label><input id="ho-brand" placeholder="e.g. Dell Latitude 5540" /></div>
          <div class="field"><label>Accessories included (comma-separated)</label><input id="ho-acc" placeholder="charger, mouse, bag" /></div>
        </div>
      </div>

      <div class="form-section">
        <h4>Handover</h4>
        <div class="grid-2">
          <div class="field"><label class="required">Handover type</label>
            <select id="ho-htype">
              <option value="employee_handover">Employee handover</option>
              <option value="branch_transfer">Branch transfer</option>
              <option value="temporary_issue">Temporary issue</option>
              <option value="return">Return</option>
              <option value="repair_loaner">Repair loaner</option>
              <option value="replacement">Replacement</option>
            </select>
          </div>
          <div class="field"><label class="required">To (receiver)</label>
            <select id="ho-to">
              <option value="">— select —</option>
              ${(users||[]).map(u => `<option value="${u.id}">${escape(u.full_name)}</option>`).join('')}
            </select>
          </div>
          <div class="field"><label>To location</label><input id="ho-toloc" /></div>
          <div class="field"><label>Issue date</label><input id="ho-issue" type="date" /></div>
          <div class="field"><label>Expected return date</label><input id="ho-expreturn" type="date" /></div>
          <div class="field"><label>Condition at issue</label>
            <select id="ho-cond">
              <option value="new">New</option><option value="good" selected>Good</option>
              <option value="fair">Fair</option><option value="damaged">Damaged</option>
            </select>
          </div>
        </div>
        <div class="field"><label>Remarks</label><textarea id="ho-rem" rows="2"></textarea></div>
      </div>

      <div class="btn-row">
        <button class="btn ok" id="ho-submit">Submit for approval</button>
        <button class="btn secondary" id="ho-draft">Save as draft</button>
      </div>
    </div>
  `;
  $('#ho-submit').addEventListener('click', () => submitHandover(true));
  $('#ho-draft').addEventListener('click', () => submitHandover(false));

  // Auto-fill from existing asset
  $('#ho-asset').addEventListener('change', () => {
    const sel = (assetList || []).find(a => a.id === $('#ho-asset').value);
    if (!sel) return;
    $('#ho-tag').value = sel.asset_tag || '';
    $('#ho-serial').value = sel.serial_number || '';
    $('#ho-type').value = sel.asset_type || '';
    $('#ho-brand').value = [sel.brand, sel.model].filter(Boolean).join(' ');
  });
}

async function submitHandover(submit=true) {
  const btnId = submit ? 'ho-submit' : 'ho-draft';
  const btn = $('#'+btnId);
  if (btn.disabled) return;
  btn.disabled = true;
  const origText = btn.textContent;
  btn.innerHTML = '<span class="spin"></span> Submitting…';

  try {
    const get = (id) => document.getElementById(id)?.value?.trim() || '';
    if (!get('ho-to') || !get('ho-htype')) {
      toast('Receiver and handover type required', 'error');
      return;
    }
    const accessories = get('ho-acc').split(',').map(s=>s.trim()).filter(Boolean);
    const { data: toUser } = await sb.from('profiles').select('full_name').eq('id', get('ho-to')).single();

    const payload = {
      asset_id: get('ho-asset') || null,
      asset_tag: get('ho-tag') || null,
      asset_type: get('ho-type') || null,
      brand_model: get('ho-brand') || null,
      serial_number: get('ho-serial') || null,
      handover_type: get('ho-htype'),
      to_owner_id: get('ho-to'),
      to_location: get('ho-toloc') || null,
      from_owner_id: CURRENT_USER.id,
      issue_date: get('ho-issue') || null,
      expected_return_date: get('ho-expreturn') || null,
      condition_at_issue: get('ho-cond') || 'good',
      accessories_included: accessories.length ? accessories.join(',') : null,
      it_engineer_id: CURRENT_USER.id,
      remarks: get('ho-rem') || null
    };

    // Single atomic RPC — does all steps in one round trip (~1-2s vs ~8s)
    const rpcPayload = {
      ...payload,
      requester_id: CURRENT_USER.id,
      department_id: CURRENT_USER.department_id,
      title: `Asset ${get('ho-htype').replace('_',' ')}: ${get('ho-tag') || get('ho-brand') || 'asset'} → ${toUser?.full_name}`,
      summary: `${get('ho-type')} · ${get('ho-brand')}`
    };

    const { data: result, error: rpcErr } = await sb.rpc('submit_asset_handover_fast', {
      p_payload: rpcPayload,
      p_submit: submit
    });
    if (rpcErr) { toast(rpcErr.message, 'error'); return; }

    toast(`${result.ref_no} ${submit ? 'submitted' : 'saved'}`, 'success');
    await refreshBadges();
    route('my-requests');
  } finally {
    btn.disabled = false;
    btn.textContent = origText;
  }
}

// ---------------- ONBOARDING TASKS (for IT Engineers) ----------------
async function renderMyOnboardingTasks() {
  const { data: tasks } = await sb.from('onboarding_tasks')
    .select('*, onb:onboarding_requests(id, employee_full_name, request_type, request_id)')
    .or(`assigned_to.eq.${CURRENT_USER.id}`)
    .order('created_at', { ascending: false })
    .limit(300);

  // Also fetch tasks where no one's assigned yet (fallback for IT team to claim)
  const { data: unassigned } = isAdmin() || hasRole('it_manager') || hasRole('it_support') || hasRole('sysadmin')
    ? await sb.from('onboarding_tasks')
        .select('*, onb:onboarding_requests(id, employee_full_name, request_type, request_id)')
        .is('assigned_to', null)
        .in('status', ['pending','in_progress'])
        .order('created_at', { ascending: false })
        .limit(300)
    : { data: [] };

  const renderTask = (t) => `
    <div class="comment" data-task="${t.id}" style="margin-bottom:10px;cursor:pointer">
      <div class="comment-head">
        <div>
          <span class="comment-author">${t.seq}. ${escape(t.task_title)}</span>
          ${t.service ? `<span class="comment-flag" style="background:var(--blue)">${escape(t.service)}</span>` : ''}
        </div>
        <span class="status s-${t.status==='completed'?'approved':t.status==='failed'?'rejected':t.status==='in_progress'?'in_progress':'pending_approval'}">
          <span class="dot"></span>${escape(t.status)}
        </span>
      </div>
      <div class="comment-body">
        For: <b>${escape(t.onb?.employee_full_name || '—')}</b> (${escape(t.onb?.request_type || '')})
        ${t.remarks ? `<br/><small style="color:var(--muted)">${escape(t.remarks)}</small>` : ''}
      </div>
    </div>`;

  $('#viewContent').innerHTML = `
    <div class="panel">
      <div class="panel-head"><h3>My assigned tasks — ${(tasks||[]).length}</h3></div>
      <div class="panel-body" style="padding:14px 20px">
        ${(tasks||[]).length ? (tasks||[]).map(renderTask).join('') : emptyRow('No tasks assigned')}
      </div>
    </div>
    ${(unassigned||[]).length ? `
    <div class="panel">
      <div class="panel-head"><h3>Unassigned tasks (claim one) — ${unassigned.length}</h3></div>
      <div class="panel-body" style="padding:14px 20px">
        ${unassigned.map(renderTask).join('')}
      </div>
    </div>` : ''}
  `;

  $$('[data-task]').forEach(el => el.addEventListener('click', () => openOnbTask(el.dataset.task)));
}

async function openOnbTask(taskId) {
  const { data: task } = await sb.from('onboarding_tasks')
    .select('*, onb:onboarding_requests(*)')
    .eq('id', taskId).single();
  if (!task) return;

  $('#drawerBg').classList.add('show');
  $('#drawerTitle').textContent = task.task_title;
  $('#drawerRef').innerHTML = `Task for ${escape(task.onb?.employee_full_name || '')} · ${escape(task.status)}`;

  $('#drawerBody').innerHTML = `
    <div class="detail-meta">
      <div class="m-item"><label>Service</label><span>${escape(task.service || '—')}</span></div>
      <div class="m-item"><label>Status</label><span>${escape(task.status)}</span></div>
      <div class="m-item"><label>Employee</label><span>${escape(task.onb?.employee_full_name || '—')}</span></div>
      <div class="m-item"><label>Type</label><span>${escape(task.onb?.request_type || '')}</span></div>
    </div>
    ${task.task_description ? `<div class="detail-section"><h4>Description</h4><p>${escape(task.task_description)}</p></div>` : ''}
    <div class="form-section">
      <h4>Update task</h4>
      <div class="field"><label>Status</label>
        <select id="tk-status">
          ${['pending','in_progress','completed','skipped','failed'].map(s => `<option value="${s}" ${task.status===s?'selected':''}>${s}</option>`).join('')}
        </select>
      </div>
      <div class="field"><label>Remarks</label>
        <textarea id="tk-rem" rows="2">${escape(task.remarks || '')}</textarea>
      </div>
      <div class="btn-row">
        <button class="btn ok btn-sm" id="tk-save">Save</button>
        ${!task.assigned_to ? `<button class="btn secondary btn-sm" id="tk-claim">Claim this task</button>` : ''}
      </div>
    </div>
  `;

  $('#tk-save').addEventListener('click', async () => {
    const status = $('#tk-status').value;
    const patch = {
      status,
      remarks: $('#tk-rem').value.trim() || null,
      started_at: status === 'in_progress' && !task.started_at ? new Date().toISOString() : task.started_at,
      completed_at: status === 'completed' ? new Date().toISOString() : null,
      completed_by: status === 'completed' ? CURRENT_USER.id : null
    };
    const { error } = await sb.from('onboarding_tasks').update(patch).eq('id', taskId);
    if (error) { toast(error.message, 'error'); return; }
    toast('Task updated', 'success');

    // Recalculate completion_pct on the parent onboarding
    const { data: allTasks } = await sb.from('onboarding_tasks').select('status').eq('onboarding_id', task.onboarding_id);
    const total = (allTasks||[]).length;
    const done = (allTasks||[]).filter(t => t.status === 'completed' || t.status === 'skipped').length;
    await sb.from('onboarding_requests').update({
      completion_pct: total > 0 ? (done/total*100).toFixed(2) : 0,
      execution_completed_at: (total > 0 && done === total) ? new Date().toISOString() : null
    }).eq('id', task.onboarding_id);

    closeDrawer();
    route(CURRENT_VIEW);
  });

  const claimBtn = $('#tk-claim');
  if (claimBtn) {
    claimBtn.addEventListener('click', async () => {
      const { error } = await sb.from('onboarding_tasks').update({ assigned_to: CURRENT_USER.id }).eq('id', taskId);
      if (error) { toast(error.message, 'error'); return; }
      toast('Task claimed', 'success');
      openOnbTask(taskId);
    });
  }
}

// ---------------- ASSETS REGISTRY ----------------
async function renderAssetsRegistry() {
  const canWrite = isAdmin() || hasRole('it_manager') || hasRole('it_support') || hasRole('sysadmin') || hasRole('helpdesk');

  // Get total count separately so we always show the real number
  const [assetsRes, countRes] = await Promise.all([
    sb.from('assets')
      .select('*, owner:profiles!assets_current_owner_id_fkey(full_name)')
      .order('asset_tag')
      .limit(1000),  // raised from 300 to 1000
    sb.from('assets').select('id', { count: 'exact', head: true })
  ]);

  const assets = assetsRes.data || [];
  const totalCount = countRes.count || assets.length;
  const showing = assets.length < totalCount ? ` (showing ${assets.length} of ${totalCount})` : ` (${totalCount} total)`;

  $('#viewContent').innerHTML = `
    <div class="filter-bar">
      <select id="afType"><option value="">All types</option>
        ${ASSET_TYPES.map(t => `<option value="${t}">${t.replace(/_/g,' ')}</option>`).join('')}
      </select>
      <select id="afRetired">
        <option value="active">Active only</option>
        <option value="all">All incl. retired</option>
        <option value="retired">Retired only</option>
      </select>
      <input id="afSearch" placeholder="Search tag, serial, brand, owner…" />
      <span class="count" id="afCount">${assets.length} assets${totalCount > assets.length ? ` <span style="color:var(--muted);font-size:10.5px">(${totalCount} total in DB)</span>` : ''}</span>
      ${canWrite ? `<button class="btn ok btn-sm" id="btnNewAsset" style="margin-left:8px">+ Add Asset</button><button class="btn secondary btn-sm" id="btnAssetBulk" style="margin-left:6px">⬆ Bulk Upload</button>` : ''}
    </div>
    <div class="panel"><div class="panel-body" id="astList">
      ${renderAssetRowsHeader()}
      ${assets.length ? assets.map(assetRow).join('') : emptyRow('No assets registered yet')}
    </div></div>
  `;
  wireAssetRows();

  const apply = () => {
    const t = $('#afType').value;
    const q = $('#afSearch').value.toLowerCase().trim();
    const retired = $('#afRetired').value;
    const f = assets.filter(a =>
      (!t || a.asset_type === t) &&
      (retired === 'all' || (retired === 'retired' ? a.is_retired : !a.is_retired)) &&
      (!q || (a.asset_tag||'').toLowerCase().includes(q)
          || (a.serial_number||'').toLowerCase().includes(q)
          || (a.brand||'').toLowerCase().includes(q)
          || (a.model||'').toLowerCase().includes(q)
          || (a.owner?.full_name||'').toLowerCase().includes(q))
    );
    $('#astList').innerHTML = renderAssetRowsHeader() + (f.length ? f.map(assetRow).join('') : emptyRow('No matches'));
    $('#afCount').textContent = `${f.length} assets`;
    wireAssetRows();
  };
  ['afType','afSearch','afRetired'].forEach(id => $('#'+id).addEventListener('input', apply));

  if (canWrite) $('#btnNewAsset').addEventListener('click', () => openAssetEditor(null));
  if (canWrite && $('#btnAssetBulk')) $('#btnAssetBulk').addEventListener('click', () => openBulkUpload('asset'));
}

function renderAssetRowsHeader() {
  return `<div class="req-row head" style="grid-template-columns:140px 1fr 100px 1fr 120px">
    <div>Tag</div><div>Brand / Model</div><div>Type</div><div>Current Owner</div><div>Condition</div>
  </div>`;
}
function assetRow(a) {
  return `<div class="req-row" data-asset="${a.id}" style="grid-template-columns:140px 1fr 100px 1fr 120px">
    <div class="req-id">${escape(a.asset_tag)}</div>
    <div class="req-title">${escape(a.brand || '')} ${escape(a.model || '')}<small>${escape(a.serial_number || '')}</small></div>
    <div class="req-cell mono">${escape(a.asset_type)}</div>
    <div class="req-cell">${escape(a.owner?.full_name || '—')}${a.current_location?` <small style="color:var(--muted)">· ${escape(a.current_location)}</small>`:''}</div>
    <div class="req-cell"><span class="status s-${a.current_condition==='good'?'approved':a.current_condition==='damaged'||a.current_condition==='lost'?'rejected':'pending_approval'}"><span class="dot"></span>${escape(a.current_condition)}</span></div>
  </div>`;
}
function wireAssetRows() {
  $$('[data-asset]').forEach(el => el.addEventListener('click', () => openAssetEditor(el.dataset.asset)));
}

async function openAssetEditor(assetId) {
  const canWrite = isAdmin() || hasRole('it_manager') || hasRole('it_support') || hasRole('sysadmin') || hasRole('helpdesk');
  const [assetRes, usersRes] = await Promise.all([
    assetId ? sb.from('assets').select('*').eq('id', assetId).single() : Promise.resolve({ data: null }),
    sb.from('profiles').select('id, full_name').eq('is_active', true).order('full_name')
  ]);
  const a = assetRes.data || {};
  const users = usersRes.data || [];

  $('#drawerBg').classList.add('show');
  $('#drawerTitle').textContent = assetId ? `Asset ${a.asset_tag || ''}` : 'New Asset';
  $('#drawerRef').innerHTML = assetId ? escape(a.asset_type || '') : 'Register new asset';

  $('#drawerBody').innerHTML = `
    <div class="form-section">
      <div class="grid-2">
        <div class="field"><label class="required">Asset tag</label><input id="as-tag" value="${escape(a.asset_tag || '')}" /></div>
        <div class="field"><label>Serial number</label><input id="as-sn" value="${escape(a.serial_number || '')}" /></div>
        <div class="field"><label class="required">Type</label>
          <select id="as-type">${ASSET_TYPES.map(t => `<option value="${t}" ${a.asset_type===t?'selected':''}>${t.replace(/_/g,' ')}</option>`).join('')}</select>
        </div>
        <div class="field"><label>Brand</label><input id="as-brand" value="${escape(a.brand || '')}" /></div>
        <div class="field"><label>Model</label><input id="as-model" value="${escape(a.model || '')}" /></div>
        <div class="field"><label>Specs</label><input id="as-specs" value="${escape(a.specifications || '')}" placeholder="i5 / 16GB / 512GB SSD" /></div>
        <div class="field"><label>Purchase date</label><input id="as-pdate" type="date" value="${a.purchase_date || ''}" /></div>
        <div class="field"><label>Warranty expiry</label><input id="as-warr" type="date" value="${a.warranty_expiry || ''}" /></div>
        <div class="field"><label>Current owner</label>
          <select id="as-owner">
            <option value="">— unassigned —</option>
            ${users.map(u => `<option value="${u.id}" ${a.current_owner_id===u.id?'selected':''}>${escape(u.full_name)}</option>`).join('')}
          </select>
        </div>
        <div class="field"><label>Current location</label><input id="as-loc" value="${escape(a.current_location || '')}" /></div>
        <div class="field"><label>Condition</label>
          <select id="as-cond">
            ${['new','good','fair','damaged','lost','retired'].map(c => `<option value="${c}" ${a.current_condition===c?'selected':''}>${c}</option>`).join('')}
          </select>
        </div>
        <div class="field"><label>Accessories (comma-separated)</label><input id="as-acc" value="${escape((a.accessories||[]).join(', '))}" /></div>
      </div>
    </div>
    ${canWrite ? `<div class="btn-row">
      <button class="btn ok" id="as-save">${assetId ? 'Save' : 'Create asset'}</button>
      ${assetId ? `<button class="btn danger" id="as-retire">${a.is_retired?'Un-retire':'Retire'}</button>` : ''}
    </div>` : ''}
  `;

  if (canWrite) {
    $('#as-save').addEventListener('click', async () => {
      const get = (id) => document.getElementById(id)?.value?.trim() || '';
      if (!get('as-tag') || !get('as-type')) { toast('Tag and type required', 'error'); return; }
      const payload = {
        asset_tag: get('as-tag'),
        serial_number: get('as-sn') || null,
        asset_type: get('as-type'),
        brand: get('as-brand') || null,
        model: get('as-model') || null,
        specifications: get('as-specs') || null,
        purchase_date: get('as-pdate') || null,
        warranty_expiry: get('as-warr') || null,
        current_owner_id: get('as-owner') || null,
        current_location: get('as-loc') || null,
        current_condition: get('as-cond') || 'good',
        accessories: get('as-acc') ? get('as-acc').split(',').map(s=>s.trim()).filter(Boolean) : null
      };
      let err;
      if (assetId) {
        ({ error: err } = await sb.from('assets').update(payload).eq('id', assetId));
      } else {
        const { error: insertErr, data: inserted } = await sb.from('assets').insert(payload).select().single();
        err = insertErr;
        if (!insertErr && !inserted) {
          err = { message: 'Insert returned no data — possible RLS policy blocking. Run 16_combined_fix.sql.' };
        }
      }
      if (err) {
        console.error('Asset save error:', err);
        toast(`Save failed: ${err.message}`, 'error', 8000);
        return;
      }
      toast(assetId ? 'Asset updated' : 'Asset created ✓', 'success');
      closeDrawer();
      route('assets-registry');
    });

    const retireBtn = $('#as-retire');
    if (retireBtn) {
      retireBtn.addEventListener('click', async () => {
        const { error } = await sb.from('assets').update({
          is_retired: !a.is_retired,
          retired_on: a.is_retired ? null : new Date().toISOString().slice(0,10)
        }).eq('id', assetId);
        if (error) { toast(error.message, 'error'); return; }
        toast(a.is_retired ? 'Asset reactivated' : 'Asset retired', 'success');
        closeDrawer();
        route('assets-registry');
      });
    }
  }
}

// ---------------- LICENSE TRACKER ----------------
async function renderLicenses() {
  const canWrite = isAdmin() || hasRole('it_manager') || hasRole('sysadmin') || hasRole('finance');
  const { data: items } = await sb.from('license_items')
    .select('*, vendor_lbl:vendor, owner:profiles!license_items_product_owner_id_fkey(full_name)')
    .order('expiry_date', { ascending: true })
    .limit(300);

  const expiring = (items||[]).filter(l => l.status === 'expiring_soon' || (l.expiry_date && new Date(l.expiry_date) - new Date() < 30*86400000 && l.status === 'active'));
  const expired = (items||[]).filter(l => l.status === 'expired');
  const total = (items||[]).length;
  const totalCost = (items||[]).reduce((s, l) => s + Number(l.total_cost || 0), 0);

  $('#viewContent').innerHTML = `
    <div class="stats-grid">
      <div class="stat accent"><div class="label">Total Licenses</div><div class="value">${total}</div></div>
      <div class="stat warn"><div class="label">Expiring Soon</div><div class="value">${expiring.length}</div><div class="sub">Action needed</div></div>
      <div class="stat danger"><div class="label">Expired</div><div class="value">${expired.length}</div></div>
      <div class="stat"><div class="label">Annual Spend</div><div class="value">${totalCost.toLocaleString()}</div><div class="sub">USD equivalent</div></div>
    </div>

    <div class="filter-bar">
      <select id="lfType"><option value="">All types</option>
        ${LIC_TYPES.map(([v,l]) => `<option value="${v}">${escape(l)}</option>`).join('')}
      </select>
      <select id="lfStatus"><option value="">All statuses</option>
        <option value="active">Active</option><option value="expiring_soon">Expiring Soon</option>
        <option value="renewal_in_progress">Renewal In Progress</option><option value="renewed">Renewed</option>
        <option value="expired">Expired</option><option value="archived">Archived</option>
      </select>
      <input id="lfSearch" placeholder="Search name, vendor, contract…" />
      <span class="count" id="lfCount">${total} licenses</span>
      ${canWrite ? `<button class="btn ok btn-sm" data-goto="licenses-new" style="margin-left:8px">+ Add License</button><button class="btn secondary btn-sm" id="btnLicBulk" style="margin-left:6px">⬆ Bulk Upload</button>` : ''}
    </div>

    <div class="panel"><div class="panel-body" id="licList">
      ${renderLicRowsHeader()}
      ${(items||[]).length ? (items||[]).map(licRow).join('') : emptyRow('No licenses tracked yet')}
    </div></div>
  `;

  wireLicRows();
  $$('[data-goto="licenses-new"]').forEach(b => b.addEventListener('click', () => route('licenses-new')));

  const apply = () => {
    const t = $('#lfType').value;
    const s = $('#lfStatus').value;
    const q = $('#lfSearch').value.toLowerCase().trim();
    const f = (items||[]).filter(l =>
      (!t || l.item_type === t) &&
      (!s || l.status === s) &&
      (!q || (l.item_name||'').toLowerCase().includes(q)
          || (l.vendor||'').toLowerCase().includes(q)
          || (l.contract_number||'').toLowerCase().includes(q)
          || (l.item_code||'').toLowerCase().includes(q))
    );
    $('#licList').innerHTML = renderLicRowsHeader() + (f.length ? f.map(licRow).join('') : emptyRow('No matches'));
    $('#lfCount').textContent = `${f.length} licenses`;
    wireLicRows();
  };
  ['lfType','lfStatus','lfSearch'].forEach(id => $('#'+id).addEventListener('input', apply));
  if ($('#btnLicBulk')) $('#btnLicBulk').addEventListener('click', () => openBulkUpload('license'));
}

function renderLicRowsHeader() {
  return `<div class="req-row head" style="grid-template-columns:130px 1fr 150px 110px 100px 100px">
    <div>Code</div><div>License</div><div>Vendor</div><div>Expiry</div><div>Status</div><div>Cost</div>
  </div>`;
}
function licRow(l) {
  const days = l.expiry_date ? Math.floor((new Date(l.expiry_date) - new Date()) / 86400000) : null;
  const dueText = days !== null ? (days < 0 ? `${Math.abs(days)}d overdue` : `${days}d left`) : '—';
  const dueColor = days !== null && days < 0 ? 'color:var(--red-deep)' : days !== null && days < 30 ? 'color:var(--orange-deep)' : '';
  return `<div class="req-row" data-lic="${l.id}" style="grid-template-columns:130px 1fr 150px 110px 100px 100px">
    <div class="req-id">${escape(l.item_code)}</div>
    <div class="req-title">${escape(l.item_name)}<small>${escape(l.item_type.replace(/_/g,' '))}</small></div>
    <div class="req-cell">${escape(l.vendor || '—')}</div>
    <div class="req-cell mono" style="${dueColor}">${fmtDate(l.expiry_date)}<br/><small>${dueText}</small></div>
    <div class="req-cell"><span class="status s-${l.status==='active'||l.status==='renewed'?'approved':l.status==='expired'||l.status==='cancelled'?'rejected':l.status==='expiring_soon'?'pending_approval':'in_progress'}"><span class="dot"></span>${escape(l.status.replace(/_/g,' '))}</span></div>
    <div class="req-cell mono">${l.total_cost ? Number(l.total_cost).toLocaleString() : '—'} ${escape(l.currency || '')}</div>
  </div>`;
}
function wireLicRows() {
  $$('[data-lic]').forEach(el => el.addEventListener('click', () => openLicenseEditor(el.dataset.lic)));
}

async function renderLicenseForm() {
  openLicenseEditor(null);
  $('#viewContent').innerHTML = '<div class="loading">Opening license form…</div>';
}

async function openLicenseEditor(licenseId) {
  const canWrite = isAdmin() || hasRole('it_manager') || hasRole('sysadmin') || hasRole('finance');
  const [licRes, renewalsRes, usersRes] = await Promise.all([
    licenseId ? sb.from('license_items').select('*').eq('id', licenseId).single() : Promise.resolve({ data: null }),
    licenseId ? sb.from('license_renewals').select('*, renewer:profiles(full_name)').eq('license_id', licenseId).order('renewed_on', { ascending: false }) : Promise.resolve({ data: [] }),
    sb.from('profiles').select('id, full_name').eq('is_active', true).order('full_name')
  ]);
  const l = licRes.data || {};
  const renewals = renewalsRes.data || [];
  const users = usersRes.data || [];

  $('#drawerBg').classList.add('show');
  $('#drawerTitle').textContent = licenseId ? l.item_name : 'New License';
  $('#drawerRef').innerHTML = licenseId ? `${escape(l.item_code)} · ${escape(l.vendor || '')}` : 'Add a license / subscription / domain';

  $('#drawerBody').innerHTML = `
    <div class="form-section">
      <h4>Identity</h4>
      <div class="grid-2">
        <div class="field"><label class="required">Item code</label><input id="li-code" value="${escape(l.item_code || '')}" placeholder="LIC-2026-042" /></div>
        <div class="field"><label class="required">Item name</label><input id="li-name" value="${escape(l.item_name || '')}" /></div>
        <div class="field"><label class="required">Type</label>
          <select id="li-type">${LIC_TYPES.map(([v,lab]) => `<option value="${v}" ${l.item_type===v?'selected':''}>${escape(lab)}</option>`).join('')}</select>
        </div>
        <div class="field"><label class="required">Vendor</label><input id="li-vendor" value="${escape(l.vendor || '')}" /></div>
        <div class="field"><label>Product owner</label>
          <select id="li-owner">
            <option value="">—</option>
            ${users.map(u => `<option value="${u.id}" ${l.product_owner_id===u.id?'selected':''}>${escape(u.full_name)}</option>`).join('')}
          </select>
        </div>
        <div class="field"><label>Contract number</label><input id="li-contract" value="${escape(l.contract_number || '')}" /></div>
      </div>
    </div>
    <div class="form-section">
      <h4>Commercial</h4>
      <div class="grid-3">
        <div class="field"><label>Quantity</label><input id="li-qty" type="number" min="1" value="${l.quantity || 1}" /></div>
        <div class="field"><label>Unit cost</label><input id="li-unit" type="number" step="0.01" value="${l.unit_cost || ''}" /></div>
        <div class="field"><label>Total cost</label><input id="li-total" type="number" step="0.01" value="${l.total_cost || ''}" /></div>
        <div class="field"><label>Currency</label><input id="li-cur" value="${escape(l.currency || 'AED')}" /></div>
        <div class="field"><label>Frequency</label>
          <select id="li-freq">
            ${['one_time','monthly','quarterly','semi_annual','annual','biennial','triennial'].map(f => `<option value="${f}" ${l.payment_frequency===f?'selected':''}>${f.replace(/_/g,' ')}</option>`).join('')}
          </select>
        </div>
        <div class="field"><label>Criticality</label>
          <select id="li-crit">
            ${['low','medium','high','critical'].map(c => `<option value="${c}" ${l.criticality===c?'selected':''}>${c}</option>`).join('')}
          </select>
        </div>
      </div>
    </div>
    <div class="form-section">
      <h4>Dates</h4>
      <div class="grid-3">
        <div class="field"><label class="required">Start date</label><input id="li-start" type="date" value="${l.start_date || ''}" /></div>
        <div class="field"><label class="required">Expiry date</label><input id="li-expiry" type="date" value="${l.expiry_date || ''}" /></div>
        <div class="field"><label>Reminder (days before)</label><input id="li-remind" type="number" min="1" max="365" value="${l.reminder_days_before || 30}" /></div>
      </div>
      <div class="grid-2">
        <div class="field"><label><input type="checkbox" id="li-auto" ${l.auto_renew?'checked':''} /> Auto-renew</label></div>
        <div class="field"><label>Domain / URL (optional)</label><input id="li-url" value="${escape(l.domain_or_url || '')}" /></div>
      </div>
      <div class="field"><label>Remarks</label><textarea id="li-rem" rows="2">${escape(l.remarks || '')}</textarea></div>
    </div>

    ${licenseId ? `
    <div class="form-section">
      <h4>Renewal History (${renewals.length})</h4>
      ${renewals.length ? renewals.map(r => `
        <div class="comment">
          <div class="comment-head">
            <div><span class="comment-author">${fmtDate(r.renewed_on)}</span>
              <span class="comment-flag">${r.new_expiry ? 'new expiry: ' + fmtDate(r.new_expiry) : ''}</span>
            </div>
            <span class="comment-time">${escape(r.renewer?.full_name || '')}</span>
          </div>
          <div class="comment-body">
            ${r.cost_paid ? `Paid ${Number(r.cost_paid).toLocaleString()} ${escape(r.currency||'')}` : ''}
            ${r.po_number ? ` · PO ${escape(r.po_number)}` : ''}
            ${r.remarks ? `<br/>${escape(r.remarks)}` : ''}
          </div>
        </div>
      `).join('') : '<p style="color:var(--muted);font-size:12px">No renewals recorded yet</p>'}
    </div>` : ''}

    ${canWrite ? `
    <div class="btn-row">
      <button class="btn ok" id="li-save">${licenseId ? 'Save changes' : 'Create license'}</button>
      ${licenseId ? `<button class="btn warn" id="li-renew">+ Record Renewal</button>` : ''}
      ${licenseId ? `<button class="btn danger" id="li-archive">Archive</button>` : ''}
    </div>` : ''}
  `;

  if (canWrite) {
    $('#li-save').addEventListener('click', async () => {
      const get = (id) => document.getElementById(id)?.value?.trim() || '';
      if (!get('li-code') || !get('li-name') || !get('li-vendor') || !get('li-start') || !get('li-expiry')) {
        toast('Code, name, vendor, start, and expiry dates are required', 'error');
        return;
      }
      const payload = {
        item_code: get('li-code'),
        item_name: get('li-name'),
        item_type: get('li-type'),
        vendor: get('li-vendor'),
        product_owner_id: get('li-owner') || null,
        contract_number: get('li-contract') || null,
        quantity: parseInt(get('li-qty')) || 1,
        unit_cost: parseFloat(get('li-unit')) || null,
        total_cost: parseFloat(get('li-total')) || null,
        currency: get('li-cur') || 'AED',
        start_date: get('li-start'),
        expiry_date: get('li-expiry'),
        reminder_days_before: parseInt(get('li-remind')) || 30,
        payment_frequency: get('li-freq'),
        criticality: get('li-crit'),
        auto_renew: $('#li-auto').checked,
        domain_or_url: get('li-url') || null,
        remarks: get('li-rem') || null
      };

      let err;
      if (licenseId) {
        ({ error: err } = await sb.from('license_items').update(payload).eq('id', licenseId));
      } else {
        payload.created_by = CURRENT_USER.id;
        ({ error: err } = await sb.from('license_items').insert(payload));
      }
      if (err) { toast(err.message, 'error'); return; }
      toast(licenseId ? 'License updated' : 'License created', 'success');
      closeDrawer();
      route('licenses');
    });

    const renewBtn = $('#li-renew');
    if (renewBtn) renewBtn.addEventListener('click', () => promptLicenseRenewal(licenseId, l));

    const archiveBtn = $('#li-archive');
    if (archiveBtn) archiveBtn.addEventListener('click', async () => {
      if (!confirm('Archive this license? It will stop appearing in expiry alerts.')) return;
      const { error } = await sb.from('license_items').update({ status: 'archived' }).eq('id', licenseId);
      if (error) { toast(error.message, 'error'); return; }
      toast('Archived', 'success');
      closeDrawer();
      route('licenses');
    });
  }
}

function promptLicenseRenewal(licenseId, license) {
  const newExpiry = prompt('New expiry date (YYYY-MM-DD):');
  if (!newExpiry) return;
  const costPaid = prompt('Cost paid (number, optional):', license.total_cost || '');
  const po = prompt('PO / invoice reference (optional):', '');
  const remarks = prompt('Remarks (optional):', '');

  (async () => {
    const { error } = await sb.from('license_renewals').insert({
      license_id: licenseId,
      renewed_on: new Date().toISOString().slice(0,10),
      previous_expiry: license.expiry_date,
      new_expiry: newExpiry,
      cost_paid: costPaid ? parseFloat(costPaid) : null,
      currency: license.currency || 'AED',
      po_number: po || null,
      remarks: remarks || null,
      renewed_by: CURRENT_USER.id
    });
    if (error) { toast(error.message, 'error'); return; }
    toast('Renewal recorded · license extended', 'success');
    closeDrawer();
    route('licenses');
  })();
}

// =============================================================================
// GOVERNANCE PHASE 2: Vendors, DR Tracker, CAPA, Branch Compliance
// =============================================================================

// ---------------- VENDORS & AMC ----------------
async function renderVendors() {
  const canWrite = isAdmin() || hasRole('it_manager') || hasRole('sysadmin') || hasRole('finance');
  const [{ data: vendors }, { data: contracts }] = await Promise.all([
    sb.from('vendors').select('*').eq('is_active', true).order('name'),
    sb.from('vendor_contracts').select('*, vendor:vendors(name, category)').order('end_date', { ascending: true }).limit(300)
  ]);

  const active = (contracts||[]).filter(c => c.status === 'active').length;
  const expiring = (contracts||[]).filter(c => c.status === 'expiring_soon').length;
  const expired = (contracts||[]).filter(c => c.status === 'expired').length;
  const totalCost = (contracts||[]).reduce((s, c) => s + Number(c.cost || 0), 0);

  $('#viewContent').innerHTML = `
    <div class="stats-grid">
      <div class="stat accent"><div class="label">Active Contracts</div><div class="value">${active}</div></div>
      <div class="stat warn"><div class="label">Expiring Soon</div><div class="value">${expiring}</div></div>
      <div class="stat danger"><div class="label">Expired</div><div class="value">${expired}</div></div>
      <div class="stat"><div class="label">Annual Commitment</div><div class="value">${totalCost.toLocaleString()}</div><div class="sub">USD equivalent</div></div>
    </div>

    <div class="filter-bar">
      <select id="vnfVendor"><option value="">All vendors</option>
        ${(vendors||[]).map(v => `<option value="${v.id}">${escape(v.name)}</option>`).join('')}
      </select>
      <select id="vnfStatus"><option value="">All statuses</option>
        <option value="active">Active</option><option value="expiring_soon">Expiring Soon</option>
        <option value="renewal_in_progress">Renewal In Progress</option>
        <option value="expired">Expired</option><option value="suspended">Suspended</option>
      </select>
      <input id="vnfSearch" placeholder="Search contract, vendor, system…" />
      <span class="count" id="vnfCount">${(contracts||[]).length} contracts</span>
      ${canWrite ? `<button class="btn ok btn-sm" id="btnNewContract" style="margin-left:8px">+ New Contract</button>
                    <button class="btn secondary btn-sm" id="btnContractBulk" style="margin-left:6px">⬆ Bulk Contracts</button>
                    <button class="btn secondary btn-sm" id="btnNewVendor">+ Vendor</button><button class="btn secondary btn-sm" id="btnVendorBulk" style="margin-left:6px">⬆ Bulk Vendors</button>` : ''}
    </div>

    <div class="panel"><div class="panel-body" id="vnList">
      ${renderVCRowsHeader()}
      ${(contracts||[]).length ? contracts.map(vcRow).join('') : emptyRow('No contracts yet')}
    </div></div>
  `;
  wireVCRows();

  const apply = () => {
    const v = $('#vnfVendor').value, s = $('#vnfStatus').value, q = $('#vnfSearch').value.toLowerCase().trim();
    const f = (contracts||[]).filter(c =>
      (!v || c.vendor_id === v) &&
      (!s || c.status === s) &&
      (!q || (c.contract_code||'').toLowerCase().includes(q)
          || (c.contract_title||'').toLowerCase().includes(q)
          || (c.vendor?.name||'').toLowerCase().includes(q)
          || (c.service_covered||'').toLowerCase().includes(q))
    );
    $('#vnList').innerHTML = renderVCRowsHeader() + (f.length ? f.map(vcRow).join('') : emptyRow('No matches'));
    $('#vnfCount').textContent = `${f.length} contracts`;
    wireVCRows();
  };
  ['vnfVendor','vnfStatus','vnfSearch'].forEach(id => $('#'+id).addEventListener('input', apply));

  if (canWrite) {
    $('#btnNewContract').addEventListener('click', () => openContractEditor(null, vendors));
  if ($('#btnContractBulk')) $('#btnContractBulk').addEventListener('click', () => openBulkUpload('vendor_contract'));
  if ($('#btnVendorBulk')) $('#btnVendorBulk').addEventListener('click', () => openBulkUpload('vendor'));
    $('#btnNewVendor').addEventListener('click', () => openVendorEditor(null));
  if ($('#btnVendorBulk')) $('#btnVendorBulk').addEventListener('click', () => openBulkUpload('vendor'));
  }
}

function renderVCRowsHeader() {
  return `<div class="req-row head" style="grid-template-columns:160px 1fr 150px 110px 100px 110px">
    <div>Code</div><div>Contract</div><div>Vendor</div><div>Expiry</div><div>Status</div><div>Cost</div>
  </div>`;
}
function vcRow(c) {
  const days = c.end_date ? Math.floor((new Date(c.end_date) - new Date())/86400000) : null;
  const dueText = days !== null ? (days < 0 ? `${Math.abs(days)}d overdue` : `${days}d left`) : '—';
  const dueColor = days !== null && days < 0 ? 'color:var(--red-deep)' : days !== null && days < 45 ? 'color:var(--orange-deep)' : '';
  return `<div class="req-row" data-contract="${c.id}" style="grid-template-columns:160px 1fr 150px 110px 100px 110px">
    <div class="req-id">${escape(c.contract_code)}</div>
    <div class="req-title">${escape(c.contract_title)}<small>${escape((c.service_covered||'').slice(0,80))}</small></div>
    <div class="req-cell">${escape(c.vendor?.name || '—')}</div>
    <div class="req-cell mono" style="${dueColor}">${fmtDate(c.end_date)}<br/><small>${dueText}</small></div>
    <div class="req-cell"><span class="status s-${c.status==='active'||c.status==='renewed'?'approved':c.status==='expired'||c.status==='cancelled'?'rejected':'pending_approval'}"><span class="dot"></span>${escape(c.status.replace(/_/g,' '))}</span></div>
    <div class="req-cell mono">${c.cost ? Number(c.cost).toLocaleString() : '—'} ${escape(c.currency || '')}</div>
  </div>`;
}
function wireVCRows() {
  $$('[data-contract]').forEach(el => el.addEventListener('click', () => openContractEditor(el.dataset.contract)));
}

async function openVendorEditor(vendorId) {
  const { data: v } = vendorId ? await sb.from('vendors').select('*').eq('id', vendorId).single() : { data: null };
  const vend = v || {};
  $('#drawerBg').classList.add('show');
  $('#drawerTitle').textContent = vendorId ? vend.name : 'New Vendor';
  $('#drawerRef').textContent = vendorId ? vend.code : 'Add vendor';

  $('#drawerBody').innerHTML = `
    <div class="form-section">
      <div class="grid-2">
        <div class="field"><label class="required">Code</label><input id="vn-code" value="${escape(vend.code||'')}" placeholder="VND-0001" /></div>
        <div class="field"><label class="required">Name</label><input id="vn-name" value="${escape(vend.name||'')}" /></div>
        <div class="field"><label>Category</label><input id="vn-cat" value="${escape(vend.category||'')}" placeholder="network, security, cloud…" /></div>
        <div class="field"><label>Service type</label><input id="vn-svc" value="${escape(vend.service_type||'')}" placeholder="AMC, support, implementation" /></div>
        <div class="field"><label>Account manager</label><input id="vn-am" value="${escape(vend.account_manager_name||'')}" /></div>
        <div class="field"><label>AM email</label><input id="vn-am-email" type="email" value="${escape(vend.account_manager_email||'')}" /></div>
        <div class="field"><label>AM phone</label><input id="vn-am-phone" value="${escape(vend.account_manager_phone||'')}" /></div>
        <div class="field"><label>Support email</label><input id="vn-supp-email" type="email" value="${escape(vend.support_email||'')}" /></div>
        <div class="field"><label>Support phone</label><input id="vn-supp-phone" value="${escape(vend.support_phone||'')}" /></div>
        <div class="field"><label>Support portal URL</label><input id="vn-portal" value="${escape(vend.support_portal_url||'')}" /></div>
      </div>
    </div>
    <div class="btn-row">
      <button class="btn ok" id="vn-save">${vendorId?'Save':'Create vendor'}</button>
    </div>
  `;

  $('#vn-save').addEventListener('click', async () => {
    const get = (id) => document.getElementById(id)?.value?.trim() || '';
    if (!get('vn-code') || !get('vn-name')) { toast('Code and name required','error'); return; }
    const payload = {
      code: get('vn-code'), name: get('vn-name'),
      category: get('vn-cat') || null, service_type: get('vn-svc') || null,
      account_manager_name: get('vn-am') || null,
      account_manager_email: get('vn-am-email') || null,
      account_manager_phone: get('vn-am-phone') || null,
      support_email: get('vn-supp-email') || null,
      support_phone: get('vn-supp-phone') || null,
      support_portal_url: get('vn-portal') || null
    };
    const { error } = vendorId
      ? await sb.from('vendors').update(payload).eq('id', vendorId)
      : await sb.from('vendors').insert(payload);
    if (error) { toast(error.message, 'error'); return; }
    toast(vendorId?'Updated':'Vendor created', 'success');
    closeDrawer();
    route('vendors');
  });
}

async function openContractEditor(contractId, vendors) {
  const canWrite = isAdmin() || hasRole('it_manager') || hasRole('sysadmin') || hasRole('finance');
  if (!vendors) {
    const { data } = await sb.from('vendors').select('*').eq('is_active', true).order('name');
    vendors = data || [];
  }
  const [cRes, aRes, licRes, renewalsRes] = await Promise.all([
    contractId ? sb.from('vendor_contracts').select('*, vendor:vendors(name)').eq('id', contractId).single() : Promise.resolve({ data: null }),
    contractId ? sb.from('vendor_contract_attachments').select('*, uploader:profiles(full_name)').eq('contract_id', contractId).order('created_at', { ascending: false }) : Promise.resolve({ data: [] }),
    sb.from('license_items').select('id, item_code, item_name').order('item_code'),
    contractId ? sb.from('vendor_contract_renewals').select('*, renewer:profiles(full_name)').eq('contract_id', contractId).order('renewed_on', { ascending: false }) : Promise.resolve({ data: [] })
  ]);
  const c = cRes.data || {};
  const attachments = aRes.data || [];
  const licenses = licRes.data || [];
  const renewals = renewalsRes.data || [];

  $('#drawerBg').classList.add('show');
  $('#drawerTitle').textContent = contractId ? c.contract_title : 'New Contract / AMC';
  $('#drawerRef').innerHTML = contractId ? `${escape(c.contract_code)} · ${escape(c.vendor?.name||'')}` : 'Add contract';

  $('#drawerBody').innerHTML = `
    <div class="form-section"><h4>Identity</h4>
      <div class="grid-2">
        <div class="field"><label class="required">Contract code</label><input id="vc-code" value="${escape(c.contract_code||'')}" placeholder="AMC-2026-0012" /></div>
        <div class="field"><label class="required">Title</label><input id="vc-title" value="${escape(c.contract_title||'')}" /></div>
        <div class="field"><label class="required">Vendor</label>
          <select id="vc-vendor">
            <option value="">— select —</option>
            ${vendors.map(v => `<option value="${v.id}" ${c.vendor_id===v.id?'selected':''}>${escape(v.name)}</option>`).join('')}
          </select>
        </div>
        <div class="field"><label>Vendor's contract number</label><input id="vc-num" value="${escape(c.contract_number||'')}" /></div>
        <div class="field"><label>Service covered</label><input id="vc-svc" value="${escape(c.service_covered||'')}" /></div>
        <div class="field"><label>Linked license</label>
          <select id="vc-lic">
            <option value="">—</option>
            ${licenses.map(l => `<option value="${l.id}" ${c.license_id===l.id?'selected':''}>${escape(l.item_code)} · ${escape(l.item_name)}</option>`).join('')}
          </select>
        </div>
      </div>
    </div>
    <div class="form-section"><h4>Dates</h4>
      <div class="grid-3">
        <div class="field"><label class="required">Start</label><input id="vc-start" type="date" value="${c.start_date||''}" /></div>
        <div class="field"><label class="required">End</label><input id="vc-end" type="date" value="${c.end_date||''}" /></div>
        <div class="field"><label>Reminder (days before)</label><input id="vc-rem" type="number" value="${c.renewal_reminder_days||45}" /></div>
      </div>
    </div>
    <div class="form-section"><h4>SLA & Commercial</h4>
      <div class="grid-3">
        <div class="field"><label>Response time</label><input id="vc-sla-resp" value="${escape(c.sla_response_time||'')}" placeholder="e.g. 2 hours" /></div>
        <div class="field"><label>Resolution time</label><input id="vc-sla-res" value="${escape(c.sla_resolution_time||'')}" placeholder="e.g. 1 business day" /></div>
        <div class="field"><label>Support hours</label>
          <select id="vc-hours">
            ${['24x7','business_hours','nbd','mon_to_fri_9_5','mon_to_sat_9_6','custom'].map(h => `<option value="${h}" ${c.support_hours===h?'selected':''}>${h.replace(/_/g,' ')}</option>`).join('')}
          </select>
        </div>
        <div class="field"><label>Cost</label><input id="vc-cost" type="number" step="0.01" value="${c.cost||''}" /></div>
        <div class="field"><label>Currency</label><input id="vc-cur" value="${escape(c.currency||'AED')}" /></div>
        <div class="field"><label>Frequency</label>
          <select id="vc-freq">
            ${['one_time','monthly','quarterly','semi_annual','annual','biennial','triennial'].map(f => `<option value="${f}" ${c.payment_frequency===f?'selected':''}>${f.replace(/_/g,' ')}</option>`).join('')}
          </select>
        </div>
      </div>
      <div class="grid-2">
        <div class="field"><label>Covered systems (comma-separated)</label><input id="vc-sys" value="${escape((c.covered_systems||[]).join(', '))}" /></div>
        <div class="field"><label>Site coverage (comma-separated)</label><input id="vc-sites" value="${escape((c.site_coverage||[]).join(', '))}" placeholder="FFC-HO, TFM, ALL" /></div>
      </div>
      <div class="field"><label><input type="checkbox" id="vc-auto" ${c.auto_renew?'checked':''} /> Auto-renew</label></div>
      <div class="field"><label>Notes</label><textarea id="vc-notes" rows="2">${escape(c.notes||'')}</textarea></div>
    </div>

    ${contractId ? `
    <div class="detail-section">
      <h4>Attachments (${attachments.length})</h4>
      ${attachments.map(a => `
        <div class="attachment">
          <div class="info">${escape(a.file_name)}<small>${escape(a.document_type||'')} · ${escape(a.uploader?.full_name||'')} · ${fmtRel(a.created_at)}</small></div>
          <button class="btn secondary btn-sm" data-dl="${escape(a.storage_path)}" data-name="${escape(a.file_name)}">Download</button>
        </div>`).join('') || '<p style="color:var(--muted);font-size:12px">No attachments</p>'}
      <div class="field" style="margin-top:8px"><input type="file" id="vc-upload" /></div>
    </div>
    <div class="detail-section">
      <h4>Renewal history (${renewals.length})</h4>
      ${renewals.length ? renewals.map(r => `
        <div class="comment">
          <div class="comment-head">
            <div><span class="comment-author">${fmtDate(r.renewed_on)}</span>
              <span class="comment-flag">new end: ${fmtDate(r.new_end_date)}</span></div>
            <span class="comment-time">${escape(r.renewer?.full_name||'')}</span>
          </div>
          <div class="comment-body">${r.cost_paid?`Paid ${Number(r.cost_paid).toLocaleString()} ${escape(r.currency||'')}`:''}${r.remarks?`<br/>${escape(r.remarks)}`:''}</div>
        </div>`).join('') : '<p style="color:var(--muted);font-size:12px">No renewals yet</p>'}
    </div>` : ''}

    ${canWrite ? `<div class="btn-row">
      <button class="btn ok" id="vc-save">${contractId?'Save':'Create contract'}</button>
      ${contractId ? `<button class="btn warn" id="vc-renew">+ Record Renewal</button>` : ''}
    </div>` : ''}
  `;

  if (canWrite) {
    $('#vc-save').addEventListener('click', async () => {
      const get = (id) => document.getElementById(id)?.value?.trim() || '';
      if (!get('vc-code') || !get('vc-title') || !get('vc-vendor') || !get('vc-start') || !get('vc-end')) {
        toast('Code, title, vendor, start, end required', 'error'); return;
      }
      const payload = {
        contract_code: get('vc-code'), contract_title: get('vc-title'),
        vendor_id: get('vc-vendor'), contract_number: get('vc-num') || null,
        service_covered: get('vc-svc') || null,
        start_date: get('vc-start'), end_date: get('vc-end'),
        renewal_reminder_days: parseInt(get('vc-rem')) || 45,
        sla_response_time: get('vc-sla-resp') || null,
        sla_resolution_time: get('vc-sla-res') || null,
        support_hours: get('vc-hours'),
        cost: parseFloat(get('vc-cost')) || null,
        currency: get('vc-cur') || 'AED',
        payment_frequency: get('vc-freq'),
        covered_systems: get('vc-sys') ? get('vc-sys').split(',').map(s=>s.trim()).filter(Boolean) : null,
        site_coverage: get('vc-sites') ? get('vc-sites').split(',').map(s=>s.trim()).filter(Boolean) : null,
        license_id: get('vc-lic') || null,
        auto_renew: $('#vc-auto').checked,
        notes: get('vc-notes') || null
      };
      const { error } = contractId
        ? await sb.from('vendor_contracts').update(payload).eq('id', contractId)
        : await sb.from('vendor_contracts').insert({ ...payload, created_by: CURRENT_USER.id });
      if (error) { toast(error.message, 'error'); return; }
      toast(contractId?'Updated':'Created', 'success');
      closeDrawer();
      route('vendors');
    });

    const rBtn = $('#vc-renew');
    if (rBtn) rBtn.addEventListener('click', () => promptContractRenewal(contractId, c));

    const upload = $('#vc-upload');
    if (upload) {
      upload.addEventListener('change', async (e) => {
        const file = e.target.files[0]; if (!file) return;
        const path = `vendor_contracts/${contractId}/${Date.now()}_${file.name}`;
        const { error: upErr } = await sb.storage.from(CFG.STORAGE_BUCKET).upload(path, file);
        if (upErr) { toast(upErr.message,'error'); return; }
        await sb.from('vendor_contract_attachments').insert({
          contract_id: contractId, uploaded_by: CURRENT_USER.id,
          storage_path: path, file_name: file.name, file_size: file.size,
          mime_type: file.type, document_type: 'contract'
        });
        toast('Uploaded', 'success');
        openContractEditor(contractId, vendors);
      });
    }

    $$('[data-dl]').forEach(b => b.addEventListener('click', () => downloadAttachment(b.dataset.dl, b.dataset.name)));
  }
}

function promptContractRenewal(contractId, contract) {
  const newEnd = prompt('New end date (YYYY-MM-DD):');
  if (!newEnd) return;
  const cost = prompt('Cost paid (optional):', contract.cost || '');
  const po = prompt('PO / invoice (optional):', '');
  const remarks = prompt('Remarks (optional):', '');

  (async () => {
    const { error } = await sb.from('vendor_contract_renewals').insert({
      contract_id: contractId,
      renewed_on: new Date().toISOString().slice(0,10),
      previous_end_date: contract.end_date, new_end_date: newEnd,
      cost_paid: cost ? parseFloat(cost) : null, currency: contract.currency || 'AED',
      po_number: po || null, remarks: remarks || null,
      renewed_by: CURRENT_USER.id
    });
    if (error) { toast(error.message, 'error'); return; }
    toast('Renewal recorded', 'success');
    closeDrawer();
    route('vendors');
  })();
}

// ---------------- DR TRACKER ----------------
async function renderDRTracker() {
  const canWrite = isAdmin() || hasRole('it_manager') || hasRole('sysadmin');
  const [{ data: services }, { data: tests }] = await Promise.all([
    sb.from('dr_services').select('*, owner:profiles!dr_services_business_owner_id_fkey(full_name), infra:profiles!dr_services_infra_owner_id_fkey(full_name)').eq('is_active', true).order('criticality', { ascending: false }).order('service_name'),
    sb.from('dr_tests').select('*, service:dr_services(service_name, service_code, criticality)').order('planned_date', { ascending: false }).limit(50)
  ]);

  const overdue = (services||[]).filter(s => s.next_test_due && new Date(s.next_test_due) < new Date()).length;
  const upcoming = (services||[]).filter(s => s.next_test_due && new Date(s.next_test_due) >= new Date() && (new Date(s.next_test_due) - new Date()) / 86400000 <= 30).length;
  const critical = (services||[]).filter(s => s.criticality === 'critical').length;

  $('#viewContent').innerHTML = `
    <div class="stats-grid">
      <div class="stat"><div class="label">DR Services</div><div class="value">${(services||[]).length}</div></div>
      <div class="stat"><div class="label">Critical Services</div><div class="value">${critical}</div></div>
      <div class="stat warn"><div class="label">Tests Upcoming (30d)</div><div class="value">${upcoming}</div></div>
      <div class="stat danger"><div class="label">Tests Overdue</div><div class="value">${overdue}</div></div>
    </div>

    <div class="panel">
      <div class="panel-head">
        <h3>DR Services Registry</h3>
        <div class="right">${canWrite ? '<button class="btn ok btn-sm" id="btnNewService">+ Service</button>' : ''}</div>
      </div>
      <div class="panel-body">
        <div class="req-row head" style="grid-template-columns:120px 1fr 100px 90px 120px 130px">
          <div>Code</div><div>Service</div><div>Criticality</div><div>RPO/RTO</div><div>Last Tested</div><div>Next Due</div>
        </div>
        ${(services||[]).map(s => {
          const overdueNext = s.next_test_due && new Date(s.next_test_due) < new Date();
          return `<div class="req-row" data-service="${s.id}" style="grid-template-columns:120px 1fr 100px 90px 120px 130px">
            <div class="req-id">${escape(s.service_code)}</div>
            <div class="req-title">${escape(s.service_name)}<small>Owner: ${escape(s.owner?.full_name || '—')} · Infra: ${escape(s.infra?.full_name || '—')}</small></div>
            <div class="req-cell"><span class="status s-${s.criticality==='critical'?'rejected':s.criticality==='high'?'pending_approval':'approved'}"><span class="dot"></span>${escape(s.criticality)}</span></div>
            <div class="req-cell mono">${s.rpo_minutes||'—'}m / ${s.rto_minutes||'—'}m</div>
            <div class="req-cell mono">${fmtDate(s.last_tested_on)}</div>
            <div class="req-cell mono" ${overdueNext?'style="color:var(--red-deep)"':''}>${fmtDate(s.next_test_due)}</div>
          </div>`;
        }).join('') || emptyRow('No DR services registered')}
      </div>
    </div>

    <div class="panel">
      <div class="panel-head">
        <h3>Recent Tests</h3>
        <div class="right">${canWrite ? '<button class="btn ok btn-sm" id="btnNewTest">+ New Test</button>' : ''}</div>
      </div>
      <div class="panel-body">
        <div class="req-row head" style="grid-template-columns:160px 1fr 130px 110px 110px">
          <div>Code</div><div>Test</div><div>Type</div><div>Planned</div><div>Status</div>
        </div>
        ${(tests||[]).map(t => `<div class="req-row" data-drtest="${t.id}" style="grid-template-columns:160px 1fr 130px 110px 110px">
          <div class="req-id">${escape(t.test_code)}</div>
          <div class="req-title">${escape(t.test_title)}<small>${escape(t.service?.service_name || '')}</small></div>
          <div class="req-cell mono">${escape(t.test_type)}</div>
          <div class="req-cell mono">${fmtDate(t.planned_date)}</div>
          <div class="req-cell"><span class="status s-${t.status==='passed'||t.status==='completed'||t.status==='closed'?'approved':t.status==='failed'?'rejected':t.status==='cancelled'?'cancelled':'pending_approval'}"><span class="dot"></span>${escape(t.status.replace(/_/g,' '))}</span></div>
        </div>`).join('') || emptyRow('No tests recorded yet')}
      </div>
    </div>
  `;

  $$('[data-service]').forEach(el => el.addEventListener('click', () => openDRService(el.dataset.service, canWrite)));
  $$('[data-drtest]').forEach(el => el.addEventListener('click', () => openDRTest(el.dataset.drtest, canWrite)));

  if (canWrite) {
    $('#btnNewService').addEventListener('click', () => openDRService(null, canWrite));
    $('#btnNewTest').addEventListener('click', () => openDRTest(null, canWrite, services));
  }
}

async function openDRService(serviceId, canWrite) {
  const [sRes, uRes] = await Promise.all([
    serviceId ? sb.from('dr_services').select('*').eq('id', serviceId).single() : Promise.resolve({ data: null }),
    sb.from('profiles').select('id, full_name').eq('is_active', true).order('full_name')
  ]);
  const s = sRes.data || {};
  const users = uRes.data || [];

  $('#drawerBg').classList.add('show');
  $('#drawerTitle').textContent = serviceId ? s.service_name : 'New DR Service';
  $('#drawerRef').textContent = serviceId ? s.service_code : '';

  $('#drawerBody').innerHTML = `
    <div class="form-section">
      <div class="grid-2">
        <div class="field"><label class="required">Service code</label><input id="ds-code" value="${escape(s.service_code||'')}" placeholder="DR-SVC-001" /></div>
        <div class="field"><label class="required">Service name</label><input id="ds-name" value="${escape(s.service_name||'')}" /></div>
        <div class="field"><label>Category</label><input id="ds-cat" value="${escape(s.category||'')}" /></div>
        <div class="field"><label class="required">Criticality</label>
          <select id="ds-crit">${['low','medium','high','critical'].map(c => `<option value="${c}" ${s.criticality===c?'selected':''}>${c}</option>`).join('')}</select>
        </div>
        <div class="field"><label>Business owner</label>
          <select id="ds-biz">${userOpts(users, s.business_owner_id)}</select>
        </div>
        <div class="field"><label>Infra owner</label>
          <select id="ds-inf">${userOpts(users, s.infra_owner_id)}</select>
        </div>
        <div class="field"><label>Backup owner</label>
          <select id="ds-bck">${userOpts(users, s.backup_owner_id)}</select>
        </div>
        <div class="field"><label>RPO (minutes)</label><input id="ds-rpo" type="number" value="${s.rpo_minutes||''}" /></div>
        <div class="field"><label>RTO (minutes)</label><input id="ds-rto" type="number" value="${s.rto_minutes||''}" /></div>
        <div class="field"><label>Primary site</label><input id="ds-psite" value="${escape(s.primary_site||'')}" /></div>
        <div class="field"><label>DR site</label><input id="ds-dsite" value="${escape(s.dr_site||'')}" /></div>
        <div class="field"><label>Test frequency (months)</label><input id="ds-freq" type="number" value="${s.test_frequency_months||3}" /></div>
        <div class="field"><label>Dependencies (comma-separated)</label><input id="ds-dep" value="${escape((s.dependencies||[]).join(', '))}" /></div>
        <div class="field"><label>Next test due</label><input id="ds-next" type="date" value="${s.next_test_due||''}" /></div>
      </div>
      <div class="field"><label>Notes</label><textarea id="ds-notes" rows="2">${escape(s.notes||'')}</textarea></div>
    </div>
    ${canWrite ? `<div class="btn-row"><button class="btn ok" id="ds-save">${serviceId?'Save':'Create'}</button></div>` : ''}
  `;

  if (canWrite) {
    $('#ds-save').addEventListener('click', async () => {
      const get = (id) => document.getElementById(id)?.value?.trim() || '';
      if (!get('ds-code') || !get('ds-name')) { toast('Code and name required','error'); return; }
      const payload = {
        service_code: get('ds-code'), service_name: get('ds-name'),
        category: get('ds-cat')||null, criticality: get('ds-crit'),
        business_owner_id: get('ds-biz')||null, infra_owner_id: get('ds-inf')||null, backup_owner_id: get('ds-bck')||null,
        rpo_minutes: parseInt(get('ds-rpo'))||null, rto_minutes: parseInt(get('ds-rto'))||null,
        primary_site: get('ds-psite')||null, dr_site: get('ds-dsite')||null,
        test_frequency_months: parseInt(get('ds-freq'))||3,
        dependencies: get('ds-dep') ? get('ds-dep').split(',').map(x=>x.trim()).filter(Boolean) : null,
        next_test_due: get('ds-next')||null,
        notes: get('ds-notes')||null
      };
      const { error } = serviceId
        ? await sb.from('dr_services').update(payload).eq('id', serviceId)
        : await sb.from('dr_services').insert(payload);
      if (error) { toast(error.message, 'error'); return; }
      toast(serviceId?'Updated':'Service created', 'success');
      closeDrawer();
      route('dr-tracker');
    });
  }
}

function userOpts(users, selectedId) {
  return `<option value="">—</option>` + users.map(u => `<option value="${u.id}" ${selectedId===u.id?'selected':''}>${escape(u.full_name)}</option>`).join('');
}

async function openDRTest(testId, canWrite, servicesList) {
  const [tRes, sRes, uRes] = await Promise.all([
    testId ? sb.from('dr_tests').select('*, service:dr_services(service_name, service_code)').eq('id', testId).single() : Promise.resolve({ data: null }),
    servicesList ? Promise.resolve({ data: servicesList }) : sb.from('dr_services').select('id, service_code, service_name').eq('is_active', true).order('service_name'),
    sb.from('profiles').select('id, full_name').eq('is_active', true).order('full_name')
  ]);
  const t = tRes.data || {};
  const services = sRes.data || [];
  const users = uRes.data || [];

  $('#drawerBg').classList.add('show');
  $('#drawerTitle').textContent = testId ? t.test_title : 'New DR Test';
  $('#drawerRef').textContent = testId ? t.test_code : '';

  $('#drawerBody').innerHTML = `
    <div class="form-section">
      <div class="grid-2">
        <div class="field"><label class="required">Test code</label><input id="dt-code" value="${escape(t.test_code||'')}" placeholder="DR-TEST-2026-00001" /></div>
        <div class="field"><label class="required">Service</label>
          <select id="dt-svc">
            <option value="">—</option>
            ${services.map(s => `<option value="${s.id}" ${t.service_id===s.id?'selected':''}>${escape(s.service_code)} · ${escape(s.service_name)}</option>`).join('')}
          </select>
        </div>
        <div class="field"><label class="required">Test title</label><input id="dt-title" value="${escape(t.test_title||'')}" /></div>
        <div class="field"><label class="required">Type</label>
          <select id="dt-type">
            ${['tabletop','technical_restore','failover','partial_recovery','full_recovery','data_restore_test','full_dr_drill','backup_verification'].map(x => `<option value="${x}" ${t.test_type===x?'selected':''}>${x.replace(/_/g,' ')}</option>`).join('')}
          </select>
        </div>
        <div class="field"><label class="required">Planned date</label><input id="dt-planned" type="date" value="${t.planned_date||''}" /></div>
        <div class="field"><label>Actual date</label><input id="dt-actual" type="date" value="${t.actual_date||''}" /></div>
        <div class="field"><label>Lead engineer</label><select id="dt-lead">${userOpts(users, t.lead_engineer_id || CURRENT_USER.id)}</select></div>
        <div class="field"><label>Status</label>
          <select id="dt-status">
            ${['planned','scheduled','in_progress','completed','passed','passed_with_observations','failed','follow_up_required','closed','cancelled'].map(x => `<option value="${x}" ${t.status===x?'selected':''}>${x.replace(/_/g,' ')}</option>`).join('')}
          </select>
        </div>
        <div class="field"><label>Recovery duration (minutes)</label><input id="dt-dur" type="number" value="${t.recovery_duration_minutes||''}" /></div>
        <div class="field"><label>Issues count</label><input id="dt-issues" type="number" min="0" value="${t.issues_count||0}" /></div>
      </div>
      <div class="field"><label>Objective</label><textarea id="dt-obj" rows="2">${escape(t.test_objective||'')}</textarea></div>
      <div class="field"><label>Expected result</label><textarea id="dt-exp" rows="2">${escape(t.expected_result||'')}</textarea></div>
      <div class="field"><label>Actual result</label><textarea id="dt-act" rows="2">${escape(t.actual_result||'')}</textarea></div>
      <div class="field"><label>Observations</label><textarea id="dt-obs" rows="2">${escape(t.observations||'')}</textarea></div>
      <div class="field"><label>Issues found</label><textarea id="dt-isstxt" rows="2">${escape(t.issues_found||'')}</textarea></div>
      <div class="field"><label>Next action</label><textarea id="dt-next" rows="2">${escape(t.next_action||'')}</textarea></div>
    </div>
    ${canWrite ? `<div class="btn-row">
      <button class="btn ok" id="dt-save">${testId?'Save':'Create test'}</button>
      ${testId ? `<button class="btn warn" id="dt-capa">→ Create CAPA from this</button>` : ''}
    </div>` : ''}
  `;

  if (canWrite) {
    $('#dt-save').addEventListener('click', async () => {
      const get = (id) => document.getElementById(id)?.value?.trim() || '';
      if (!get('dt-code') || !get('dt-title') || !get('dt-svc') || !get('dt-planned')) {
        toast('Code, title, service, planned date required', 'error'); return;
      }
      const payload = {
        test_code: get('dt-code'), test_title: get('dt-title'),
        service_id: get('dt-svc'), test_type: get('dt-type'),
        planned_date: get('dt-planned'), actual_date: get('dt-actual')||null,
        lead_engineer_id: get('dt-lead')||null,
        status: get('dt-status'),
        recovery_duration_minutes: parseInt(get('dt-dur'))||null,
        issues_count: parseInt(get('dt-issues'))||0,
        test_objective: get('dt-obj')||null, expected_result: get('dt-exp')||null,
        actual_result: get('dt-act')||null, observations: get('dt-obs')||null,
        issues_found: get('dt-isstxt')||null, next_action: get('dt-next')||null
      };
      const { error } = testId
        ? await sb.from('dr_tests').update(payload).eq('id', testId)
        : await sb.from('dr_tests').insert({ ...payload, created_by: CURRENT_USER.id });
      if (error) { toast(error.message, 'error'); return; }
      toast(testId?'Updated':'Test recorded', 'success');
      closeDrawer();
      route('dr-tracker');
    });

    const cBtn = $('#dt-capa');
    if (cBtn) cBtn.addEventListener('click', async () => {
      const title = prompt('CAPA title:', `Follow-up from ${t.test_title}`);
      if (!title) return;
      const issue = prompt('Issue / finding summary:', t.issues_found || t.observations || '');
      if (!issue) return;
      const severity = prompt('Severity (low/medium/high/critical):', 'medium') || 'medium';
      const target = prompt('Target date (YYYY-MM-DD):', new Date(Date.now()+30*86400000).toISOString().slice(0,10));
      if (!target) return;
      const corrective = prompt('Corrective action:', '');
      const preventive = prompt('Preventive action:', '');

      const { error } = await sb.rpc('create_capa_from_dr_test', {
        p_test_id: testId, p_title: title, p_issue: issue,
        p_severity: severity, p_owner: CURRENT_USER.id, p_target_date: target,
        p_corrective: corrective || null, p_preventive: preventive || null
      });
      if (error) { toast(error.message, 'error'); return; }
      toast('CAPA created · check the CAPA register', 'success');
    });
  }
}

// ---------------- CAPA REGISTER ----------------
async function renderCAPAs() {
  const [{ data: m }, { data: capas }] = await Promise.all([
    sb.rpc('governance2_metrics'),
    sb.from('capas').select('*, owner:profiles!capas_owner_id_fkey(full_name), reviewer:profiles!capas_reviewer_id_fkey(full_name)').order('target_date', { ascending: true }).limit(300)
  ]);
  const metrics = m || {};

  const byStatus = {};
  (capas||[]).forEach(c => { byStatus[c.status] = (byStatus[c.status]||0)+1; });

  $('#viewContent').innerHTML = `
    <div class="stats-grid">
      <div class="stat accent"><div class="label">My Open CAPAs</div><div class="value">${metrics.my_capas_open ?? 0}</div></div>
      <div class="stat danger"><div class="label">My Overdue</div><div class="value">${metrics.my_capas_overdue ?? 0}</div></div>
      <div class="stat warn"><div class="label">Critical Open</div><div class="value">${metrics.capas_critical_open ?? 0}</div></div>
      <div class="stat"><div class="label">Total Open</div><div class="value">${metrics.capas_total_open ?? 0}</div></div>
    </div>

    <div class="filter-bar">
      <select id="capaStatus"><option value="">All statuses</option>
        ${['open','assigned','in_progress','pending_evidence','pending_verification','overdue','closed','cancelled','rejected'].map(s => `<option value="${s}">${s.replace(/_/g,' ')}</option>`).join('')}
      </select>
      <select id="capaSev"><option value="">All severities</option>
        <option value="critical">Critical</option><option value="high">High</option>
        <option value="medium">Medium</option><option value="low">Low</option>
      </select>
      <select id="capaMine"><option value="">All CAPAs</option><option value="mine">My CAPAs</option></select>
      <input id="capaSearch" placeholder="Search title, code…" />
      <span class="count" id="capaCount">${(capas||[]).length} CAPAs</span>
      <button class="btn ok btn-sm" id="btnNewCapa" style="margin-left:8px">+ New CAPA</button>
    </div>

    <div class="panel"><div class="panel-body" id="capaList">
      ${renderCAPARowsHeader()}
      ${(capas||[]).length ? capas.map(capaRow).join('') : emptyRow('No CAPAs yet')}
    </div></div>
  `;
  wireCAPARows();

  const apply = () => {
    const s = $('#capaStatus').value, sv = $('#capaSev').value, m = $('#capaMine').value, q = $('#capaSearch').value.toLowerCase().trim();
    const f = (capas||[]).filter(c =>
      (!s || c.status === s) && (!sv || c.severity === sv) &&
      (m !== 'mine' || c.owner_id === CURRENT_USER.id) &&
      (!q || (c.capa_code||'').toLowerCase().includes(q) || (c.title||'').toLowerCase().includes(q))
    );
    $('#capaList').innerHTML = renderCAPARowsHeader() + (f.length ? f.map(capaRow).join('') : emptyRow('No matches'));
    $('#capaCount').textContent = `${f.length} CAPAs`;
    wireCAPARows();
  };
  ['capaStatus','capaSev','capaMine','capaSearch'].forEach(id => $('#'+id).addEventListener('input', apply));

  $('#btnNewCapa').addEventListener('click', () => openCAPAEditor(null));
}

function renderCAPARowsHeader() {
  return `<div class="req-row head" style="grid-template-columns:140px 1fr 120px 100px 100px 120px">
    <div>Code</div><div>Title</div><div>Owner</div><div>Severity</div><div>Target</div><div>Status</div>
  </div>`;
}
function capaRow(c) {
  const overdue = c.status === 'overdue' || (c.target_date && new Date(c.target_date) < new Date() && c.status !== 'closed' && c.status !== 'cancelled');
  return `<div class="req-row" data-capa="${c.id}" style="grid-template-columns:140px 1fr 120px 100px 100px 120px">
    <div class="req-id">${escape(c.capa_code)}</div>
    <div class="req-title">${escape(c.title)}<small>${escape(c.source_type)}${c.source_ref?` · ${escape(c.source_ref)}`:''}</small></div>
    <div class="req-cell">${escape(c.owner?.full_name || '—')}</div>
    <div class="req-cell"><span class="status s-${c.severity==='critical'?'rejected':c.severity==='high'?'pending_approval':'approved'}"><span class="dot"></span>${escape(c.severity)}</span></div>
    <div class="req-cell mono" ${overdue?'style="color:var(--red-deep)"':''}>${fmtDate(c.target_date)}</div>
    <div class="req-cell"><span class="status s-${c.status==='closed'?'approved':c.status==='overdue'||c.status==='rejected'?'rejected':c.status==='cancelled'?'cancelled':'pending_approval'}"><span class="dot"></span>${escape(c.status.replace(/_/g,' '))}</span></div>
  </div>`;
}
function wireCAPARows() {
  $$('[data-capa]').forEach(el => el.addEventListener('click', () => openCAPAEditor(el.dataset.capa)));
}

async function openCAPAEditor(capaId) {
  const [cRes, uRes, histRes, cmtRes, attRes] = await Promise.all([
    capaId ? sb.from('capas').select('*').eq('id', capaId).single() : Promise.resolve({ data: null }),
    sb.from('profiles').select('id, full_name').eq('is_active', true).order('full_name'),
    capaId ? sb.from('capa_history').select('*, actor:profiles(full_name)').eq('capa_id', capaId).order('occurred_at') : Promise.resolve({ data: [] }),
    capaId ? sb.from('capa_comments').select('*, author:profiles(full_name)').eq('capa_id', capaId).order('created_at') : Promise.resolve({ data: [] }),
    capaId ? sb.from('capa_attachments').select('*, uploader:profiles(full_name)').eq('capa_id', capaId) : Promise.resolve({ data: [] })
  ]);
  const c = cRes.data || {};
  const users = uRes.data || [];
  const history = histRes.data || [];
  const comments = cmtRes.data || [];
  const attachments = attRes.data || [];

  const canEdit = !capaId
    || c.owner_id === CURRENT_USER.id
    || c.reviewer_id === CURRENT_USER.id
    || c.created_by === CURRENT_USER.id
    || isAdmin() || hasRole('it_manager');

  $('#drawerBg').classList.add('show');
  $('#drawerTitle').textContent = capaId ? c.title : 'New CAPA';
  $('#drawerRef').innerHTML = capaId ? `${escape(c.capa_code)} · <span class="status s-${c.severity==='critical'?'rejected':c.severity==='high'?'pending_approval':'approved'}">${escape(c.severity)}</span>` : '';

  $('#drawerBody').innerHTML = `
    <div class="form-section"><h4>Details</h4>
      <div class="grid-2">
        <div class="field"><label class="required">Title</label><input id="cp-title" value="${escape(c.title||'')}" /></div>
        <div class="field"><label class="required">Source</label>
          <select id="cp-src">${['dr_test','branch_compliance','audit','security_finding','recurring_issue','checklist_miss','root_cause_analysis','incident_post_mortem','vendor_issue','other'].map(x => `<option value="${x}" ${c.source_type===x?'selected':''}>${x.replace(/_/g,' ')}</option>`).join('')}</select>
        </div>
        <div class="field"><label>Source reference</label><input id="cp-srcref" value="${escape(c.source_ref||'')}" /></div>
        <div class="field"><label class="required">Severity</label>
          <select id="cp-sev">${['low','medium','high','critical'].map(x => `<option value="${x}" ${c.severity===x?'selected':''}>${x}</option>`).join('')}</select>
        </div>
        <div class="field"><label class="required">Owner</label><select id="cp-owner">${userOpts(users, c.owner_id || CURRENT_USER.id)}</select></div>
        <div class="field"><label>Reviewer</label><select id="cp-rev">${userOpts(users, c.reviewer_id)}</select></div>
        <div class="field"><label class="required">Target date</label><input id="cp-target" type="date" value="${c.target_date||new Date(Date.now()+30*86400000).toISOString().slice(0,10)}" /></div>
        <div class="field"><label>Status</label>
          <select id="cp-status">${['draft','open','under_review','assigned','in_progress','pending_evidence','pending_verification','closed','cancelled','rejected'].map(x => `<option value="${x}" ${(c.status||'open')===x?'selected':''}>${x.replace(/_/g,' ')}</option>`).join('')}</select>
        </div>
      </div>
      <div class="field"><label class="required">Issue summary</label><textarea id="cp-issue" rows="3">${escape(c.issue_summary||'')}</textarea></div>
      <div class="field"><label>Business impact</label><textarea id="cp-impact" rows="2">${escape(c.business_impact||'')}</textarea></div>
      <div class="field"><label>Root cause summary</label><textarea id="cp-root" rows="2">${escape(c.root_cause_summary||'')}</textarea></div>
      <div class="field"><label>Corrective action</label><textarea id="cp-corr" rows="2">${escape(c.corrective_action||'')}</textarea></div>
      <div class="field"><label>Preventive action</label><textarea id="cp-prev" rows="2">${escape(c.preventive_action||'')}</textarea></div>
      <div class="field"><label>Closure note</label><textarea id="cp-close" rows="2">${escape(c.closure_note||'')}</textarea></div>
    </div>

    ${capaId ? `
      <div class="detail-section"><h4>Attachments (${attachments.length})</h4>
        ${attachments.map(a => `<div class="attachment">
          <div class="info">${escape(a.file_name)}<small>${escape(a.purpose||'')} · ${escape(a.uploader?.full_name||'')} · ${fmtRel(a.created_at)}</small></div>
          <button class="btn secondary btn-sm" data-dl="${escape(a.storage_path)}" data-name="${escape(a.file_name)}">Download</button>
        </div>`).join('') || '<p style="color:var(--muted);font-size:12px">No attachments</p>'}
        <div class="field" style="margin-top:8px"><input type="file" id="cp-upload" /></div>
      </div>
      <div class="detail-section"><h4>Comments (${comments.length})</h4>
        ${comments.map(cm => `<div class="comment">
          <div class="comment-head">
            <div><span class="comment-author">${escape(cm.author?.full_name||'')}</span></div>
            <span class="comment-time">${fmtDateTime(cm.created_at)}</span>
          </div>
          <div class="comment-body">${escape(cm.body)}</div>
        </div>`).join('') || '<p style="color:var(--muted);font-size:12px">No comments</p>'}
        <textarea id="cp-newcmt" rows="2" placeholder="Add a comment…"></textarea>
        <div class="btn-row"><button class="btn btn-sm" id="cp-postcmt">Post comment</button></div>
      </div>
      <div class="detail-section"><h4>Audit trail</h4>
        <div class="timeline">
          ${history.map(h => `<div class="tl-step done">
            <h5>${escape(h.action.replace(/_/g,' '))}</h5>
            <div class="meta">${escape(h.actor?.full_name||'system')} · ${fmtDateTime(h.occurred_at)}</div>
          </div>`).join('') || '<p style="color:var(--muted);font-size:12px">No events</p>'}
        </div>
      </div>
    ` : ''}

    ${canEdit ? `<div class="btn-row">
      <button class="btn ok" id="cp-save">${capaId?'Save':'Create CAPA'}</button>
      ${capaId && c.status !== 'closed' ? '<button class="btn warn" id="cp-verify">Mark Verified & Close</button>' : ''}
    </div>` : ''}
  `;

  if (canEdit) {
    $('#cp-save').addEventListener('click', async () => {
      const get = (id) => document.getElementById(id)?.value?.trim() || '';
      if (!get('cp-title') || !get('cp-issue') || !get('cp-target')) {
        toast('Title, issue, target date required', 'error'); return;
      }
      const oldStatus = c.status;
      const newStatus = get('cp-status');
      const payload = {
        title: get('cp-title'),
        issue_summary: get('cp-issue'),
        source_type: get('cp-src'),
        source_ref: get('cp-srcref')||null,
        severity: get('cp-sev'),
        owner_id: get('cp-owner'),
        reviewer_id: get('cp-rev')||null,
        target_date: get('cp-target'),
        status: newStatus,
        business_impact: get('cp-impact')||null,
        root_cause_summary: get('cp-root')||null,
        corrective_action: get('cp-corr')||null,
        preventive_action: get('cp-prev')||null,
        closure_note: get('cp-close')||null
      };
      let id = capaId;
      if (capaId) {
        const { error } = await sb.from('capas').update(payload).eq('id', capaId);
        if (error) { toast(error.message, 'error'); return; }
      } else {
        payload.capa_code = null;  // trigger-less, we'll call RPC-free insert below
        const { data: codeRow } = await sb.rpc('generate_capa_code');
        payload.capa_code = codeRow;
        payload.created_by = CURRENT_USER.id;
        const { data, error } = await sb.from('capas').insert(payload).select().single();
        if (error) { toast(error.message, 'error'); return; }
        id = data.id;
      }
      if (capaId && oldStatus !== newStatus) {
        await sb.from('capa_history').insert({
          capa_id: id, actor_id: CURRENT_USER.id,
          action: 'status_change', from_status: oldStatus, to_status: newStatus
        });
      } else if (!capaId) {
        await sb.from('capa_history').insert({
          capa_id: id, actor_id: CURRENT_USER.id, action: 'created', to_status: payload.status
        });
      }
      toast(capaId?'Updated':'CAPA created', 'success');
      closeDrawer();
      route('capas');
    });

    const vBtn = $('#cp-verify');
    if (vBtn) vBtn.addEventListener('click', async () => {
      const note = prompt('Closure note:', '');
      if (note === null) return;
      const { error } = await sb.from('capas').update({
        status: 'closed',
        closed_on: new Date().toISOString().slice(0,10),
        verified_by: CURRENT_USER.id,
        verified_at: new Date().toISOString(),
        closure_note: note || c.closure_note
      }).eq('id', capaId);
      if (error) { toast(error.message, 'error'); return; }
      await sb.from('capa_history').insert({
        capa_id: capaId, actor_id: CURRENT_USER.id,
        action: 'verified_and_closed', from_status: c.status, to_status: 'closed'
      });
      toast('CAPA closed', 'success');
      closeDrawer();
      route('capas');
    });

    const postBtn = $('#cp-postcmt');
    if (postBtn) postBtn.addEventListener('click', async () => {
      const body = $('#cp-newcmt').value.trim();
      if (!body) return;
      const { error } = await sb.from('capa_comments').insert({
        capa_id: capaId, author_id: CURRENT_USER.id, body
      });
      if (error) { toast(error.message, 'error'); return; }
      openCAPAEditor(capaId);
    });

    const upload = $('#cp-upload');
    if (upload) upload.addEventListener('change', async (e) => {
      const file = e.target.files[0]; if (!file) return;
      const path = `capas/${capaId}/${Date.now()}_${file.name}`;
      const { error: upErr } = await sb.storage.from(CFG.STORAGE_BUCKET).upload(path, file);
      if (upErr) { toast(upErr.message, 'error'); return; }
      await sb.from('capa_attachments').insert({
        capa_id: capaId, uploaded_by: CURRENT_USER.id,
        storage_path: path, file_name: file.name, file_size: file.size,
        mime_type: file.type, purpose: 'evidence'
      });
      await sb.from('capas').update({ evidence_attached: true }).eq('id', capaId);
      toast('Uploaded', 'success');
      openCAPAEditor(capaId);
    });

    $$('[data-dl]').forEach(b => b.addEventListener('click', () => downloadAttachment(b.dataset.dl, b.dataset.name)));
  }
}

// ---------------- BRANCH COMPLIANCE ----------------
async function renderBranchCompliance() {
  const canWrite = isAdmin() || hasRole('it_manager');
  const [{ data: branches }, { data: audits }, { data: areas }] = await Promise.all([
    sb.from('branches').select('*, owner:profiles(full_name)').eq('is_active', true).order('branch_name'),
    sb.from('branch_compliance_audits').select('*, branch:branches(branch_name, branch_code), auditor:profiles!branch_compliance_audits_auditor_id_fkey(full_name)').order('created_at', { ascending: false }).limit(300),
    sb.from('compliance_control_areas').select('*').eq('is_active', true).order('sort_order')
  ]);

  const totalBranches = (branches||[]).length;
  const nonCompliant = (audits||[]).filter(a => a.result === 'non_compliant' || a.result === 'action_required').length;
  const avgScore = (audits||[]).length ? ((audits||[]).reduce((s,a) => s + Number(a.compliance_pct || 0), 0) / (audits||[]).length).toFixed(1) : '—';

  $('#viewContent').innerHTML = `
    <div class="stats-grid">
      <div class="stat accent"><div class="label">Branches</div><div class="value">${totalBranches}</div></div>
      <div class="stat"><div class="label">Audits (total)</div><div class="value">${(audits||[]).length}</div></div>
      <div class="stat warn"><div class="label">Non-compliant</div><div class="value">${nonCompliant}</div></div>
      <div class="stat"><div class="label">Avg Compliance %</div><div class="value">${avgScore}</div></div>
    </div>

    <div class="panel">
      <div class="panel-head"><h3>Branches</h3>
        <div class="right">${canWrite ? '<button class="btn ok btn-sm" id="btnNewBranch">+ Branch</button>' : ''}</div>
      </div>
      <div class="panel-body">
        <div class="req-row head" style="grid-template-columns:130px 1fr 1fr 120px 110px">
          <div>Code</div><div>Branch</div><div>IT Owner</div><div>Support</div><div>Actions</div>
        </div>
        ${(branches||[]).map(b => `<div class="req-row" style="grid-template-columns:130px 1fr 1fr 120px 110px;cursor:default">
          <div class="req-id">${escape(b.branch_code)}</div>
          <div class="req-title">${escape(b.branch_name)}<small>${escape(b.location||'')}</small></div>
          <div class="req-cell">${escape(b.owner?.full_name || '—')}</div>
          <div class="req-cell mono">${escape(b.support_mode)}</div>
          <div class="req-cell"><button class="btn btn-sm secondary" data-branch-audit="${b.id}">+ Audit</button></div>
        </div>`).join('') || emptyRow('No branches configured')}
      </div>
    </div>

    <div class="panel">
      <div class="panel-head"><h3>Recent Audits</h3></div>
      <div class="panel-body">
        <div class="req-row head" style="grid-template-columns:130px 1fr 130px 120px 110px 100px">
          <div>Code</div><div>Branch / Period</div><div>Auditor</div><div>Compliance</div><div>Status</div><div></div>
        </div>
        ${(audits||[]).map(a => `<div class="req-row" data-audit="${a.id}" style="grid-template-columns:130px 1fr 130px 120px 110px 100px">
          <div class="req-id">${escape(a.audit_code)}</div>
          <div class="req-title">${escape(a.branch?.branch_name || '')}<small>${escape(a.period_label || '')}</small></div>
          <div class="req-cell">${escape(a.auditor?.full_name || '—')}</div>
          <div class="req-cell mono">${a.compliance_pct ? Number(a.compliance_pct).toFixed(1)+'%' : '—'}</div>
          <div class="req-cell"><span class="status s-${a.result==='compliant'||a.result==='verified'||a.result==='closed'?'approved':a.result==='non_compliant'||a.result==='action_required'?'rejected':a.result==='partially_compliant'?'pending_approval':'cancelled'}"><span class="dot"></span>${escape(a.result.replace(/_/g,' '))}</span></div>
          <div class="req-cell" style="text-align:right">›</div>
        </div>`).join('') || emptyRow('No audits yet')}
      </div>
    </div>
  `;

  $$('[data-branch-audit]').forEach(el => el.addEventListener('click', (e) => {
    e.stopPropagation();
    startNewAudit(el.dataset.branchAudit);
  }));
  $$('[data-audit]').forEach(el => el.addEventListener('click', () => openAuditEditor(el.dataset.audit)));

  if (canWrite) {
    $('#btnNewBranch').addEventListener('click', () => openBranchEditor(null));
  }
}

async function openBranchEditor(branchId) {
  const [bRes, uRes] = await Promise.all([
    branchId ? sb.from('branches').select('*').eq('id', branchId).single() : Promise.resolve({ data: null }),
    sb.from('profiles').select('id, full_name').eq('is_active', true).order('full_name')
  ]);
  const b = bRes.data || {};
  const users = uRes.data || [];

  $('#drawerBg').classList.add('show');
  $('#drawerTitle').textContent = branchId ? b.branch_name : 'New Branch';

  $('#drawerBody').innerHTML = `
    <div class="form-section">
      <div class="grid-2">
        <div class="field"><label class="required">Code</label><input id="br-code" value="${escape(b.branch_code||'')}" placeholder="BR-HO-01" /></div>
        <div class="field"><label class="required">Name</label><input id="br-name" value="${escape(b.branch_name||'')}" /></div>
        <div class="field"><label>Location</label><input id="br-loc" value="${escape(b.location||'')}" /></div>
        <div class="field"><label>Branch manager name</label><input id="br-mgr" value="${escape(b.branch_manager_name||'')}" /></div>
        <div class="field"><label>Branch manager email</label><input id="br-mgr-email" type="email" value="${escape(b.branch_manager_email||'')}" /></div>
        <div class="field"><label>Assigned IT owner</label><select id="br-owner">${userOpts(users, b.assigned_it_owner_id)}</select></div>
        <div class="field"><label>Support mode</label>
          <select id="br-mode">${['on_site','remote','hybrid'].map(m => `<option value="${m}" ${b.support_mode===m?'selected':''}>${m}</option>`).join('')}</select>
        </div>
      </div>
    </div>
    <div class="btn-row"><button class="btn ok" id="br-save">${branchId?'Save':'Create'}</button></div>
  `;

  $('#br-save').addEventListener('click', async () => {
    const get = (id) => document.getElementById(id)?.value?.trim() || '';
    if (!get('br-code') || !get('br-name')) { toast('Code and name required', 'error'); return; }
    const payload = {
      branch_code: get('br-code'), branch_name: get('br-name'),
      location: get('br-loc')||null,
      branch_manager_name: get('br-mgr')||null,
      branch_manager_email: get('br-mgr-email')||null,
      assigned_it_owner_id: get('br-owner')||null,
      support_mode: get('br-mode')
    };
    const { error } = branchId
      ? await sb.from('branches').update(payload).eq('id', branchId)
      : await sb.from('branches').insert(payload);
    if (error) { toast(error.message, 'error'); return; }
    toast('Saved', 'success');
    closeDrawer();
    route('branch-compliance');
  });
}

async function startNewAudit(branchId) {
  const period = prompt('Audit period label (e.g. "Q2 2026"):', `Q${Math.floor(new Date().getMonth()/3)+1} ${new Date().getFullYear()}`);
  if (!period) return;

  // Generate audit code
  const { data: maxRow } = await sb.from('branch_compliance_audits').select('audit_code').like('audit_code', `BCA-${new Date().getFullYear()}-%`).order('created_at', { ascending: false }).limit(1);
  const lastSeq = maxRow?.[0]?.audit_code?.split('-')?.[2] || '00000';
  const nextSeq = String(parseInt(lastSeq) + 1).padStart(5, '0');
  const code = `BCA-${new Date().getFullYear()}-${nextSeq}`;

  const { data: audit, error } = await sb.from('branch_compliance_audits').insert({
    audit_code: code,
    branch_id: branchId,
    period_label: period,
    auditor_id: CURRENT_USER.id,
    created_by: CURRENT_USER.id,
    result: 'in_review',
    started_at: new Date().toISOString()
  }).select().single();
  if (error) { toast(error.message, 'error'); return; }

  // Pull all active controls and create findings
  const { data: controls } = await sb.from('compliance_controls').select('*').eq('is_active', true).order('sort_order');
  if (controls?.length) {
    const findings = controls.map(c => ({
      audit_id: audit.id,
      control_id: c.id,
      control_code_snapshot: c.code,
      control_name_snapshot: c.name,
      max_score: Number(c.weight) || 1.0
    }));
    await sb.from('compliance_findings').insert(findings);
  }

  toast(`Audit ${code} started`, 'success');
  openAuditEditor(audit.id);
}

async function openAuditEditor(auditId) {
  const canWrite = isAdmin() || hasRole('it_manager');
  const [aRes, fRes, uRes] = await Promise.all([
    sb.from('branch_compliance_audits').select('*, branch:branches(branch_name, branch_code, location)').eq('id', auditId).single(),
    sb.from('compliance_findings').select('*, control:compliance_controls(name, description, is_critical, expected_evidence, control_area:compliance_control_areas(name, code))').eq('audit_id', auditId).order('control_code_snapshot'),
    sb.from('profiles').select('id, full_name').eq('is_active', true).order('full_name')
  ]);
  const a = aRes.data;
  const findings = fRes.data || [];
  const users = uRes.data || [];
  if (!a) return;

  const isAuditor = a.auditor_id === CURRENT_USER.id;
  const canEdit = canWrite || isAuditor;

  // Group findings by control area
  const byArea = {};
  findings.forEach(f => {
    const key = f.control?.control_area?.name || 'Other';
    (byArea[key] ||= []).push(f);
  });

  $('#drawerBg').classList.add('show');
  $('#drawerTitle').textContent = `${a.branch?.branch_name || ''} — ${a.period_label}`;
  $('#drawerRef').innerHTML = `${escape(a.audit_code)} · <span class="status s-${a.result==='compliant'?'approved':a.result==='non_compliant'?'rejected':'pending_approval'}">${escape(a.result.replace(/_/g,' '))}</span> · ${a.compliance_pct ? Number(a.compliance_pct).toFixed(1)+'%' : '—'}`;

  $('#drawerBody').innerHTML = `
    <div class="detail-meta">
      <div class="m-item"><label>Branch</label><span>${escape(a.branch?.branch_code)}</span></div>
      <div class="m-item"><label>Period</label><span>${escape(a.period_label)}</span></div>
      <div class="m-item"><label>Score</label><span>${a.score ? Number(a.score).toFixed(1) : '—'} / ${a.max_score ? Number(a.max_score).toFixed(1) : '—'}</span></div>
      <div class="m-item"><label>Compliance</label><span>${a.compliance_pct ? Number(a.compliance_pct).toFixed(1)+'%' : '—'}</span></div>
    </div>

    ${Object.entries(byArea).map(([area, items]) => `
      <div class="detail-section">
        <h4>${escape(area)} (${items.length})</h4>
        ${items.map(f => renderFindingRow(f, canEdit, users)).join('')}
      </div>
    `).join('')}

    ${canEdit ? `
      <div class="field"><label>Overall notes</label><textarea id="au-notes" rows="2">${escape(a.overall_notes||'')}</textarea></div>
      <div class="btn-row">
        <button class="btn ok" id="au-save">Save overall notes</button>
        <button class="btn warn" id="au-submit">Mark Submitted</button>
        ${canWrite ? '<button class="btn secondary" id="au-verify">Verify & Close</button>' : ''}
      </div>` : ''}
  `;

  // Wire up per-finding inputs
  findings.forEach(f => wireFindingInputs(f, users));

  if (canEdit) {
    $('#au-save').addEventListener('click', async () => {
      await sb.from('branch_compliance_audits').update({ overall_notes: $('#au-notes').value.trim() || null }).eq('id', auditId);
      toast('Saved', 'success');
    });
    $('#au-submit').addEventListener('click', async () => {
      await sb.from('branch_compliance_audits').update({
        submitted_at: new Date().toISOString(),
        overall_notes: $('#au-notes').value.trim() || null
      }).eq('id', auditId);
      toast('Submitted for review', 'success');
      closeDrawer();
      route('branch-compliance');
    });
    const vBtn = $('#au-verify');
    if (vBtn) vBtn.addEventListener('click', async () => {
      await sb.from('branch_compliance_audits').update({
        reviewer_id: CURRENT_USER.id,
        verified_at: new Date().toISOString(),
        result: 'verified'
      }).eq('id', auditId);
      toast('Verified', 'success');
      closeDrawer();
      route('branch-compliance');
    });
  }
}

function renderFindingRow(f, canEdit, users) {
  return `<div class="comment" data-finding="${f.id}" style="margin-bottom:10px">
    <div class="comment-head">
      <div>
        <span class="comment-author">${escape(f.control_code_snapshot)} — ${escape(f.control_name_snapshot)}</span>
        ${f.control?.is_critical ? '<span class="comment-flag" style="background:var(--red-deep)">critical</span>' : ''}
        ${f.linked_capa_id ? '<span class="comment-flag" style="background:var(--orange)">CAPA linked</span>' : ''}
      </div>
    </div>
    ${f.control?.description ? `<div style="font-size:12px;color:var(--muted);margin-top:4px">${escape(f.control.description)}</div>` : ''}

    ${canEdit ? `
    <div class="grid-3" style="margin-top:8px">
      <div class="field">
        <label style="font-size:10px">Result</label>
        <select data-f-field="is_compliant" data-fid="${f.id}">
          <option value="">— not assessed —</option>
          <option value="true" ${f.is_compliant===true&&!f.partial?'selected':''}>Compliant</option>
          <option value="partial" ${f.partial?'selected':''}>Partial</option>
          <option value="false" ${f.is_compliant===false&&!f.partial?'selected':''}>Non-compliant</option>
        </select>
      </div>
      <div class="field">
        <label style="font-size:10px">Score (max ${f.max_score||1})</label>
        <input type="number" step="0.1" min="0" max="${f.max_score||1}" data-f-field="score_awarded" data-fid="${f.id}" value="${f.score_awarded??''}" />
      </div>
      <div class="field">
        <label style="font-size:10px">Owner</label>
        <select data-f-field="owner_id" data-fid="${f.id}">${userOpts(users, f.owner_id)}</select>
      </div>
    </div>
    <div class="field" style="margin-top:4px"><label style="font-size:10px">Finding / remarks</label>
      <textarea rows="1" data-f-field="finding_description" data-fid="${f.id}">${escape(f.finding_description||'')}</textarea>
    </div>
    <div class="field" style="margin-top:4px"><label style="font-size:10px">Action required</label>
      <textarea rows="1" data-f-field="action_required" data-fid="${f.id}">${escape(f.action_required||'')}</textarea>
    </div>
    <div class="btn-row" style="margin-top:6px">
      <button class="btn secondary btn-sm" data-f-save="${f.id}">Save</button>
      ${!f.linked_capa_id ? `<button class="btn warn btn-sm" data-f-capa="${f.id}">→ Create CAPA</button>` : ''}
    </div>
    ` : `
    <div style="font-size:12.5px;color:var(--ink-soft);margin-top:6px">
      Result: <b>${f.is_compliant===null?'Not assessed':f.partial?'Partial':f.is_compliant?'Compliant':'Non-compliant'}</b>
      ${f.finding_description ? `<br/>${escape(f.finding_description)}` : ''}
    </div>`}
  </div>`;
}

function wireFindingInputs(f, users) {
  document.querySelectorAll(`[data-f-save="${f.id}"]`).forEach(btn => {
    btn.addEventListener('click', async () => {
      const getF = (field) => document.querySelector(`[data-f-field="${field}"][data-fid="${f.id}"]`)?.value;
      const resultVal = getF('is_compliant');
      const payload = {
        is_compliant: resultVal === '' ? null : (resultVal === 'true' || resultVal === 'partial'),
        partial: resultVal === 'partial',
        score_awarded: getF('score_awarded') ? parseFloat(getF('score_awarded')) : null,
        owner_id: getF('owner_id') || null,
        finding_description: getF('finding_description') || null,
        action_required: getF('action_required') || null,
        responded_by: CURRENT_USER.id,
        responded_at: new Date().toISOString()
      };
      const { error } = await sb.from('compliance_findings').update(payload).eq('id', f.id);
      if (error) { toast(error.message, 'error'); return; }
      toast('Finding saved', 'success');
    });
  });

  document.querySelectorAll(`[data-f-capa="${f.id}"]`).forEach(btn => {
    btn.addEventListener('click', async () => {
      const severity = prompt('Severity (low/medium/high/critical):', 'medium') || 'medium';
      const target = prompt('Target date (YYYY-MM-DD):', new Date(Date.now()+30*86400000).toISOString().slice(0,10));
      if (!target) return;
      const { data, error } = await sb.rpc('create_capa_from_finding', {
        p_finding_id: f.id, p_severity: severity,
        p_owner: CURRENT_USER.id, p_target_date: target
      });
      if (error) { toast(error.message, 'error'); return; }
      toast('CAPA created from finding', 'success');
      location.reload();   // simplest to re-render
    });
  });
}

// =============================================================================
// WIRE UP
// =============================================================================
$('#btnLogin').addEventListener('click', login);
['loginEmail','loginPassword'].forEach(id => $('#'+id).addEventListener('keydown', (e) => { if (e.key==='Enter') login(); }));
$('#btnLogout').addEventListener('click', logout);
const btnSecurity = $('#btnSecurity');
if (btnSecurity) btnSecurity.addEventListener('click', openSecurityPanel);

async function openSecurityPanel() {
  const { data: { user } } = await sb.auth.getUser();
  const { data: profile } = await sb.from('profiles')
    .select('mfa_required, mfa_enrolled, mfa_enrolled_at, password_changed_at')
    .eq('id', user.id).single();
  const { data: factors } = await sb.auth.mfa.listFactors();
  const hasTotp = (factors?.totp || []).length > 0;

  const { data: recentEvents } = await sb.from('auth_events')
    .select('*')
    .eq('user_id', user.id)
    .order('occurred_at', { ascending: false })
    .limit(10);

  $('#drawerBg').classList.add('show');
  $('#drawerTitle').textContent = 'Security Settings';
  $('#drawerRef').textContent = user.email;

  $('#drawerBody').innerHTML = `
    <div class="detail-section">
      <h4>Two-Factor Authentication</h4>
      <div class="detail-meta">
        <div class="m-item">
          <label>Status</label>
          <span>${hasTotp ? '<span style="color:var(--green-700)">✓ Enabled</span>' : '<span style="color:var(--orange-deep)">Not set up</span>'}</span>
        </div>
        <div class="m-item">
          <label>Required</label>
          <span>${profile?.mfa_required ? '<b>Yes (enforced)</b>' : 'Optional'}</span>
        </div>
        ${profile?.mfa_enrolled_at ? `
        <div class="m-item">
          <label>Enrolled on</label>
          <span>${fmtDate(profile.mfa_enrolled_at)}</span>
        </div>` : ''}
      </div>
      <div class="btn-row" style="margin-top:10px">
        ${!hasTotp ? '<button class="btn ok btn-sm" onclick="enableMfa()">Set Up MFA</button>' : ''}
        ${hasTotp && !profile?.mfa_required ? '<button class="btn danger btn-sm" onclick="disableMfa()">Disable MFA</button>' : ''}
      </div>
    </div>

    <div class="detail-section">
      <h4>Password</h4>
      <div class="detail-meta">
        <div class="m-item">
          <label>Last changed</label>
          <span>${fmtDate(profile?.password_changed_at) || '—'}</span>
        </div>
      </div>
      <div class="btn-row" style="margin-top:10px">
        <button class="btn secondary btn-sm" id="btnChangePw">Change password</button>
      </div>
    </div>

    <div class="detail-section">
      <h4>Recent Sign-In Activity</h4>
      ${(recentEvents || []).length ? `
      <div class="timeline">
        ${recentEvents.map(e => `
          <div class="tl-step ${e.event_type.includes('failed') ? 'failed' : 'done'}">
            <h5>${escape(e.event_type.replace(/_/g,' '))}</h5>
            <div class="meta">${fmtDateTime(e.occurred_at)}${e.user_agent ? ` · ${escape(e.user_agent.split('/')[0])}` : ''}</div>
          </div>`).join('')}
      </div>` : '<p style="color:var(--muted);font-size:12px">No recent activity</p>'}
    </div>
  `;

  const btnCpw = document.getElementById('btnChangePw');
  if (btnCpw) btnCpw.addEventListener('click', async () => {
    const newPw = prompt('Enter new password (min 12 chars):');
    if (!newPw) return;
    if (newPw.length < 12) { alert('Password must be at least 12 characters.'); return; }
    const { error } = await sb.auth.updateUser({ password: newPw });
    if (error) { alert('Error: ' + error.message); return; }
    await sb.from('profiles').update({ password_changed_at: new Date().toISOString() }).eq('id', user.id);
    alert('Password updated.');
    await logAuthEvent('password_changed');
  });
}
$('#drawerClose').addEventListener('click', closeDrawer);
$('#drawerBg').addEventListener('click', (e) => { if (e.target.id === 'drawerBg') closeDrawer(); });
$$('.nav-item').forEach(n => n.addEventListener('click', () => route(n.dataset.view)));
$('#dateStamp').textContent = new Date().toLocaleDateString('en-GB',{day:'2-digit',month:'short',year:'numeric'}).toUpperCase();

// Poll badges every 60s
// Poll badges every 60s — but only when tab is visible (saves network & DB calls)
setInterval(() => {
  if (CURRENT_USER && !document.hidden) refreshBadges();
}, 60000);

// Refresh immediately when user returns to the tab
document.addEventListener('visibilitychange', () => {
  if (!document.hidden && CURRENT_USER) {
    refreshBadges();
    updatePresence();
  }
});

// =============================================================================
// PRESENCE TRACKING — silently update last_seen_at every 2 minutes
// =============================================================================
async function updatePresence() {
  if (!CURRENT_USER) return;
  try {
    await sb.from('profiles')
      .update({ last_seen_at: new Date().toISOString() })
      .eq('id', CURRENT_USER.id);
  } catch(e) { /* fail silently — presence is non-critical */ }
}

// Update presence on load + every 2 minutes while active
function startPresenceTracking() {
  updatePresence();
  setInterval(() => {
    if (CURRENT_USER && !document.hidden) updatePresence();
  }, 2 * 60 * 1000);

  // Also ping on any user interaction (mouse move, key press) — debounced
  let presenceDebounce;
  const presencePing = () => {
    clearTimeout(presenceDebounce);
    presenceDebounce = setTimeout(updatePresence, 30000); // max once per 30s
  };
  document.addEventListener('mousemove', presencePing, { passive: true });
  document.addEventListener('keydown', presencePing, { passive: true });
}

// Online indicator helper
function onlineDot(lastSeen, size = 10) {
  if (!lastSeen) return `<span style="display:inline-block;width:${size}px;height:${size}px;border-radius:50%;background:#64748b;flex-shrink:0" title="Never seen"></span>`;
  const minsAgo = Math.floor((Date.now() - new Date(lastSeen)) / 60000);
  const isOnline = minsAgo < 5;
  const isRecent = minsAgo < 30;
  const color = isOnline ? '#22c55e' : isRecent ? '#f59e0b' : '#64748b';
  const label = isOnline ? 'Online now' : minsAgo < 60 ? `${minsAgo}m ago` : minsAgo < 1440 ? `${Math.floor(minsAgo/60)}h ago` : `${Math.floor(minsAgo/1440)}d ago`;
  return `<span style="display:inline-block;width:${size}px;height:${size}px;border-radius:50%;background:${color};flex-shrink:0;${isOnline?'box-shadow:0 0 0 2px rgba(34,197,94,0.3)':''}" title="${label}"></span>`;
}

// Team presence widget (shown on dashboard for IT Manager/Admin)
async function renderTeamPresenceWidget() {
  const { data: team } = await sb.rpc('get_team_presence');
  if (!team || !team.length) return '';

  const online = team.filter(u => u.is_online);
  const offline = team.filter(u => !u.is_online);

  return `
    <div class="panel">
      <div class="panel-head">
        <h3>Team Status</h3>
        <div class="right">
          <span style="font-size:11px;color:#22c55e;font-weight:600">${online.length} online</span>
          <span style="font-size:11px;color:var(--muted);margin-left:6px">${offline.length} offline</span>
        </div>
      </div>
      <div class="panel-body" style="padding:10px 16px">
        ${team.map(u => `
          <div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px dashed var(--line)">
            ${onlineDot(u.last_seen_at, 9)}
            <div style="flex:1;min-width:0">
              <div style="font-size:13px;font-weight:500;color:var(--ink)">${escape(u.full_name)}</div>
              <div style="font-size:11px;color:var(--muted)">${escape(u.designation||u.role_code||'—')}</div>
            </div>
            <div style="font-size:11px;color:var(--muted);font-family:monospace;text-align:right">
              ${u.is_online
                ? '<span style="color:#22c55e;font-weight:600">Online</span>'
                : u.last_seen_at
                  ? escape((() => { const m = Math.floor((Date.now() - new Date(u.last_seen_at)) / 60000); return m < 60 ? m+'m ago' : m < 1440 ? Math.floor(m/60)+'h ago' : Math.floor(m/1440)+'d ago'; })())
                  : 'Never'
              }
            </div>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

// Update sidebar user card with online dot
function updateSidebarPresence() {
  const who = document.querySelector('.user-card .who');
  if (!who || !CURRENT_USER) return;
  // Add green online dot to user card
  const existing = document.getElementById('sidebarOnlineDot');
  if (!existing) {
    const dot = document.createElement('span');
    dot.id = 'sidebarOnlineDot';
    dot.style.cssText = 'display:inline-block;width:8px;height:8px;border-radius:50%;background:#22c55e;box-shadow:0 0 0 2px rgba(34,197,94,0.3);margin-left:4px;vertical-align:middle';
    dot.title = 'You are online';
    const nameSpan = who.querySelector('span');
    if (nameSpan) nameSpan.appendChild(dot);
  }
}

// =============================================================================
// LIVE IT SECURITY NEWS TICKER (Reddit-based, public JSON API, no auth)
// =============================================================================
const NEWS_SOURCES = [
  { sub: 'cybersecurity', label: 'r/cybersec' },
  { sub: 'netsec',        label: 'r/netsec' },
  { sub: 'sysadmin',      label: 'r/sysadmin' }
];

const NEWS_CRITICAL_KEYWORDS = [
  'cve-', 'zero-day', '0-day', 'zero day', 'critical',
  'ransomware', 'exploit', 'breach', 'rce', 'actively exploited',
  'unpatched', 'malware', 'backdoor', 'emergency', 'urgent',
  'fortinet', 'microsoft', 'windows', 'vmware', 'cisco', 'fortigate',
  'citrix', 'sonicwall', 'exchange', 'azure', 'veeam'
];

function isCriticalHeadline(title) {
  const t = (title || '').toLowerCase();
  return NEWS_CRITICAL_KEYWORDS.some(k => t.includes(k));
}

async function fetchNewsFromReddit() {
  const allItems = [];
  for (const source of NEWS_SOURCES) {
    try {
      const res = await fetch(`https://www.reddit.com/r/${source.sub}/hot.json?limit=15&raw_json=1`, {
        headers: { 'Accept': 'application/json' }
      });
      if (!res.ok) continue;
      const data = await res.json();
      const posts = data?.data?.children || [];
      posts.forEach(p => {
        const d = p.data;
        if (d.stickied || d.over_18) return;
        if (d.score < 10) return;   // quality filter: skip low-engagement posts
        allItems.push({
          title: d.title,
          url: `https://reddit.com${d.permalink}`,
          source: source.label,
          score: d.score,
          comments: d.num_comments,
          critical: isCriticalHeadline(d.title)
        });
      });
    } catch (e) {
      console.warn(`Failed to fetch ${source.sub}`, e);
    }
  }

  // Sort: critical first, then by score
  allItems.sort((a, b) => {
    if (a.critical !== b.critical) return a.critical ? -1 : 1;
    return b.score - a.score;
  });

  return allItems.slice(0, 25);
}

function escapeHTML(s) {
  return String(s || '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function truncate(s, n) {
  return s.length > n ? s.slice(0, n - 1).trimEnd() + '…' : s;
}

async function refreshNewsTicker() {
  const container = document.getElementById('newsTickerContent');
  if (!container) return;

  try {
    const items = await fetchNewsFromReddit();
    if (!items.length) {
      container.innerHTML = '<span style="color:#888;font-size:11.5px">No news available right now.</span>';
      return;
    }

    // Render items twice for seamless loop
    const renderItem = (it) => `
      <a href="${escapeHTML(it.url)}" target="_blank" rel="noopener"
         class="news-item ${it.critical ? 'critical' : ''}">
        <span class="news-item-source">${escapeHTML(it.source)}</span>
        ${escapeHTML(truncate(it.title, 120))}
      </a>
    `;
    const html = items.map(renderItem).join('') + items.map(renderItem).join('');
    container.innerHTML = html;

    // Adjust animation duration based on content length (slower for more items)
    const duration = Math.max(60, items.length * 6);
    container.style.animationDuration = `${duration}s`;
  } catch (e) {
    console.error('News ticker refresh failed', e);
    container.innerHTML = '<span style="color:#888;font-size:11.5px">Could not load news.</span>';
  }
}

function showNewsTicker() {
  const ticker = document.getElementById('newsTicker');
  if (ticker) ticker.style.display = 'flex';
  try { localStorage.setItem('ffc-news-hidden', '0'); } catch(e) {}
}
function hideNewsTicker() {
  const ticker = document.getElementById('newsTicker');
  if (ticker) ticker.style.display = 'none';
  try { localStorage.setItem('ffc-news-hidden', '1'); } catch(e) {}
}

function initNewsTicker() {
  // Respect user preference
  let hidden = false;
  try { hidden = localStorage.getItem('ffc-news-hidden') === '1'; } catch(e) {}

  if (!hidden) showNewsTicker();

  // Wire close button
  const closeBtn = document.getElementById('newsTickerClose');
  if (closeBtn) closeBtn.addEventListener('click', hideNewsTicker);

  // Wire toggle button
  const toggleBtn = document.getElementById('newsToggle');
  if (toggleBtn) toggleBtn.addEventListener('click', () => {
    const ticker = document.getElementById('newsTicker');
    if (!ticker) return;
    if (ticker.style.display === 'none') {
      showNewsTicker();
      refreshNewsTicker();
    } else {
      hideNewsTicker();
    }
  });

  // Initial fetch + periodic refresh every 5 minutes (only when tab visible)
  refreshNewsTicker();
  setInterval(() => {
    if (!document.hidden) refreshNewsTicker();
  }, 5 * 60 * 1000);
}

// Start ticker once app is visible (after bootstrap succeeds)
// FIX: Single consolidated auth state listener (was two separate listeners)
sb.auth.onAuthStateChange((event, session) => {
  console.log('[FFC] Auth event:', event);

  if (event === 'SIGNED_OUT') {
    CURRENT_USER = null;
    USER_ROLES = [];
    USER_PERMS = [];
    $('#app').classList.remove('show');
    $('#loginScreen').style.display = 'grid';
    hideBootSplash();
  }

  if (event === 'SIGNED_IN' || event === 'INITIAL_SESSION') {
    // Init secondary features once logged in (non-blocking)
    setTimeout(() => {
      if (CURRENT_USER) {
        initNewsTicker();
        startPresenceTracking();
        updateSidebarPresence();
      }
    }, 1000);
  }
});

// Hide the boot splash — safe to call multiple times
function hideBootSplash() {
  const splash = $('#bootSplash');
  if (splash) splash.style.display = 'none';
}

// Fallback: if something truly hangs, force-hide splash after 30 seconds
// Increased from 8s because MFA challenge + cold-start Supabase can take 10-15s
let bootstrapComplete = false;
const bootTimeout = setTimeout(() => {
  if (bootstrapComplete) return;  // bootstrap already finished, don't interfere
  console.warn('[FFC] Boot timeout reached — forcing login screen');
  hideBootSplash();
  if (!CURRENT_USER) {
    $('#loginScreen').style.display = 'grid';
    $('#app').classList.remove('show');
  }
}, 30000);  // 30 seconds — generous enough for MFA + cold start

// On page load / refresh — check session and route accordingly
(async () => {
  const setStatus = (t) => { if (window.__bootStatus) window.__bootStatus(t); };
  console.log('[FFC] Boot started');
  setStatus('Initializing…');
  try {
    setStatus('Checking session…');
    console.log('[FFC] Checking session…');
    const { data: { session }, error } = await sb.auth.getSession();
    console.log('[FFC] Session result:', { hasSession: !!session, error });

    if (error) {
      console.error('[FFC] Session check failed', error);
      setStatus('Session error: ' + error.message);
      $('#loginScreen').style.display = 'grid';
      hideBootSplash();
      clearTimeout(bootTimeout);
      return;
    }

    if (session) {
      setStatus('Loading your profile…');
      console.log('[FFC] Valid session found, bootstrapping…');
      try {
        await bootstrap();
        bootstrapComplete = true;
        console.log('[FFC] Bootstrap complete');
      } catch(e) {
        console.error('[FFC] Bootstrap threw:', e);
        setStatus('Bootstrap error: ' + (e?.message || e));
        $('#loginScreen').style.display = 'grid';
        $('#app').classList.remove('show');
      }
      hideBootSplash();
    } else {
      console.log('[FFC] No session, showing login');
      setStatus('No session, redirecting…');
      bootstrapComplete = true;
      $('#loginScreen').style.display = 'grid';
      hideBootSplash();
    }
  } catch(e) {
    console.error('[FFC] Top-level boot failure:', e);
    setStatus('Boot failed: ' + (e?.message || e));
    bootstrapComplete = true;
    $('#loginScreen').style.display = 'grid';
    hideBootSplash();
  } finally {
    bootstrapComplete = true;
    clearTimeout(bootTimeout);
  }
})();

// =============================================================================
// BULK CSV UPLOAD — Licenses, Assets, Vendors, Vendor Contracts
// =============================================================================

// CSV template definitions — what columns each module expects
const CSV_TEMPLATES = {

  license: {
    label: 'License Tracker',
    filename: 'FFC_License_Template.csv',
    columns: [
      'item_code','item_name','item_type','vendor',
      'contract_number','po_number','quantity','unit_cost','total_cost','currency',
      'start_date','expiry_date','last_renewed_on','next_review_date',
      'payment_frequency','criticality','status','auto_renew',
      'notes'
    ],
    required: ['item_code','item_name','item_type','vendor','start_date','expiry_date'],
    enums: {
      item_type: ['software_license','saas_subscription','domain','ssl_certificate','cloud_service','support_contract','maintenance_contract','antivirus','backup_subscription','hosting','other'],
      payment_frequency: ['one_time','monthly','quarterly','semi_annual','annual','biennial','triennial'],
      criticality: ['low','medium','high','critical'],
      status: ['active','expiring_soon','renewal_in_progress','renewed','expired','cancelled','archived'],
      auto_renew: ['true','false']
    },
    sample: [
      'LIC-2026-001,Microsoft 365 Business,saas_subscription,Microsoft,EA-123456,PO-2026-001,300,45,13500,AED,2026-01-01,2026-12-31,2025-12-15,2026-11-01,annual,critical,active,false,Enterprise Agreement',
      'LIC-2026-002,Fortinet FortiGuard,support_contract,Fortinet,FG-SUP-789,,1,8500,8500,AED,2026-03-01,2027-02-28,,,annual,high,active,true,UTM protection bundle'
    ]
  },

  asset: {
    label: 'Asset Registry',
    filename: 'FFC_Asset_Template.csv',
    columns: [
      'asset_tag','serial_number','asset_type','brand','model',
      'specifications','purchase_date','purchase_cost','currency',
      'warranty_expiry','current_owner_email','current_location',
      'current_condition','is_retired','notes'
    ],
    required: ['asset_tag','asset_type'],
    enums: {
      asset_type: ['laptop','desktop','monitor','phone','tablet','printer','scanner','network_device','server','ups','docking_station','headset','keyboard_mouse','accessory','sim_card','other'],
      current_condition: ['new','good','fair','damaged','lost','retired'],
      is_retired: ['true','false']
    },
    sample: [
      'FFC-LPT-001,SN123456789,laptop,Dell,Latitude 5540,Intel i7 16GB 512GB SSD,2024-03-15,4500,AED,2027-03-15,satham@freshfruitscompany.com,Head Office,good,false,Primary work laptop',
      'FFC-SRV-001,SRV987654321,server,HP,ProLiant DL380 G10,Xeon 64GB 2x1TB RAID,2023-01-10,25000,AED,2026-01-10,,Server Room,good,false,Primary Hyper-V host'
    ]
  },

  vendor: {
    label: 'Vendors',
    filename: 'FFC_Vendor_Template.csv',
    columns: [
      'code','name','category','service_type','website','address','country',
      'account_manager_name','account_manager_email','account_manager_phone',
      'support_email','support_phone','support_portal_url','is_active','notes'
    ],
    required: ['code','name'],
    enums: {
      is_active: ['true','false']
    },
    sample: [
      'VND-001,Technowave International,network,support,https://technowave.ae,Dubai Internet City,UAE,Ahmed Al-Rashid,ahmed@technowave.ae,+971501234567,support@technowave.ae,+97143456789,https://portal.technowave.ae,true,ESL/Zkong vendor',
      'VND-002,Bespin Global,cloud,consulting,https://bespinglobal.com,DIFC Dubai,UAE,Omar El Hallab,omar@bespinglobal.com,+971551234567,support@bespinglobal.com,+97143456780,,true,Microsoft licensing partner'
    ]
  },

  vendor_contract: {
    label: 'Vendor Contracts (AMC)',
    filename: 'FFC_VendorContract_Template.csv',
    columns: [
      'vendor_code','contract_code','contract_title','contract_number',
      'service_covered','start_date','end_date','renewal_reminder_days',
      'sla_response_time','sla_resolution_time','support_hours',
      'cost','currency','payment_frequency','po_number','covered_systems','notes'
    ],
    required: ['vendor_code','contract_code','contract_title','start_date','end_date'],
    enums: {
      support_hours: ['24x7','business_hours','nbd','mon_to_fri_9_5','mon_to_sat_9_6','custom'],
      payment_frequency: ['one_time','monthly','quarterly','semi_annual','annual','biennial','triennial']
    },
    sample: [
      'VND-001,AMC-2026-001,Technowave Network Support AMC,TW-AMC-2026-089,Network switches and APs maintenance,2026-01-01,2026-12-31,45,4 hours,1 business day,business_hours,18000,AED,annual,PO-AMC-001,Aruba switches|Aruba APs,Annual maintenance contract',
      'VND-002,AMC-2026-002,Microsoft 365 Support,MSFT-EA-2026,M365 enterprise support,2026-01-01,2026-12-31,60,2 hours,4 hours,24x7,5000,AED,annual,PO-AMC-002,Microsoft 365|Azure AD,Premier support'
    ]
  }
};

// Download a CSV template file
function downloadCSVTemplate(type) {
  const tpl = CSV_TEMPLATES[type];
  if (!tpl) return;

  const header = tpl.columns.join(',');
  const rows = tpl.sample.join('\n');
  const content = `${header}\n${rows}`;

  const blob = new Blob([content], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = tpl.filename;
  a.click();
  URL.revokeObjectURL(url);
}

// Parse CSV text → array of objects
function parseCSV(text) {
  const lines = text.trim().split('\n').filter(l => l.trim());
  if (lines.length < 2) return { headers: [], rows: [], error: 'CSV has no data rows' };

  const headers = lines[0].split(',').map(h => h.trim().replace(/^"|"$/g, '').toLowerCase());
  const rows = [];

  for (let i = 1; i < lines.length; i++) {
    // Handle quoted fields with commas inside
    const values = [];
    let current = '';
    let inQuotes = false;
    for (const char of lines[i]) {
      if (char === '"') { inQuotes = !inQuotes; }
      else if (char === ',' && !inQuotes) { values.push(current.trim()); current = ''; }
      else { current += char; }
    }
    values.push(current.trim());

    const row = {};
    headers.forEach((h, idx) => {
      row[h] = (values[idx] || '').replace(/^"|"$/g, '').trim();
    });
    rows.push(row);
  }

  return { headers, rows, error: null };
}

// Validate a parsed row against template rules
function validateCSVRow(row, tpl, rowNum) {
  const errors = [];

  // Check required fields
  tpl.required.forEach(col => {
    if (!row[col]) errors.push(`Row ${rowNum}: "${col}" is required`);
  });

  // Check enum values
  Object.entries(tpl.enums || {}).forEach(([col, allowed]) => {
    const val = row[col]?.toLowerCase();
    if (val && !allowed.includes(val)) {
      errors.push(`Row ${rowNum}: "${col}" must be one of: ${allowed.join(', ')}`);
    }
  });

  // Check date format
  ['start_date','expiry_date','end_date','purchase_date','warranty_expiry',
   'last_renewed_on','next_review_date'].forEach(col => {
    const val = row[col];
    if (val && !/^\d{4}-\d{2}-\d{2}$/.test(val)) {
      errors.push(`Row ${rowNum}: "${col}" must be YYYY-MM-DD format (got: ${val})`);
    }
  });

  return errors;
}

// Open the bulk upload modal
async function openBulkUpload(type) {
  const tpl = CSV_TEMPLATES[type];
  if (!tpl) return;

  const existing = document.getElementById('bulkUploadModal');
  if (existing) existing.remove();

  const modal = document.createElement('div');
  modal.id = 'bulkUploadModal';
  modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:10000;display:flex;align-items:center;justify-content:center;padding:20px';

  modal.innerHTML = `
    <div style="background:white;border-radius:12px;padding:32px;max-width:680px;width:100%;max-height:90vh;overflow-y:auto;font-family:Inter,sans-serif">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px">
        <div>
          <h2 style="font-size:20px;font-weight:600;margin:0;color:#1a2e0f">Bulk Upload — ${tpl.label}</h2>
          <p style="font-size:12.5px;color:#7a8775;margin:4px 0 0">Upload a CSV file to import multiple records at once</p>
        </div>
        <button id="bulkClose" style="background:none;border:none;font-size:24px;cursor:pointer;color:#7a8775;line-height:1">×</button>
      </div>

      <!-- Step 1: Download template -->
      <div style="background:#f8faf3;border:1px solid #e3ebd8;border-radius:8px;padding:16px;margin-bottom:16px">
        <div style="font-size:13px;font-weight:600;color:#3D7A18;margin-bottom:6px">Step 1 — Download the template</div>
        <p style="font-size:12px;color:#5a6b51;margin-bottom:10px">Fill in the CSV file with your data. Don't change the column headers.</p>
        <button id="btnDownloadTpl" class="btn secondary btn-sm">⬇ Download CSV Template</button>
      </div>

      <!-- Column reference -->
      <details style="margin-bottom:16px">
        <summary style="font-size:12px;color:#5BA829;cursor:pointer;font-weight:600;padding:8px 0">📋 Column reference & allowed values</summary>
        <div style="background:#f8faf3;border-radius:6px;padding:12px;margin-top:8px;font-size:11px;font-family:monospace;line-height:1.8">
          <div style="color:#3D7A18;font-weight:700;margin-bottom:6px">REQUIRED: ${tpl.required.join(', ')}</div>
          <div style="color:#5a6b51;margin-bottom:8px">ALL COLUMNS: ${tpl.columns.join(', ')}</div>
          ${Object.entries(tpl.enums||{}).map(([col, vals]) =>
            `<div><b style="color:#3D7A18">${col}:</b> ${vals.join(' | ')}</div>`
          ).join('')}
          <div style="color:#7a8775;margin-top:8px">Dates must be YYYY-MM-DD format (e.g. 2026-04-19)</div>
          ${type === 'vendor_contract' ? '<div style="color:#7a8775">covered_systems: separate multiple with pipe | (e.g. SAP|NetSuite|FortiGate)</div>' : ''}
        </div>
      </details>

      <!-- Step 2: Upload file -->
      <div style="background:#f8faf3;border:1px solid #e3ebd8;border-radius:8px;padding:16px;margin-bottom:16px">
        <div style="font-size:13px;font-weight:600;color:#3D7A18;margin-bottom:6px">Step 2 — Upload your filled CSV</div>
        <input type="file" id="bulkFileInput" accept=".csv" style="font-size:12.5px;width:100%" />
      </div>

      <!-- Preview area -->
      <div id="bulkPreview" style="display:none;margin-bottom:16px">
        <div style="font-size:13px;font-weight:600;color:#3D7A18;margin-bottom:8px">Step 3 — Review before importing</div>
        <div id="bulkPreviewContent"></div>
      </div>

      <!-- Error area -->
      <div id="bulkErrors" style="display:none;background:#fff5f5;border:1px solid #fca5a5;border-radius:8px;padding:12px;margin-bottom:16px;font-size:12px;color:#7f1d1d;line-height:1.8"></div>

      <!-- Action buttons -->
      <div style="display:flex;gap:10px;justify-content:flex-end">
        <button id="bulkCancelBtn" class="btn secondary">Cancel</button>
        <button id="bulkImportBtn" class="btn ok" style="display:none">⬆ Import Records</button>
      </div>
    </div>
  `;

  document.body.appendChild(modal);

  // Wire buttons
  document.getElementById('bulkClose').addEventListener('click', () => modal.remove());
  document.getElementById('bulkCancelBtn').addEventListener('click', () => modal.remove());
  document.getElementById('btnDownloadTpl').addEventListener('click', () => downloadCSVTemplate(type));

  // File input handler
  document.getElementById('bulkFileInput').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const text = await file.text();
    const { headers, rows, error } = parseCSV(text);

    if (error) {
      showBulkErrors([error]);
      return;
    }

    // Validate all rows
    const allErrors = [];
    rows.forEach((row, idx) => {
      const errs = validateCSVRow(row, tpl, idx + 2);
      allErrors.push(...errs);
    });

    if (allErrors.length > 0) {
      showBulkErrors(allErrors);
      document.getElementById('bulkImportBtn').style.display = 'none';
      return;
    }

    // Show preview
    document.getElementById('bulkErrors').style.display = 'none';
    showBulkPreview(rows, tpl);

    // Store rows for import
    modal._csvRows = rows;
    modal._csvType = type;
    document.getElementById('bulkImportBtn').style.display = '';
  });

  // Import button
  document.getElementById('bulkImportBtn').addEventListener('click', async () => {
    const rows = modal._csvRows;
    const csvType = modal._csvType;
    if (!rows || !csvType) return;

    const btn = document.getElementById('bulkImportBtn');
    btn.disabled = true;
    btn.innerHTML = '<span class="spin"></span> Importing…';

    try {
      const result = await importCSVRows(csvType, rows);
      modal.remove();
      toast(`✓ Imported ${result.inserted} records${result.skipped > 0 ? `, ${result.skipped} skipped (duplicates)` : ''}`, 'success', 5000);
      // Refresh current view
      route(CURRENT_VIEW);
    } catch(e) {
      btn.disabled = false;
      btn.innerHTML = '⬆ Import Records';
      showBulkErrors([e.message || 'Import failed']);
    }
  });
}

function showBulkErrors(errors) {
  const el = document.getElementById('bulkErrors');
  el.style.display = 'block';
  el.innerHTML = `<b>⚠ Please fix these errors before importing:</b><br>${errors.slice(0, 20).map(e => `• ${e}`).join('<br>')}${errors.length > 20 ? `<br>…and ${errors.length - 20} more` : ''}`;
  document.getElementById('bulkPreview').style.display = 'none';
}

function showBulkPreview(rows, tpl) {
  const previewEl = document.getElementById('bulkPreview');
  const contentEl = document.getElementById('bulkPreviewContent');
  previewEl.style.display = 'block';

  const previewCols = tpl.required.slice(0, 5);
  contentEl.innerHTML = `
    <div style="font-size:12px;color:#5a6b51;margin-bottom:8px">
      <b style="color:#3D7A18">${rows.length} records ready to import.</b>
      Showing first 5 rows, ${previewCols.length} key columns:
    </div>
    <div style="overflow-x:auto">
      <table style="width:100%;border-collapse:collapse;font-size:11.5px">
        <thead>
          <tr style="background:#f0f7e8">
            <th style="padding:6px 8px;text-align:left;border-bottom:1px solid #e3ebd8">#</th>
            ${previewCols.map(c => `<th style="padding:6px 8px;text-align:left;border-bottom:1px solid #e3ebd8">${c}</th>`).join('')}
          </tr>
        </thead>
        <tbody>
          ${rows.slice(0, 5).map((row, idx) => `
            <tr style="${idx % 2 === 0 ? 'background:#fafcf7' : ''}">
              <td style="padding:5px 8px;color:#7a8775">${idx + 1}</td>
              ${previewCols.map(c => `<td style="padding:5px 8px">${escape(row[c] || '—')}</td>`).join('')}
            </tr>
          `).join('')}
          ${rows.length > 5 ? `
            <tr><td colspan="${previewCols.length + 1}" style="padding:6px 8px;color:#7a8775;font-style:italic;text-align:center">
              …and ${rows.length - 5} more rows
            </td></tr>` : ''}
        </tbody>
      </table>
    </div>
  `;
}

// The actual import logic — sends rows to Supabase
async function importCSVRows(type, rows) {
  let inserted = 0, skipped = 0;

  if (type === 'license') {
    const records = rows.map(r => ({
      item_code: r.item_code,
      item_name: r.item_name,
      item_type: r.item_type,
      vendor: r.vendor,
      contract_number: r.contract_number || null,
      po_number: r.po_number || null,
      quantity: r.quantity ? parseInt(r.quantity) : 1,
      unit_cost: r.unit_cost ? parseFloat(r.unit_cost) : null,
      total_cost: r.total_cost ? parseFloat(r.total_cost) : null,
      currency: r.currency || 'AED',
      start_date: r.start_date,
      expiry_date: r.expiry_date,
      last_renewed_on: r.last_renewed_on || null,
      next_review_date: r.next_review_date || null,
      payment_frequency: r.payment_frequency || 'annual',
      criticality: r.criticality || 'medium',
      status: r.status || 'active',
      auto_renew: r.auto_renew === 'true',
      notes: r.notes || null
    }));

    const { data, error } = await sb.from('license_items')
      .upsert(records, { onConflict: 'item_code', ignoreDuplicates: false })
      .select();
    if (error) throw error;
    inserted = data?.length || records.length;
  }

  else if (type === 'asset') {
    // Resolve owner emails to user IDs
    const emails = [...new Set(rows.map(r => r.current_owner_email).filter(Boolean))];
    let emailMap = {};
    if (emails.length > 0) {
      const { data: users } = await sb.from('profiles')
        .select('id, email').in('email', emails);
      (users || []).forEach(u => { emailMap[u.email] = u.id; });
    }

    const records = rows.map(r => ({
      asset_tag: r.asset_tag,
      serial_number: r.serial_number || null,
      asset_type: r.asset_type,
      brand: r.brand || null,
      model: r.model || null,
      specifications: r.specifications || null,
      purchase_date: r.purchase_date || null,
      purchase_cost: r.purchase_cost ? parseFloat(r.purchase_cost) : null,
      currency: r.currency || 'AED',
      warranty_expiry: r.warranty_expiry || null,
      current_owner_id: r.current_owner_email ? (emailMap[r.current_owner_email] || null) : null,
      current_location: r.current_location || null,
      current_condition: r.current_condition || 'good',
      is_retired: r.is_retired === 'true'
    }));

    const { data, error } = await sb.from('assets')
      .upsert(records, { onConflict: 'asset_tag', ignoreDuplicates: false })
      .select();
    if (error) throw error;
    inserted = data?.length || records.length;
  }

  else if (type === 'vendor') {
    const records = rows.map(r => ({
      code: r.code,
      name: r.name,
      category: r.category || null,
      service_type: r.service_type || null,
      website: r.website || null,
      address: r.address || null,
      country: r.country || 'UAE',
      account_manager_name: r.account_manager_name || null,
      account_manager_email: r.account_manager_email || null,
      account_manager_phone: r.account_manager_phone || null,
      support_email: r.support_email || null,
      support_phone: r.support_phone || null,
      support_portal_url: r.support_portal_url || null,
      is_active: r.is_active !== 'false'
    }));

    const { data, error } = await sb.from('vendors')
      .upsert(records, { onConflict: 'code', ignoreDuplicates: false })
      .select();
    if (error) throw error;
    inserted = data?.length || records.length;
  }

  else if (type === 'vendor_contract') {
    // Resolve vendor codes to IDs
    const codes = [...new Set(rows.map(r => r.vendor_code).filter(Boolean))];
    let vendorMap = {};
    if (codes.length > 0) {
      const { data: vends } = await sb.from('vendors')
        .select('id, code').in('code', codes);
      (vends || []).forEach(v => { vendorMap[v.code] = v.id; });
    }

    const records = rows.map(r => {
      const vendorId = vendorMap[r.vendor_code];
      if (!vendorId) throw new Error(`Vendor code "${r.vendor_code}" not found. Import vendors first.`);
      return {
        vendor_id: vendorId,
        contract_code: r.contract_code,
        contract_title: r.contract_title,
        contract_number: r.contract_number || null,
        service_covered: r.service_covered || null,
        start_date: r.start_date,
        end_date: r.end_date,
        renewal_reminder_days: r.renewal_reminder_days ? parseInt(r.renewal_reminder_days) : 45,
        sla_response_time: r.sla_response_time || null,
        sla_resolution_time: r.sla_resolution_time || null,
        support_hours: r.support_hours || 'business_hours',
        cost: r.cost ? parseFloat(r.cost) : null,
        currency: r.currency || 'AED',
        payment_frequency: r.payment_frequency || 'annual',
        po_number: r.po_number || null,
        covered_systems: r.covered_systems ? r.covered_systems.split('|').map(s => s.trim()).filter(Boolean) : null
      };
    });

    const { data, error } = await sb.from('vendor_contracts')
      .upsert(records, { onConflict: 'contract_code', ignoreDuplicates: false })
      .select();
    if (error) throw error;
    inserted = data?.length || records.length;
  }

  return { inserted, skipped };
}

// =============================================================================
// IT PROJECT TRACKER
// =============================================================================

const PROJECT_CATEGORIES = [
  ['infrastructure','Infrastructure'],['security','Security'],['erp','ERP'],
  ['operations','Operations'],['compliance','Compliance'],['networking','Networking'],['other','Other']
];
const PROJECT_STATUSES = [
  ['planning','Planning'],['in_progress','In Progress'],['on_hold','On Hold'],
  ['completed','Completed'],['cancelled','Cancelled']
];
const PROJECT_PRIORITIES = [['low','Low'],['medium','Medium'],['high','High'],['critical','Critical']];
const MS_STATUSES = [
  ['pending','Pending'],['in_progress','In Progress'],['completed','Completed'],
  ['overdue','Overdue'],['cancelled','Cancelled']
];

const ragColor = { green:'#22c55e', amber:'#f59e0b', red:'#ef4444' };
const ragBg    = { green:'#f0fdf4', amber:'#fffbeb', red:'#fef2f2' };
const ragLabel = { green:'On Track', amber:'At Risk', red:'Off Track' };

const statusColor = {
  planning:'#6366f1', in_progress:'#3b82f6', on_hold:'#f59e0b',
  completed:'#22c55e', cancelled:'#9ca3af'
};

async function renderITProjects() {
  const canWrite = isAdmin() || hasRole('it_manager') || hasRole('sysadmin') || hasRole('network_admin') || hasRole('erp_admin');

  const [metricsRes, projectsRes] = await Promise.allSettled([
    sb.rpc('project_metrics'),
    sb.from('it_projects')
      .select('*, owner:profiles!it_projects_owner_id_fkey(full_name,email), milestones:project_milestones(id,status,planned_end)')
      .order('planned_end', { ascending: true, nullsFirst: false })
  ]);

  const m = metricsRes.value?.data || {};
  const projects = projectsRes.value?.data || [];

  $('#viewContent').innerHTML = `
    <!-- Stats -->
    <div class="stats-grid">
      <div class="stat accent">
        <div class="label">Active Projects</div>
        <div class="value">${(m.planning||0) + (m.in_progress||0)}</div>
        <div class="sub">${m.in_progress||0} in progress · ${m.planning||0} planning</div>
      </div>
      <div class="stat ${(m.red_projects||0) > 0 ? 'danger' : (m.amber_projects||0) > 0 ? 'warn' : ''}">
        <div class="label">Health</div>
        <div class="value">${m.red_projects||0} <span style="font-size:14px">🔴</span> ${m.amber_projects||0} <span style="font-size:14px">🟡</span></div>
        <div class="sub">Red · Amber projects</div>
      </div>
      <div class="stat ${(m.overdue_milestones||0) > 0 ? 'danger' : ''}">
        <div class="label">Overdue Milestones</div>
        <div class="value">${m.overdue_milestones||0}</div>
        <div class="sub">need attention</div>
      </div>
      <div class="stat">
        <div class="label">My Projects</div>
        <div class="value">${m.my_projects||0}</div>
        <div class="sub">assigned to me</div>
      </div>
      <div class="stat">
        <div class="label">Completed</div>
        <div class="value">${m.completed_this_year||0}</div>
        <div class="sub">this year</div>
      </div>
    </div>

    <!-- Toolbar -->
    <div class="filter-bar">
      <select id="prjfStatus"><option value="">All statuses</option>
        ${PROJECT_STATUSES.map(([v,l]) => `<option value="${v}">${l}</option>`).join('')}
      </select>
      <select id="prjfCat"><option value="">All categories</option>
        ${PROJECT_CATEGORIES.map(([v,l]) => `<option value="${v}">${l}</option>`).join('')}
      </select>
      <input id="prjfSearch" placeholder="Search projects…" />
      <span class="count" id="prjCount">${projects.length} projects</span>
      ${canWrite ? `<button class="btn ok btn-sm" id="btnNewProject" style="margin-left:8px">+ New Project</button>` : ''}
    </div>

    <!-- Two views: List + Gantt -->
    <div style="display:flex;gap:8px;margin-bottom:12px">
      <button class="btn secondary btn-sm active-tab" id="tabList" style="border-bottom:2px solid var(--green-700)">☰ List</button>
      <button class="btn secondary btn-sm" id="tabGantt">▦ Gantt</button>
    </div>

    <!-- List view -->
    <div id="prjListView">
      <div id="prjList">
        ${renderProjectList(projects)}
      </div>
    </div>

    <!-- Gantt view (hidden by default) -->
    <div id="prjGanttView" style="display:none">
      <div id="prjGantt"></div>
    </div>
  `;

  // Filter logic
  const apply = () => {
    const st = $('#prjfStatus').value;
    const cat = $('#prjfCat').value;
    const q = $('#prjfSearch').value.toLowerCase();
    const filtered = projects.filter(p =>
      (!st || p.status === st) &&
      (!cat || p.category === cat) &&
      (!q || p.name.toLowerCase().includes(q) || (p.description||'').toLowerCase().includes(q))
    );
    $('#prjCount').textContent = `${filtered.length} projects`;
    $('#prjList').innerHTML = renderProjectList(filtered);
    wireProjectRows();
  };
  ['prjfStatus','prjfCat','prjfSearch'].forEach(id => $('#'+id).addEventListener('input', apply));

  // Tab switching
  $('#tabList').addEventListener('click', () => {
    $('#prjListView').style.display = '';
    $('#prjGanttView').style.display = 'none';
    $('#tabList').style.borderBottom = '2px solid var(--green-700)';
    $('#tabGantt').style.borderBottom = '';
  });
  $('#tabGantt').addEventListener('click', async () => {
    $('#prjListView').style.display = 'none';
    $('#prjGanttView').style.display = '';
    $('#tabGantt').style.borderBottom = '2px solid var(--green-700)';
    $('#tabList').style.borderBottom = '';
    await renderGantt(projects);
  });

  if (canWrite) $('#btnNewProject').addEventListener('click', () => openProjectEditor(null));
  wireProjectRows();
}

function renderProjectList(projects) {
  if (!projects.length) return `<div style="padding:40px;text-align:center;color:var(--muted)">No projects found. Click + New Project to add one.</div>`;

  return `
    <div style="display:flex;flex-direction:column;gap:10px">
      ${projects.map(p => {
        const totalMs = (p.milestones||[]).length;
        const doneMs = (p.milestones||[]).filter(m => m.status === 'completed').length;
        const overdueMs = (p.milestones||[]).filter(m => m.status === 'overdue').length;
        const daysLeft = p.planned_end ? Math.floor((new Date(p.planned_end) - new Date()) / 86400000) : null;

        return `
        <div class="proj-card" data-proj="${p.id}">
          <div class="proj-card-left">
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
              <span style="background:${ragBg[p.rag||'green']};color:${ragColor[p.rag||'green']};font-size:10px;font-weight:700;padding:2px 8px;border-radius:12px;border:1px solid ${ragColor[p.rag||'green']}33">
                ${ragLabel[p.rag||'green']}
              </span>
              <span style="background:${statusColor[p.status]}22;color:${statusColor[p.status]};font-size:10px;font-weight:600;padding:2px 8px;border-radius:12px">
                ${PROJECT_STATUSES.find(s=>s[0]===p.status)?.[1]||p.status}
              </span>
              <span style="font-size:10px;color:var(--muted);font-family:monospace">${p.project_code}</span>
              ${overdueMs > 0 ? `<span style="background:#fef2f2;color:#ef4444;font-size:10px;font-weight:600;padding:2px 8px;border-radius:12px">⚠ ${overdueMs} overdue</span>` : ''}
            </div>
            <div style="font-size:15px;font-weight:600;color:var(--ink);margin-bottom:4px">${escape(p.name)}</div>
            ${p.description ? `<div style="font-size:12px;color:var(--ink-soft);margin-bottom:8px">${escape(p.description.substring(0,120))}${p.description.length>120?'…':''}</div>` : ''}
            <div style="display:flex;gap:16px;font-size:11px;color:var(--muted)">
              <span>👤 ${escape(p.owner?.full_name||'Unassigned')}</span>
              <span>📂 ${PROJECT_CATEGORIES.find(c=>c[0]===p.category)?.[1]||p.category}</span>
              ${p.planned_start ? `<span>📅 ${fmtDate(p.planned_start)} → ${fmtDate(p.planned_end)}</span>` : ''}
              ${totalMs > 0 ? `<span>🎯 ${doneMs}/${totalMs} milestones</span>` : ''}
            </div>
          </div>
          <div class="proj-card-right">
            <div style="text-align:center;margin-bottom:8px">
              <div style="font-size:24px;font-weight:700;color:var(--green-700)">${p.progress_pct||0}%</div>
              <div style="font-size:10px;color:var(--muted)">complete</div>
            </div>
            <div style="width:80px;height:6px;background:var(--line);border-radius:3px;overflow:hidden">
              <div style="width:${p.progress_pct||0}%;height:100%;background:${p.progress_pct>=100?'var(--green-700)':p.rag==='red'?'#ef4444':p.rag==='amber'?'#f59e0b':'var(--green-500)'};border-radius:3px;transition:width 0.3s"></div>
            </div>
            ${daysLeft !== null ? `<div style="font-size:10px;margin-top:6px;text-align:center;color:${daysLeft<0?'#ef4444':daysLeft<14?'#f59e0b':'var(--muted)'}">
              ${daysLeft < 0 ? `${Math.abs(daysLeft)}d overdue` : `${daysLeft}d left`}
            </div>` : ''}
          </div>
        </div>`;
      }).join('')}
    </div>
  `;
}

function wireProjectRows() {
  $$('.proj-card').forEach(el => el.addEventListener('click', () => openProjectDetail(el.dataset.proj)));
}

// Gantt chart renderer
async function renderGantt(projects) {
  const container = $('#prjGantt');
  container.innerHTML = '<div style="padding:20px;color:var(--muted)">Loading Gantt…</div>';

  // Load milestones for all projects
  const projectIds = projects.map(p => p.id);
  if (!projectIds.length) {
    container.innerHTML = '<div style="padding:40px;text-align:center;color:var(--muted)">No projects to display.</div>';
    return;
  }

  const { data: milestones } = await sb.from('project_milestones')
    .select('*')
    .in('project_id', projectIds)
    .order('seq');

  const msMap = {};
  (milestones || []).forEach(m => {
    if (!msMap[m.project_id]) msMap[m.project_id] = [];
    msMap[m.project_id].push(m);
  });

  // Determine date range
  const allDates = [];
  projects.forEach(p => {
    if (p.planned_start) allDates.push(new Date(p.planned_start));
    if (p.planned_end) allDates.push(new Date(p.planned_end));
  });
  (milestones||[]).forEach(m => {
    if (m.planned_end) allDates.push(new Date(m.planned_end));
  });

  if (!allDates.length) {
    container.innerHTML = '<div style="padding:40px;text-align:center;color:var(--muted)">Add dates to projects to see the Gantt chart.</div>';
    return;
  }

  const minDate = new Date(Math.min(...allDates) - 7*86400000);
  const maxDate = new Date(Math.max(...allDates) + 14*86400000);
  const totalDays = Math.ceil((maxDate - minDate) / 86400000);
  const today = new Date();

  // Build month headers
  const months = [];
  let cur = new Date(minDate.getFullYear(), minDate.getMonth(), 1);
  while (cur <= maxDate) {
    months.push({ label: cur.toLocaleDateString('en-GB', { month: 'short', year: '2-digit' }), date: new Date(cur) });
    cur.setMonth(cur.getMonth() + 1);
  }

  const dayWidth = Math.max(3, Math.min(8, Math.floor(900 / totalDays)));
  const chartWidth = totalDays * dayWidth;
  const rowHeight = 36;

  const todayOffset = Math.floor((today - minDate) / 86400000) * dayWidth;

  // Helper: position in chart
  const dateToX = (d) => Math.floor((new Date(d) - minDate) / 86400000) * dayWidth;
  const dateToW = (s, e) => Math.max(dayWidth, Math.floor((new Date(e) - new Date(s)) / 86400000) * dayWidth);

  const msStatusStyle = {
    pending: '#e0e7ff', in_progress: '#3b82f6', completed: '#22c55e',
    overdue: '#ef4444', cancelled: '#9ca3af'
  };

  let ganttHTML = `
    <div style="overflow-x:auto;padding-bottom:20px">
      <div style="min-width:${chartWidth + 280}px">

        <!-- Header: months -->
        <div style="display:flex;margin-left:280px;border-bottom:2px solid var(--line)">
          ${months.map(m => {
            const monthStart = Math.max(0, Math.floor((m.date - minDate) / 86400000));
            const monthEnd = Math.floor((new Date(m.date.getFullYear(), m.date.getMonth()+1, 1) - minDate) / 86400000);
            const w = Math.max(0, (monthEnd - monthStart)) * dayWidth;
            return `<div style="min-width:${w}px;font-size:10px;font-weight:600;color:var(--muted);padding:4px 4px;white-space:nowrap;overflow:hidden;border-right:1px solid var(--line)">${m.label}</div>`;
          }).join('')}
        </div>

        <!-- Today line marker label -->
        <div style="position:relative;margin-left:280px;height:0">
          <div style="position:absolute;left:${todayOffset}px;top:0;bottom:0;z-index:2">
            <div style="background:#ef4444;color:white;font-size:9px;font-weight:700;padding:1px 4px;border-radius:2px;white-space:nowrap;transform:translateX(-50%)">TODAY</div>
          </div>
        </div>

        <!-- Rows -->
        ${projects.map((p, pi) => {
          const pMs = msMap[p.id] || [];
          const rows = 1 + pMs.length;
          const pStart = p.planned_start ? dateToX(p.planned_start) : null;
          const pWidth = (p.planned_start && p.planned_end) ? dateToW(p.planned_start, p.planned_end) : null;

          return `
          <!-- Project row -->
          <div style="display:flex;align-items:center;border-bottom:1px solid var(--line);height:${rowHeight}px;background:${pi%2===0?'#fafcf7':'white'}">
            <div style="width:280px;flex-shrink:0;padding:0 12px;font-size:12.5px;font-weight:600;color:var(--ink);display:flex;align-items:center;gap:6px;cursor:pointer" onclick="openProjectDetail('${p.id}')">
              <span style="width:8px;height:8px;border-radius:50%;background:${ragColor[p.rag||'green']};flex-shrink:0"></span>
              <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escape(p.name)}</span>
            </div>
            <div style="position:relative;flex:1;height:${rowHeight}px">
              <!-- Today line -->
              <div style="position:absolute;left:${todayOffset}px;top:0;bottom:0;width:1px;background:#ef444466;z-index:1"></div>
              <!-- Project bar -->
              ${pStart !== null && pWidth !== null ? `
              <div style="position:absolute;left:${pStart}px;top:8px;width:${pWidth}px;height:20px;background:${statusColor[p.status]}33;border:1.5px solid ${statusColor[p.status]};border-radius:4px;display:flex;align-items:center;padding:0 6px;overflow:hidden;z-index:2">
                <div style="height:8px;width:${p.progress_pct||0}%;background:${statusColor[p.status]};border-radius:2px;transition:width 0.3s"></div>
                <span style="font-size:9px;color:${statusColor[p.status]};font-weight:700;margin-left:4px;white-space:nowrap">${p.progress_pct||0}%</span>
              </div>` : ''}
            </div>
          </div>

          <!-- Milestone rows -->
          ${pMs.map(ms => {
            const mX = ms.planned_end ? dateToX(ms.planned_end) : null;
            const mStart = ms.planned_start ? dateToX(ms.planned_start) : null;
            const mW = (ms.planned_start && ms.planned_end) ? dateToW(ms.planned_start, ms.planned_end) : null;
            return `
            <div style="display:flex;align-items:center;border-bottom:1px dashed var(--line);height:${rowHeight}px;background:${pi%2===0?'#f5f9f0':'#f9fafb'}">
              <div style="width:280px;flex-shrink:0;padding:0 12px 0 28px;font-size:11.5px;color:var(--ink-soft);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
                ${ms.is_key_milestone ? '◆ ' : '· '}${escape(ms.title)}
              </div>
              <div style="position:relative;flex:1;height:${rowHeight}px">
                <div style="position:absolute;left:${todayOffset}px;top:0;bottom:0;width:1px;background:#ef444433;z-index:1"></div>
                ${mStart !== null && mW !== null ? `
                <div style="position:absolute;left:${mStart}px;top:10px;width:${mW}px;height:16px;background:${msStatusStyle[ms.status]}44;border:1px solid ${msStatusStyle[ms.status]};border-radius:3px;z-index:2"></div>` : ''}
                ${mX !== null && ms.is_key_milestone ? `
                <div style="position:absolute;left:${mX-6}px;top:9px;width:12px;height:12px;background:${msStatusStyle[ms.status]};transform:rotate(45deg);z-index:3;border:1px solid white"></div>` : ''}
              </div>
            </div>`;
          }).join('')}`;
        }).join('')}

        <!-- Legend -->
        <div style="padding:12px;display:flex;gap:16px;flex-wrap:wrap;font-size:11px;color:var(--muted);border-top:1px solid var(--line);margin-top:8px">
          <span>Legend:</span>
          ${Object.entries(msStatusStyle).map(([s,c]) => `<span style="display:flex;align-items:center;gap:4px"><span style="width:12px;height:8px;background:${c};border-radius:2px;display:inline-block"></span>${s}</span>`).join('')}
          <span style="display:flex;align-items:center;gap:4px"><span style="width:10px;height:10px;background:#6366f1;transform:rotate(45deg);display:inline-block"></span>Key milestone</span>
          <span style="display:flex;align-items:center;gap:4px"><span style="width:1px;height:12px;background:#ef4444;display:inline-block"></span>Today</span>
        </div>
      </div>
    </div>
  `;

  container.innerHTML = ganttHTML;
}

// Project detail drawer
async function openProjectDetail(projectId) {
  const canWrite = isAdmin() || hasRole('it_manager') || hasRole('sysadmin') || hasRole('network_admin') || hasRole('erp_admin');

  $('#drawerBg').classList.add('show');
  $('#drawerBody').innerHTML = '<div class="loading">Loading…</div>';

  const [projRes, msRes, updatesRes, profilesRes] = await Promise.all([
    sb.from('it_projects').select('*, owner:profiles!it_projects_owner_id_fkey(full_name,email)').eq('id', projectId).single(),
    sb.from('project_milestones').select('*, owner:profiles!project_milestones_owner_id_fkey(full_name)').eq('project_id', projectId).order('seq'),
    sb.from('project_updates').select('*, author:profiles!project_updates_author_id_fkey(full_name)').eq('project_id', projectId).order('created_at', { ascending: false }).limit(10),
    sb.from('profiles').select('id,full_name').eq('is_active', true).order('full_name')
  ]);

  const p = projRes.data;
  if (!p) { $('#drawerTitle').textContent = 'Not found'; $('#drawerBody').innerHTML = ''; return; }

  const ms = msRes.data || [];
  const updates = updatesRes.data || [];
  const profiles = profilesRes.data || [];

  $('#drawerTitle').textContent = p.name;
  $('#drawerRef').innerHTML = `${p.project_code} · <span style="color:${statusColor[p.status]}">${PROJECT_STATUSES.find(s=>s[0]===p.status)?.[1]||p.status}</span>`;

  $('#drawerBody').innerHTML = `
    <!-- RAG + Progress -->
    <div style="display:flex;gap:12px;margin-bottom:16px;align-items:center">
      <div style="background:${ragBg[p.rag||'green']};border:1px solid ${ragColor[p.rag||'green']}44;border-radius:8px;padding:8px 16px;text-align:center">
        <div style="font-size:11px;color:var(--muted)">Health</div>
        <div style="font-size:14px;font-weight:700;color:${ragColor[p.rag||'green']}">${ragLabel[p.rag||'green']}</div>
      </div>
      <div style="flex:1;background:var(--green-50);border-radius:8px;padding:8px 16px">
        <div style="display:flex;justify-content:space-between;margin-bottom:6px">
          <span style="font-size:11px;color:var(--muted)">Progress</span>
          <span style="font-size:13px;font-weight:700;color:var(--green-700)">${p.progress_pct||0}%</span>
        </div>
        <div style="height:8px;background:var(--line);border-radius:4px;overflow:hidden">
          <div style="width:${p.progress_pct||0}%;height:100%;background:var(--green-500);border-radius:4px;transition:width 0.3s"></div>
        </div>
      </div>
    </div>

    <!-- Meta -->
    <div class="detail-meta">
      <div class="m-item"><label>Category</label><span>${PROJECT_CATEGORIES.find(c=>c[0]===p.category)?.[1]||p.category}</span></div>
      <div class="m-item"><label>Priority</label><span>${PROJECT_PRIORITIES.find(c=>c[0]===p.priority)?.[1]||p.priority}</span></div>
      <div class="m-item"><label>Owner</label><span>${escape(p.owner?.full_name||'—')}</span></div>
      <div class="m-item"><label>Start Date</label><span>${p.planned_start ? fmtDate(p.planned_start) : '—'}</span></div>
      <div class="m-item"><label>End Date</label><span>${p.planned_end ? fmtDate(p.planned_end) : '—'}</span></div>
      ${p.budget ? `<div class="m-item"><label>Budget</label><span>${Number(p.budget).toLocaleString()} ${p.budget_currency||'AED'}</span></div>` : ''}
    </div>

    ${p.description ? `<div class="detail-section"><h4>Description</h4><p>${escape(p.description)}</p></div>` : ''}

    <!-- Milestones -->
    <div class="detail-section">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <h4 style="margin:0">Milestones (${ms.length})</h4>
        ${canWrite ? `<button class="btn secondary btn-sm" id="btnAddMs">+ Add Milestone</button>` : ''}
      </div>
      ${ms.length ? `
        <div style="display:flex;flex-direction:column;gap:8px">
          ${ms.map(m => `
            <div class="mini-row" style="border:1px solid var(--line);border-radius:6px;padding:10px 12px;background:white" data-ms-id="${m.id}">
              <div class="mini-main">
                <div style="display:flex;align-items:center;gap:8px">
                  ${m.is_key_milestone ? '<span style="color:var(--green-700)">◆</span>' : '<span style="color:var(--muted)">·</span>'}
                  <span style="font-size:13px;font-weight:500">${escape(m.title)}</span>
                  <span style="font-size:10px;padding:1px 6px;border-radius:10px;background:${msStatusStyle[m.status]}22;color:${msStatusStyle[m.status]}">${m.status}</span>
                  ${m.progress_pct > 0 ? `<span style="font-size:10px;color:var(--muted)">${m.progress_pct}%</span>` : ''}
                </div>
                <div style="font-size:11px;color:var(--muted);margin-top:3px;margin-left:18px">
                  Due: ${fmtDate(m.planned_end)}${m.owner ? ` · ${escape(m.owner.full_name)}` : ''}
                </div>
              </div>
              ${canWrite ? `
              <div style="display:flex;gap:4px;flex-shrink:0">
                <select class="ms-status-sel" data-ms="${m.id}" style="font-size:11px;padding:2px 4px;border:1px solid var(--line);border-radius:4px">
                  ${MS_STATUSES.map(([v,l]) => `<option value="${v}" ${m.status===v?'selected':''}>${l}</option>`).join('')}
                </select>
              </div>` : ''}
            </div>
          `).join('')}
        </div>` : `<p style="color:var(--muted);font-size:12px">No milestones yet. Add milestones to track progress.</p>`}
    </div>

    <!-- Status Updates -->
    <div class="detail-section">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <h4 style="margin:0">Status Updates</h4>
      </div>
      ${canWrite ? `
      <div style="background:var(--green-50);border:1px solid var(--green-200);border-radius:8px;padding:14px;margin-bottom:14px">
        <div style="display:flex;gap:8px;margin-bottom:8px">
          <label style="font-size:11px;font-weight:600">RAG:</label>
          <select id="updRag" style="font-size:12px;padding:2px 8px;border:1px solid var(--line);border-radius:4px">
            <option value="green">🟢 Green — On Track</option>
            <option value="amber">🟡 Amber — At Risk</option>
            <option value="red">🔴 Red — Off Track</option>
          </select>
          <input id="updPct" type="number" min="0" max="100" placeholder="Progress %" style="width:100px;font-size:12px;padding:2px 8px;border:1px solid var(--line);border-radius:4px" value="${p.progress_pct||0}" />
        </div>
        <textarea id="updSummary" rows="2" placeholder="What's the current status? What was done this week? Any blockers?" style="width:100%;font-size:12.5px;border:1px solid var(--line);border-radius:4px;padding:8px;resize:vertical"></textarea>
        <div style="margin-top:8px;text-align:right">
          <button class="btn ok btn-sm" id="btnPostUpdate">Post Update</button>
        </div>
      </div>` : ''}
      ${updates.length ? `
        <div class="timeline">
          ${updates.map(u => `
            <div class="tl-step done">
              <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px">
                <span style="width:10px;height:10px;border-radius:50%;background:${ragColor[u.rag||'green']};display:inline-block"></span>
                <h5 style="margin:0">${escape(u.author?.full_name||'—')} · ${fmtDateTime(u.created_at)}</h5>
                ${u.progress_pct !== null ? `<span style="font-size:10px;color:var(--muted)">${u.progress_pct}%</span>` : ''}
              </div>
              <div class="meta">${escape(u.summary)}</div>
            </div>
          `).join('')}
        </div>` : '<p style="color:var(--muted);font-size:12px">No updates yet.</p>'}
    </div>

    ${canWrite ? `
    <div style="display:flex;gap:8px;margin-top:16px">
      <button class="btn ok" id="btnEditProject">Edit Project</button>
      <button class="btn secondary" onclick="closeDrawer()">Close</button>
    </div>` : ''}
  `;

  // Wire milestone status changes
  $$('.ms-status-sel').forEach(sel => {
    sel.addEventListener('change', async () => {
      const msId = sel.dataset.ms;
      const { error } = await sb.from('project_milestones')
        .update({ status: sel.value, actual_end: sel.value === 'completed' ? new Date().toISOString().slice(0,10) : null })
        .eq('id', msId);
      if (error) { toast(error.message, 'error'); return; }
      await sb.rpc('recalc_project_progress', { p_project_id: projectId });
      toast('Milestone updated', 'success');
      openProjectDetail(projectId);
    });
  });

  // Post update
  if ($('#btnPostUpdate')) {
    $('#btnPostUpdate').addEventListener('click', async () => {
      const summary = $('#updSummary').value.trim();
      if (!summary) { toast('Please write an update', 'error'); return; }
      const rag = $('#updRag').value;
      const pct = $('#updPct').value ? parseInt($('#updPct').value) : null;

      const btn = $('#btnPostUpdate');
      btn.disabled = true; btn.textContent = 'Posting…';

      const { error } = await sb.from('project_updates').insert({
        project_id: projectId, author_id: CURRENT_USER.id,
        rag, summary, progress_pct: pct
      });
      if (error) { toast(error.message, 'error'); btn.disabled = false; btn.textContent = 'Post Update'; return; }

      // Update project RAG + progress
      await sb.from('it_projects').update({
        rag,
        ...(pct !== null ? { progress_pct: pct } : {}),
        updated_at: new Date().toISOString()
      }).eq('id', projectId);

      toast('Update posted', 'success');
      openProjectDetail(projectId);
    });
  }

  // Add milestone
  if ($('#btnAddMs')) {
    $('#btnAddMs').addEventListener('click', () => openMilestoneEditor(projectId, null, ms.length + 1));
  }

  // Edit project
  if ($('#btnEditProject')) {
    $('#btnEditProject').addEventListener('click', () => openProjectEditor(projectId));
  }
}

// Project editor
async function openProjectEditor(projectId) {
  const { data: profiles } = await sb.from('profiles').select('id,full_name').eq('is_active', true).order('full_name');
  const proj = projectId ? (await sb.from('it_projects').select('*').eq('id', projectId).single()).data : null;
  const p = proj || {};

  // Open the drawer
  $('#drawerBg').classList.add('show');
  $('#drawerTitle').textContent = projectId ? 'Edit Project' : 'New Project';
  $('#drawerRef').textContent = projectId ? p.project_code : 'New';
  $('#drawerBody').innerHTML = '<div class="loading">Loading…</div>';

  $('#drawerBody').innerHTML = `
    <div class="form-section">
      <h4>Project Details</h4>
      <div class="grid-2">
        <div class="field"><label class="required">Project Name</label>
          <input id="pe-name" value="${escape(p.name||'')}" placeholder="e.g. MFA Rollout Phase 2" /></div>
        <div class="field"><label class="required">Category</label>
          <select id="pe-cat">${PROJECT_CATEGORIES.map(([v,l]) => `<option value="${v}" ${p.category===v?'selected':''}>${l}</option>`).join('')}</select></div>
        <div class="field"><label class="required">Priority</label>
          <select id="pe-pri">${PROJECT_PRIORITIES.map(([v,l]) => `<option value="${v}" ${p.priority===v?'selected':''}>${l}</option>`).join('')}</select></div>
        <div class="field"><label class="required">Status</label>
          <select id="pe-status">${PROJECT_STATUSES.map(([v,l]) => `<option value="${v}" ${p.status===v?'selected':''}>${l}</option>`).join('')}</select></div>
        <div class="field"><label>Owner</label>
          <select id="pe-owner"><option value="">— Unassigned —</option>
            ${(profiles||[]).map(u => `<option value="${u.id}" ${p.owner_id===u.id?'selected':''}>${escape(u.full_name)}</option>`).join('')}
          </select></div>
        <div class="field"><label>RAG Status</label>
          <select id="pe-rag">
            <option value="green" ${p.rag==='green'?'selected':''}>🟢 Green — On Track</option>
            <option value="amber" ${p.rag==='amber'?'selected':''}>🟡 Amber — At Risk</option>
            <option value="red" ${p.rag==='red'?'selected':''}>🔴 Red — Off Track</option>
          </select></div>
        <div class="field"><label>Start Date</label>
          <input type="date" id="pe-start" value="${p.planned_start||''}" /></div>
        <div class="field"><label>Target End Date</label>
          <input type="date" id="pe-end" value="${p.planned_end||''}" /></div>
        <div class="field"><label>Progress %</label>
          <input type="number" id="pe-pct" min="0" max="100" value="${p.progress_pct||0}" /></div>
        <div class="field"><label>Budget (AED)</label>
          <input type="number" id="pe-budget" value="${p.budget||''}" placeholder="0" /></div>
      </div>
      <div class="field"><label>Description</label>
        <textarea id="pe-desc" rows="3" placeholder="What is this project about? What are the goals?">${escape(p.description||'')}</textarea></div>
    </div>
    <div class="btn-row">
      <button class="btn ok" id="btnSaveProject">${projectId ? 'Save Changes' : 'Create Project'}</button>
      <button class="btn secondary" onclick="closeDrawer()">Cancel</button>
    </div>
  `;

  const get = id => document.getElementById(id)?.value?.trim() || '';

  $('#btnSaveProject').addEventListener('click', async () => {
    if (!get('pe-name')) { toast('Project name required', 'error'); return; }
    const btn = $('#btnSaveProject');
    btn.disabled = true; btn.innerHTML = '<span class="spin"></span> Saving…';

    const payload = {
      name: get('pe-name'),
      category: get('pe-cat'),
      priority: get('pe-pri'),
      status: get('pe-status'),
      rag: get('pe-rag'),
      owner_id: get('pe-owner') || null,
      planned_start: get('pe-start') || null,
      planned_end: get('pe-end') || null,
      progress_pct: parseInt(get('pe-pct')) || 0,
      budget: get('pe-budget') ? parseFloat(get('pe-budget')) : null,
      description: get('pe-desc') || null,
      updated_at: new Date().toISOString()
    };

    try {
      if (projectId) {
        const { error } = await sb.from('it_projects').update(payload).eq('id', projectId);
        if (error) throw error;
        toast('Project updated', 'success');
        openProjectDetail(projectId);
      } else {
        const { data: codeData } = await sb.rpc('gen_project_code');
        payload.project_code = codeData || `PRJ-${Date.now()}`;
        payload.created_by = CURRENT_USER.id;
        const { error } = await sb.from('it_projects').insert(payload);
        if (error) throw error;
        toast('Project created', 'success');
        closeDrawer();
        route('it-projects');
      }
    } catch(e) {
      toast(e.message || 'Save failed', 'error');
      btn.disabled = false;
      btn.innerHTML = projectId ? 'Save Changes' : 'Create Project';
    }
  });
}

// Milestone editor
async function openMilestoneEditor(projectId, milestoneId, defaultSeq) {
  const { data: profiles } = await sb.from('profiles').select('id,full_name').eq('is_active', true).order('full_name');
  const ms = milestoneId ? (await sb.from('project_milestones').select('*').eq('id', milestoneId).single()).data : null;
  const m = ms || {};

  // Show as a mini-modal over the drawer
  const existing = document.getElementById('msModal');
  if (existing) existing.remove();

  const modal = document.createElement('div');
  modal.id = 'msModal';
  modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:10001;display:flex;align-items:center;justify-content:center;padding:20px';
  modal.innerHTML = `
    <div style="background:white;border-radius:10px;padding:24px;max-width:480px;width:100%;font-family:Inter,sans-serif">
      <h3 style="margin:0 0 16px;font-size:16px">${milestoneId ? 'Edit Milestone' : 'Add Milestone'}</h3>
      <div class="field"><label class="required">Title</label>
        <input id="ms-title" value="${escape(m.title||'')}" placeholder="e.g. Deploy to staging environment" /></div>
      <div class="grid-2">
        <div class="field"><label>Start Date</label><input type="date" id="ms-start" value="${m.planned_start||''}" /></div>
        <div class="field"><label class="required">Due Date</label><input type="date" id="ms-end" value="${m.planned_end||''}" /></div>
        <div class="field"><label>Owner</label>
          <select id="ms-owner"><option value="">— Unassigned —</option>
            ${(profiles||[]).map(u => `<option value="${u.id}" ${m.owner_id===u.id?'selected':''}>${escape(u.full_name)}</option>`).join('')}
          </select></div>
        <div class="field"><label>Status</label>
          <select id="ms-status">${MS_STATUSES.map(([v,l]) => `<option value="${v}" ${m.status===v?'selected':''}>${l}</option>`).join('')}</select></div>
        <div class="field"><label>Progress %</label>
          <input type="number" id="ms-pct" min="0" max="100" value="${m.progress_pct||0}" /></div>
        <div class="field" style="display:flex;align-items:center;gap:8px;padding-top:24px">
          <input type="checkbox" id="ms-key" ${m.is_key_milestone?'checked':''} />
          <label for="ms-key" style="font-size:12px">Key milestone (◆ on Gantt)</label>
        </div>
      </div>
      <div class="btn-row" style="margin-top:16px">
        <button class="btn ok" id="btnSaveMs">${milestoneId ? 'Save' : 'Add Milestone'}</button>
        <button class="btn secondary" onclick="document.getElementById('msModal').remove()">Cancel</button>
      </div>
    </div>
  `;
  document.body.appendChild(modal);

  document.getElementById('btnSaveMs').addEventListener('click', async () => {
    const title = document.getElementById('ms-title').value.trim();
    const end = document.getElementById('ms-end').value;
    if (!title || !end) { toast('Title and due date required', 'error'); return; }

    const payload = {
      project_id: projectId,
      seq: m.seq || defaultSeq,
      title,
      planned_start: document.getElementById('ms-start').value || null,
      planned_end: end,
      owner_id: document.getElementById('ms-owner').value || null,
      status: document.getElementById('ms-status').value,
      progress_pct: parseInt(document.getElementById('ms-pct').value) || 0,
      is_key_milestone: document.getElementById('ms-key').checked,
      updated_at: new Date().toISOString()
    };

    const btn = document.getElementById('btnSaveMs');
    btn.disabled = true; btn.innerHTML = '<span class="spin"></span>';

    try {
      if (milestoneId) {
        const { error } = await sb.from('project_milestones').update(payload).eq('id', milestoneId);
        if (error) throw error;
      } else {
        const { error } = await sb.from('project_milestones').insert(payload);
        if (error) throw error;
      }
      await sb.rpc('recalc_project_progress', { p_project_id: projectId });
      modal.remove();
      toast(milestoneId ? 'Milestone updated' : 'Milestone added', 'success');
      openProjectDetail(projectId);
    } catch(e) {
      toast(e.message || 'Save failed', 'error');
      btn.disabled = false; btn.textContent = milestoneId ? 'Save' : 'Add Milestone';
    }
  });
}


// =============================================================================
// FFC IT OPS AGENT
// =============================================================================

// Groq free API — get key from console.groq.com (free, no card needed)
const CLAUDE_API_KEY = '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';
const CLAUDE_MODEL   = 'llama-3.3-70b-versatile';

// Conversation history (kept in memory per session)
let agentHistory = [];

// Load live context from Supabase to give the agent real data
async function loadAgentContext() {
  const in30 = new Date(Date.now() + 30*86400000).toISOString().slice(0,10);

  const safe = async (fn) => {
    try { const r = await fn(); return r.data || []; }
    catch(e) { console.warn('Agent context query failed:', e.message); return []; }
  };

  const [
    openCRs, pendingApprovals, overdueChk, licExpiring,
    openCapas, drOverdue, vendorExpiring, openProjects
  ] = await Promise.all([
    safe(() => sb.from('request_master').select('ref_no,title,status')
      .eq('module','change_request').in('status',['submitted','pending_approval','approved','scheduled'])
      .order('created_at',{ascending:false}).limit(10)),
    safe(() => sb.from('request_approvals').select('request:request_master(ref_no,title,status),due_at')
      .eq('approver_id',CURRENT_USER.id).eq('decision','pending').limit(10)),
    safe(() => sb.from('checklist_instances').select('instance_code,name_snapshot,due_at')
      .in('status',['overdue','escalated']).order('due_at',{ascending:true}).limit(10)),
    safe(() => sb.from('license_items').select('item_code,item_name,vendor,expiry_date,criticality')
      .lte('expiry_date',in30).order('expiry_date',{ascending:true}).limit(10)),
    safe(() => sb.from('capas').select('capa_code,title,severity,status,target_date')
      .in('status',['open','assigned','in_progress','overdue']).order('target_date',{ascending:true}).limit(10)),
    safe(() => sb.from('dr_services').select('service_name,next_test_due,rto_hours,rpo_hours')
      .eq('is_active',true).limit(10)),
    safe(() => sb.from('vendor_contracts').select('contract_title,end_date,vendor:vendors(name)')
      .lte('end_date',in30).order('end_date',{ascending:true}).limit(5)),
    safe(() => sb.from('it_projects').select('name,status,rag,progress_pct,planned_end')
      .in('status',['planning','in_progress']).order('planned_end',{ascending:true}).limit(10))
  ]);

  const fmt = (arr, fn) => arr.length ? arr.map(fn).join('\n') : 'None';
  const fmtDate = d => d ? new Date(d).toLocaleDateString('en-GB',{day:'2-digit',month:'short',year:'numeric'}) : '—';

  return `
=== LIVE FFC IT PORTAL DATA (as of ${new Date().toLocaleString('en-GB')}) ===

PENDING APPROVALS FOR ${CURRENT_USER.full_name} (${pendingApprovals.length}):
${fmt(pendingApprovals, a => `- [${a.request?.ref_no||'?'}] ${a.request?.title||'?'} — due ${fmtDate(a.due_at)}`)}

OPEN CHANGE REQUESTS (${openCRs.length}):
${fmt(openCRs, r => `- [${r.ref_no}] ${r.title} — ${r.status}`)}

OVERDUE CHECKLISTS (${overdueChk.length}):
${fmt(overdueChk, c => `- [${c.instance_code}] ${c.name_snapshot} — due ${fmtDate(c.due_at)}`)}

LICENSES EXPIRING WITHIN 30 DAYS (${licExpiring.length}):
${fmt(licExpiring, l => `- ${l.item_name} (${l.vendor||'—'}) — expires ${fmtDate(l.expiry_date)}`)}

OPEN CAPAs (${openCapas.length}):
${fmt(openCapas, c => `- [${c.capa_code}] ${c.title} — ${c.severity} — ${c.status} — due ${fmtDate(c.target_date)}`)}

DR SERVICES (${drOverdue.length}):
${fmt(drOverdue, s => `- ${s.service_name} — next test ${fmtDate(s.next_test_due)} — RTO ${s.rto_hours}h / RPO ${s.rpo_hours}h`)}

VENDOR CONTRACTS EXPIRING WITHIN 30 DAYS (${vendorExpiring.length}):
${fmt(vendorExpiring, v => `- ${v.contract_title} (${v.vendor?.name||'—'}) — ends ${fmtDate(v.end_date)}`)}

ACTIVE IT PROJECTS (${openProjects.length}):
${fmt(openProjects, p => `- ${p.name} — ${p.status} — ${p.progress_pct||0}% — RAG:${p.rag||'green'} — due ${fmtDate(p.planned_end)}`)}
`.trim();
}


// Build system prompt with live context
function buildSystemPrompt(liveContext) {
  return `You are the FFC IT Operations AI Agent for Fresh Fruits Company (UAE).
You assist ${CURRENT_USER.full_name} (role: ${USER_ROLES.join(', ')}).

TEAM:
- Satham — IT Manager
- Syeed Hassan — Senior Sysadmin (security, systems, deployments)
- Sohail Khan — ERP Admin (SAP, NetSuite)
- Nidheeshlal — Network Admin (FortiGate, Aruba, VLANs)
- Muhammed Reza — IT Support
- Majeed — Helpdesk

INFRASTRUCTURE:
- Firewall: FortiGate 200E (FortiOS 7.2.x) — 12 audit findings (4 critical)
- Core switch: Aruba 2930F VSF stack
- Servers: HP ProLiant Hyper-V hosts
- Storage: QNAP + Synology NAS, Azure IaaS
- ERP: SAP (TFM, vendor-managed RDP) + Oracle NetSuite (FFC, SaaS)
- M365: ~300 users, Entra ID hybrid, MFA rollout in progress
- Backup: Veeam Enterprise deploying, Wasabi Cloud Object Lock, 3-2-1-1 strategy
- Monitoring: PRTG, ManageEngine ServiceDesk Plus

ACTIVE PROJECTS:
- MFA rollout (215 users, SMS OTP, Syeed owns)
- Veeam 3-2-1-1 backup deployment
- FortiGate VLAN migration (CCTV VLAN 45 first phase)
- JumpServer PAM implementation
- ESL/Zkong cloud migration (Technowave vendor)
- AD security audit (PingCastle → Purple Knight)
- SAP–CompuCash integration (price sync issues)

SITES: FFC Head Office, TFM (The Fresh Market), Market Shop, VS

FFC IT PORTAL MODULES: Change Requests, SOPs, Leave/Overtime, Onboarding/Offboarding, Access Requests, Asset Registry, License Tracker, Vendor Contracts, DR Tracker, CAPA Register, Branch Compliance, Checklists, IT Projects

${liveContext}

RESPONSE RULES:
- Be direct, concise, and practical (under 150 words unless detail explicitly needed)
- Use bullet points for lists
- Reference actual data from the live context above when relevant
- When asked to create/raise something, explain how to do it in the FFC IT Portal
- If asked about something not in context, say so clearly
- Never make up ticket numbers or data not in the context above`;
}

// Send message to Groq API
async function sendToGroq(userMessage) {
  if (!CLAUDE_API_KEY || CLAUDE_API_KEY === 'YOUR_GROQ_API_KEY') {
    return '⚠️ Groq API key not configured. Get your free key at console.groq.com → API Keys → Create API Key. Then open app.js, find CLAUDE_API_KEY near the agent section, and replace YOUR_GROQ_API_KEY with your key.';
  }

  const messages = agentHistory.filter(m => m.role !== 'system');

  const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${CLAUDE_API_KEY}`
    },
    body: JSON.stringify({
      model: CLAUDE_MODEL,
      temperature: 0.4,
      max_tokens: 512,
      messages: [
        { role: 'system', content: window._agentSystemPrompt || 'You are an IT operations assistant for Fresh Fruits Company.' },
        ...messages.map(m => ({ role: m.role, content: m.content }))
      ]
    })
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    const msg = err.error?.message || `API error ${response.status}`;
    if (response.status === 401) throw new Error('Invalid API key. Check your key at console.groq.com');
    if (response.status === 429) throw new Error('Rate limit reached. Wait a moment and try again.');
    throw new Error(msg);
  }

  const data = await response.json();
  return data.choices?.[0]?.message?.content || 'No response.';
}

// Main agent render
async function renderITAgent() {
  const canUse = isAdmin() || hasRole('it_manager') || hasRole('sysadmin') ||
                 hasRole('network_admin') || hasRole('erp_admin') || hasRole('it_support');
  if (!canUse) {
    $('#viewContent').innerHTML = '<div class="panel"><div class="panel-body" style="padding:40px;text-align:center;color:var(--muted)">IT Operations Agent is available to IT team members only.</div></div>';
    return;
  }

  $('#viewContent').innerHTML = `
    <div style="max-width:780px;margin:0 auto">

      <!-- Header -->
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;flex-wrap:wrap;gap:12px">
        <div style="display:flex;align-items:center;gap:12px">
          <div style="width:42px;height:42px;border-radius:12px;background:var(--green-700);display:flex;align-items:center;justify-content:center;flex-shrink:0">
            <span style="font-size:20px">🤖</span>
          </div>
          <div>
            <div style="font-size:16px;font-weight:600;color:var(--ink)">FFC IT Ops Agent</div>
            <div style="font-size:12px;color:var(--muted)">Powered by Llama 3.3 70B · Free via Groq</div>
          </div>
        </div>
        <div style="display:flex;align-items:center;gap:6px;font-size:12px;color:var(--muted);background:var(--card);border:0.5px solid var(--line);border-radius:20px;padding:4px 12px">
          <span id="agentStatusDot" style="width:7px;height:7px;border-radius:50%;background:#64748b;display:inline-block"></span>
          <span id="agentStatusText">Loading context…</span>
        </div>
      </div>

      <!-- Context summary cards -->
      <div id="agentContextCards" style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:18px">
        ${[1,2,3,4].map(() => `<div style="background:var(--card);border:0.5px solid var(--line);border-radius:10px;padding:12px;opacity:.4"><div style="height:8px;background:var(--line);border-radius:4px;margin-bottom:6px"></div><div style="height:20px;background:var(--line);border-radius:4px"></div></div>`).join('')}
      </div>

      <!-- Suggestion chips -->
      <div id="agentSuggestions" style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px">
        ${[
          ['📋 My approvals','What approvals are waiting for me right now?'],
          ['⚠️ Overdue items','What is overdue across checklists and CAPAs?'],
          ['🔒 Expiring soon','Which licenses or contracts are expiring in 30 days?'],
          ['📊 Project status','Give me a status summary of all active IT projects'],
          ['🔧 Open CAPAs','List all open CAPAs with their severity and owner'],
          ['💾 DR status','What DR tests are due and what services are covered?']
        ].map(([label, q]) => `
          <button onclick="agentAsk(${JSON.stringify(q)})" style="font-size:12px;padding:6px 12px;border-radius:16px;border:0.5px solid var(--line);background:var(--card);color:var(--ink-soft);cursor:pointer;transition:all .15s" onmouseover="this.style.borderColor='var(--green-500)';this.style.color='var(--green-700)'" onmouseout="this.style.borderColor='var(--line)';this.style.color='var(--ink-soft)'">${label}</button>
        `).join('')}
      </div>

      <!-- Chat window -->
      <div style="background:var(--card);border:0.5px solid var(--line);border-radius:12px;overflow:hidden">

        <!-- Messages -->
        <div id="agentMessages" style="padding:16px;display:flex;flex-direction:column;gap:12px;min-height:200px;max-height:420px;overflow-y:auto">
          <div style="display:flex;gap:10px;align-items:flex-start">
            <div style="width:28px;height:28px;border-radius:8px;background:var(--green-700);display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:13px">🤖</div>
            <div style="background:var(--bg);border:0.5px solid var(--line);border-radius:10px;padding:10px 14px;font-size:13px;line-height:1.6;color:var(--ink);max-width:85%">
              Hello ${CURRENT_USER.full_name.split(' ')[0]}. I'm loading your live IT data now — one moment…
            </div>
          </div>
        </div>

        <!-- Typing indicator -->
        <div id="agentTyping" style="display:none;padding:0 16px 12px;align-items:center;gap:10px">
          <div style="width:28px;height:28px;border-radius:8px;background:var(--green-700);display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:13px">🤖</div>
          <div style="display:flex;gap:4px;align-items:center">
            ${[0,150,300].map(d => `<span style="width:6px;height:6px;border-radius:50%;background:var(--muted);animation:agentDot 0.8s ${d}ms infinite ease-in-out"></span>`).join('')}
          </div>
        </div>

        <!-- Input -->
        <div style="padding:12px;border-top:0.5px solid var(--line);display:flex;gap:8px;background:var(--bg)">
          <input id="agentInput" placeholder="Ask about any IT operation, ticket, asset, project or team…"
            style="flex:1;padding:9px 14px;border:0.5px solid var(--line);border-radius:20px;font-size:13px;background:var(--card);color:var(--ink);outline:none;font-family:inherit"
            onfocus="this.style.borderColor='var(--green-500)'"
            onblur="this.style.borderColor='var(--line)'" />
          <button id="agentSendBtn" onclick="agentSend()" style="width:36px;height:36px;border-radius:50%;background:var(--green-700);border:none;cursor:pointer;display:flex;align-items:center;justify-content:center;flex-shrink:0;transition:opacity .15s" onmouseover="this.style.opacity='.8'" onmouseout="this.style.opacity='1'">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="white"><path d="M2 21l21-9L2 3v7l15 2-15 2z"/></svg>
          </button>
        </div>

        <!-- Footer -->
        <div style="padding:6px 14px;border-top:0.5px solid var(--line);background:var(--bg);font-size:10.5px;color:var(--muted);display:flex;justify-content:space-between">
          <span>Llama 3.3 70B via Groq · Free · Context refreshes on page load</span>
          <button onclick="agentClear()" style="background:none;border:none;font-size:10.5px;color:var(--muted);cursor:pointer;padding:0">Clear chat</button>
        </div>
      </div>

      <!-- API key notice -->
      ${(!CLAUDE_API_KEY || CLAUDE_API_KEY === 'YOUR_ANTHROPIC_API_KEY') ? `
      <div style="margin-top:12px;background:#fff5eb;border:1px solid #f5a02a55;border-radius:8px;padding:12px 16px;font-size:12.5px;color:var(--ink)">
        ⚠️ <strong>Groq API key needed.</strong> Sign up free (no card) at <a href="https://console.groq.com" target="_blank" style="color:var(--green-700)">console.groq.com</a> → API Keys → Create API Key.
        Then open <code>app.js</code>, find <code>CLAUDE_API_KEY</code> near the agent section, and replace <code>YOUR_GROQ_API_KEY</code> with your key.
      </div>` : ''}
    </div>

    <style>
      @keyframes agentDot {
        0%,60%,100%{transform:translateY(0);opacity:.4}
        30%{transform:translateY(-4px);opacity:1}
      }
    </style>
  `;

  document.getElementById('agentInput').addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); agentSend(); }
  });

  // Load live context in background
  try {
    const liveCtx = await loadAgentContext();
    agentHistory = [];

    // Rebuild system with live data
    window._agentSystemPrompt = buildSystemPrompt(liveCtx);

    // Update status indicator
    const dot = document.getElementById('agentStatusDot');
    const txt = document.getElementById('agentStatusText');
    if (dot) { dot.style.background = '#22c55e'; dot.style.boxShadow = '0 0 0 2px rgba(34,197,94,.25)'; }
    if (txt) txt.textContent = 'Live data loaded · Ready';

    // Update context summary cards
    const cards = document.getElementById('agentContextCards');
    if (cards) {
      const counts = await Promise.all([
        sb.from('request_approvals').select('id',{count:'exact',head:true}).eq('approver_id',CURRENT_USER.id).eq('decision','pending'),
        sb.from('checklist_instances').select('id',{count:'exact',head:true}).in('status',['overdue','escalated']),
        sb.from('capas').select('id',{count:'exact',head:true}).in('status',['open','assigned','in_progress','overdue']),
        sb.from('license_items').select('id',{count:'exact',head:true}).in('status',['active','expiring_soon']).lte('expiry_date', new Date(Date.now()+30*86400000).toISOString().slice(0,10))
      ]);

      const cardData = [
        { label:'My Approvals', value: counts[0].count||0, color:'var(--green-700)', bg:'var(--green-50)' },
        { label:'Overdue Checks', value: counts[1].count||0, color: counts[1].count>0 ? '#ef4444':'var(--muted)', bg: counts[1].count>0?'#fef2f2':'var(--card)' },
        { label:'Open CAPAs', value: counts[2].count||0, color: counts[2].count>0 ? '#f59e0b':'var(--muted)', bg: counts[2].count>0?'#fffbeb':'var(--card)' },
        { label:'Expiring (30d)', value: counts[3].count||0, color: counts[3].count>0 ? '#f59e0b':'var(--muted)', bg: counts[3].count>0?'#fffbeb':'var(--card)' }
      ];

      cards.innerHTML = cardData.map(c => `
        <div style="background:${c.bg};border:0.5px solid var(--line);border-radius:10px;padding:12px;cursor:pointer" onclick="agentAsk('Tell me about ${c.label.toLowerCase()}')">
          <div style="font-size:11px;color:var(--muted);margin-bottom:4px">${c.label}</div>
          <div style="font-size:22px;font-weight:600;color:${c.color}">${c.value}</div>
        </div>
      `).join('');
    }

    // Welcome message with real data
    agentAppendMessage(`Context loaded. I can see your live IT data — ${counts[0].count||0} approvals pending, ${counts[1].count||0} overdue checklists, ${counts[2].count||0} open CAPAs. What do you need?`, false);

  } catch(e) {
    console.error('Agent context load failed', e);
    window._agentSystemPrompt = buildSystemPrompt('Live data could not be loaded. Answer from FFC IT knowledge only.');
    const dot = document.getElementById('agentStatusDot');
    const txt = document.getElementById('agentStatusText');
    if (dot) dot.style.background = '#f59e0b';
    if (txt) txt.textContent = 'Context load failed — offline mode';
    agentAppendMessage('I could not load live data from the portal. I can still help with general FFC IT questions.', false);
  }
}

function agentAppendMessage(text, isUser) {
  const msgs = document.getElementById('agentMessages');
  if (!msgs) return;

  const div = document.createElement('div');
  div.style.cssText = `display:flex;gap:10px;align-items:flex-start;${isUser?'flex-direction:row-reverse':''}`;

  const formatted = text
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.*?)\*/g, '<em>$1</em>')
    .replace(/`(.*?)`/g, '<code style="background:var(--bg);padding:1px 5px;border-radius:4px;font-family:monospace;font-size:12px">$1</code>')
    .replace(/^- (.+)/gm, '<li style="margin-left:16px">$1</li>')
    .replace(/\n/g, '<br>');

  div.innerHTML = `
    <div style="width:28px;height:28px;border-radius:8px;background:${isUser?'var(--green-100)':'var(--green-700)'};display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:${isUser?'11px':'13px'};font-weight:${isUser?'600':'400'};color:${isUser?'var(--green-700)':'white'}">
      ${isUser ? CURRENT_USER.full_name.split(' ').map(w=>w[0]).join('').slice(0,2).toUpperCase() : '🤖'}
    </div>
    <div style="background:${isUser?'var(--green-700)':'var(--bg)'};color:${isUser?'white':'var(--ink)'};border:0.5px solid ${isUser?'transparent':'var(--line)'};border-radius:10px;padding:10px 14px;font-size:13px;line-height:1.6;max-width:85%">
      ${formatted}
    </div>
  `;
  msgs.appendChild(div);
  msgs.scrollTop = msgs.scrollHeight;
}

function agentShowTyping(show) {
  const t = document.getElementById('agentTyping');
  if (t) {
    t.style.display = show ? 'flex' : 'none';
    if (show) {
      const msgs = document.getElementById('agentMessages');
      if (msgs) msgs.scrollTop = msgs.scrollHeight;
    }
  }
  const btn = document.getElementById('agentSendBtn');
  const inp = document.getElementById('agentInput');
  if (btn) btn.disabled = show;
  if (inp) inp.disabled = show;
}

async function agentAsk(question) {
  if (!question?.trim()) return;
  agentAppendMessage(question, true);
  agentShowTyping(true);
  document.getElementById('agentSuggestions').style.display = 'none';

  // Add to conversation history
  if (!agentHistory.length) {
    agentHistory.push({ role: 'system', content: window._agentSystemPrompt || buildSystemPrompt('Context not loaded.') });
  }
  agentHistory.push({ role: 'user', content: question });

  try {
    const reply = await sendToGroq(question);
    agentHistory.push({ role: 'assistant', content: reply });
    agentShowTyping(false);
    agentAppendMessage(reply, false);
  } catch(e) {
    agentShowTyping(false);
    agentAppendMessage(`Error: ${e.message || 'Could not reach AI. Check your API key and internet connection.'}`, false);
  }
}

function agentSend() {
  const inp = document.getElementById('agentInput');
  if (!inp) return;
  const text = inp.value.trim();
  if (!text) return;
  inp.value = '';
  agentAsk(text);
}

function agentClear() {
  agentHistory = [];
  const msgs = document.getElementById('agentMessages');
  if (msgs) msgs.innerHTML = '';
  document.getElementById('agentSuggestions').style.display = 'flex';
  agentAppendMessage('Chat cleared. How can I help you?', false);
}

// Expose to global scope for inline onclick handlers
window.agentAsk  = agentAsk;
window.agentSend = agentSend;
window.agentClear = agentClear;
