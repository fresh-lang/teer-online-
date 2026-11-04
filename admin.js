// Master Admin Dashboard Script
let allBets = {};
let allUsers = {};
let activeMarkets = {};

document.addEventListener('DOMContentLoaded', () => {
  initRealtimeSync();
});

function initRealtimeSync() {
  // 1. Sync Markets
  db.ref('markets').on('value', (snap) => {
    activeMarkets = snap.val() || {};
    renderScheduleEditor();
  });

  // 2. Sync Bets for Risk Analytics
  db.ref('bets').on('value', (snap) => {
    allBets = snap.val() || {};
    loadRiskAnalytics();
  });

  // 3. Sync Users
  db.ref('users').on('value', (snap) => {
    allUsers = snap.val() || {};
    loadUsersList();
  });

  // 4. Sync Settings
  db.ref('settings').on('value', (snap) => {
    const s = snap.val() || {};
    document.getElementById('settingUpiId').value = s.upiId || 'teerpay@upi';
    document.getElementById('settingPayeeName').value = s.payeeName || 'Teer Online';
    document.getElementById('settingHelpline').value = s.helpline || '919876543210';
    document.getElementById('settingMarqueeText').value = s.marqueeText || '';
    document.getElementById('settingMarqueeActive').checked = s.marqueeActive !== false;
    updateAdminQrPreview(s.upiId, s.payeeName);
  });
}

// ---------------- LIVE RISK / BET ANALYTICS ---------------- //
function loadRiskAnalytics() {
  const market = document.getElementById('riskMarketSelect').value;
  const round = document.getElementById('riskRoundSelect').value;

  const gutiMatrix = {};
  for (let i = 0; i <= 99; i++) {
    const num = i < 10 ? '0' + i : '' + i;
    gutiMatrix[num] = { count: 0, totalAmount: 0 };
  }

  let totalPool = 0;
  let totalBetCount = 0;

  Object.values(allBets).forEach(b => {
    if (b.marketId === market && b.round === round) {
      totalPool += (parseFloat(b.amount) || 0);
      totalBetCount++;
      if (gutiMatrix[b.guti]) {
        gutiMatrix[b.guti].count++;
        gutiMatrix[b.guti].totalAmount += (parseFloat(b.amount) || 0);
      }
    }
  });

  // Sort Numbers by total wagered stake (Heaviest risk first)
  const sortedGutis = Object.entries(gutiMatrix).sort((a, b) => b[1].totalAmount - a[1].totalAmount);
  const highestBetGuti = sortedGutis[0];
  const maxLiability = highestBetGuti[1].totalAmount * 90;

  // Update KPI Cards
  document.getElementById('totalPoolDisplay').innerText = `₹${totalPool.toFixed(2)}`;
  document.getElementById('totalBetCount').innerText = `${totalBetCount} total bets placed`;
  document.getElementById('maxLiabilityDisplay').innerText = `₹${maxLiability.toFixed(2)}`;
  document.getElementById('topGutiDisplay').innerText = highestBetGuti[1].totalAmount > 0 ? highestBetGuti[0] : 'None';
  document.getElementById('topGutiStakeDisplay').innerText = `₹${highestBetGuti[1].totalAmount.toFixed(2)} wagered`;

  // Risk Badge Indicator
  const badge = document.getElementById('riskStatusBadge');
  if (maxLiability > totalPool && highestBetGuti[1].totalAmount > 0) {
    badge.innerHTML = `<span class="badge-risk"><i class="fas fa-triangle-exclamation me-1"></i>HIGH LIABILITY (Risk: -₹${(maxLiability - totalPool).toFixed(2)})</span>`;
  } else {
    badge.innerHTML = `<span class="badge-safe"><i class="fas fa-shield me-1"></i>HEALTHY POOL (Profitable)</span>`;
  }

  // Populate Matrix Table
  const tbody = document.getElementById('riskTableBody');
  tbody.innerHTML = '';

  sortedGutis.forEach(([num, data]) => {
    if (data.totalAmount === 0 && totalPool > 0) return; // Keep clean view
    const payout = data.totalAmount * 90;
    const margin = totalPool - payout;
    const isRisk = margin < 0 && data.totalAmount > 0;

    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><span class="badge bg-warning text-dark fs-6">${num}</span></td>
      <td>${data.count}</td>
      <td class="fw-bold">₹${data.totalAmount.toFixed(2)}</td>
      <td class="text-danger fw-bold">₹${payout.toFixed(2)}</td>
      <td class="${margin >= 0 ? 'text-success' : 'text-danger'} fw-bold">₹${margin.toFixed(2)}</td>
      <td>
        ${isRisk ? '<span class="badge-risk">CRITICAL RISK</span>' : (data.totalAmount > 0 ? '<span class="badge-safe">SAFE</span>' : '<span class="text-muted">No Bets</span>')}
      </td>
    `;
    tbody.appendChild(tr);
  });

  if (tbody.children.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="text-center text-muted py-4">No bets placed yet for ${market.toUpperCase()} - ${round}.</td></tr>`;
  }
}

// ---------------- MARKET SCHEDULE & CUTOFF TIMERS ---------------- //
function renderScheduleEditor() {
  const tbody = document.getElementById('scheduleTableBody');
  tbody.innerHTML = '';

  Object.entries(activeMarkets).forEach(([id, m]) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><b>${m.name}</b><br><small class="text-muted">${id}</small></td>
      <td><input type="time" id="frCut_${id}" class="form-control form-control-sm bg-dark text-white border-secondary" value="${m.frCutoff || '15:30'}"></td>
      <td><input type="time" id="frRes_${id}" class="form-control form-control-sm bg-dark text-white border-secondary" value="${m.frResult || '15:45'}"></td>
      <td><input type="time" id="srCut_${id}" class="form-control form-control-sm bg-dark text-white border-secondary" value="${m.srCutoff || '16:30'}"></td>
      <td><input type="time" id="srRes_${id}" class="form-control form-control-sm bg-dark text-white border-secondary" value="${m.srResult || '16:45'}"></td>
      <td>
        <div class="form-check form-switch">
          <input class="form-check-input" type="checkbox" id="status_${id}" ${m.active ? 'checked' : ''}>
        </div>
      </td>
      <td>
        <button class="btn btn-warning btn-sm fw-bold" onclick="saveMarketSchedule('${id}')">
          <i class="fas fa-save me-1"></i> Save
        </button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function saveMarketSchedule(marketId) {
  const frCut = document.getElementById(`frCut_${marketId}`).value;
  const frRes = document.getElementById(`frRes_${marketId}`).value;
  const srCut = document.getElementById(`srCut_${marketId}`).value;
  const srRes = document.getElementById(`srRes_${marketId}`).value;
  const isActive = document.getElementById(`status_${marketId}`).checked;

  db.ref('markets/' + marketId).update({
    frCutoff: frCut,
    frResult: frRes,
    srCutoff: srCut,
    srResult: srRes,
    active: isActive
  }).then(() => {
    alert(`Market "${marketId}" schedule updated and synced live!`);
  });
}

// ---------------- USER ACCOUNT CONTROLS ---------------- //
function loadUsersList() {
  const tbody = document.getElementById('userTableBody');
  tbody.innerHTML = '';

  Object.entries(allUsers).forEach(([uid, u]) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><code>${uid}</code><br><small class="text-muted">${u.phone || 'N/A'}</small></td>
      <td><b>${u.name || 'Anonymous'}</b></td>
      <td class="text-success fw-bold">₹${(u.balance || 0).toFixed(2)}</td>
      <td>
        ${u.isBlocked ? '<span class="badge bg-danger">BLOCKED</span>' : '<span class="badge bg-success">ACTIVE</span>'}
      </td>
      <td>
        <button class="btn ${u.isBlocked ? 'btn-success' : 'btn-danger'} btn-sm fw-bold" onclick="toggleUserBlock('${uid}', ${!u.isBlocked})">
          <i class="fas ${u.isBlocked ? 'fa-unlock' : 'fa-ban'} me-1"></i> ${u.isBlocked ? 'Unblock User' : 'Block User'}
        </button>
      </td>
      <td>
        <button class="btn btn-outline-warning btn-sm" onclick="openResetModal('${uid}')">
          <i class="fas fa-key me-1"></i> Reset PIN
        </button>
      </td>
    `;
    tbody.appendChild(tr);
  });

  if (tbody.children.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="text-center text-muted py-4">No users registered yet.</td></tr>`;
  }
}

function toggleUserBlock(uid, blockState) {
  db.ref('users/' + uid + '/isBlocked').set(blockState).then(() => {
    alert(`User ${uid} has been ${blockState ? 'BLOCKED' : 'UNBLOCKED'}!`);
  });
}

let activeResetUid = null;
function openResetModal(uid) {
  activeResetUid = uid;
  document.getElementById('resetTargetUid').innerText = uid;
  document.getElementById('newPasswordInput').value = '';
  const modal = new bootstrap.Modal(document.getElementById('pwdResetModal'));
  modal.show();
}

function confirmPasswordReset() {
  const newPwd = document.getElementById('newPasswordInput').value.trim();
  if (!newPwd || newPwd.length < 4) {
    alert('Please enter at least 4 characters for security code/password.');
    return;
  }
  db.ref('users/' + activeResetUid + '/password').set(newPwd).then(() => {
    alert(`Password for user ${activeResetUid} successfully reset to "${newPwd}"!`);
    bootstrap.Modal.getInstance(document.getElementById('pwdResetModal')).hide();
  });
}

// ---------------- UPI QR & HELPLINE SETTINGS ---------------- //
function updateAdminQrPreview(upi, name) {
  const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=250x250&data=upi://pay?pa=${upi || 'teerpay@upi'}%26pn=${encodeURIComponent(name || 'Teer Online')}%26cu=INR`;
  document.getElementById('adminQrPreview').src = qrUrl;
  document.getElementById('qrPayloadString').innerText = `upi://pay?pa=${upi}&pn=${name}&cu=INR`;
}

function saveUpiAndHelplineSettings() {
  const upi = document.getElementById('settingUpiId').value.trim();
  const name = document.getElementById('settingPayeeName').value.trim();
  const helpline = document.getElementById('settingHelpline').value.trim();

  if (!upi) {
    alert('Enter valid UPI ID!');
    return;
  }

  db.ref('settings').update({
    upiId: upi,
    payeeName: name,
    helpline: helpline
  }).then(() => {
    updateAdminQrPreview(upi, name);
    alert('UPI details and Helpline successfully updated and broadcast to user app!');
  });
}

// ---------------- NOTICE / MARQUEE TAB ---------------- //
function saveMarqueeSettings() {
  const text = document.getElementById('settingMarqueeText').value.trim();
  const active = document.getElementById('settingMarqueeActive').checked;

  db.ref('settings').update({
    marqueeText: text,
    marqueeActive: active
  }).then(() => {
    alert('Marquee notice broadcast updated live!');
  });
}
