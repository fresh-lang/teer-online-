// User application client script
let currentUser = null;
let selectedGuti = null;
let currentMarketId = null;
let currentRound = null;
let appSettings = {};
let markets = {};

// Initialize listeners
document.addEventListener('DOMContentLoaded', () => {
  initGutiPicker();
  listenSettings();
  listenMarkets();
  initMockAuth();
});

// Setup 00-99 Picker Grid
function initGutiPicker() {
  const container = document.getElementById('gutiPickerGrid');
  if (!container) return;
  container.innerHTML = '';
  for (let i = 0; i <= 99; i++) {
    const formatted = i < 10 ? '0' + i : '' + i;
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'guti-btn';
    btn.innerText = formatted;
    btn.onclick = () => selectGuti(formatted, btn);
    container.appendChild(btn);
  }
}

function selectGuti(num, element) {
  document.querySelectorAll('.guti-btn').forEach(b => b.classList.remove('active'));
  element.classList.add('active');
  selectedGuti = num;
  document.getElementById('selectedGutiDisplay').innerText = num;
  calculateExpectedPayout();
}

function calculateExpectedPayout() {
  const amt = parseFloat(document.getElementById('betAmountInput').value) || 0;
  document.getElementById('expectedPayout').innerText = (amt * 90).toFixed(2);
}

// Listen to Settings: UPI, Helpline, Marquee
function listenSettings() {
  db.ref('settings').on('value', (snap) => {
    appSettings = snap.val() || {
      upiId: 'teerpay@upi',
      payeeName: 'Teer Online Official',
      helpline: '919876543210',
      marqueeText: 'Welcome to Teer Online! Live Betting active for FR & SR.',
      marqueeActive: true
    };
    renderMarquee();
    updateQrCode();
  });
}

function renderMarquee() {
  const wrapper = document.getElementById('marqueeWrapper');
  const textElem = document.getElementById('marqueeText');
  if (appSettings.marqueeActive && appSettings.marqueeText) {
    wrapper.style.display = 'flex';
    textElem.innerText = appSettings.marqueeText;
  } else {
    wrapper.style.display = 'none';
  }
}

function updateQrCode() {
  const upi = appSettings.upiId || 'teerpay@upi';
  const name = encodeURIComponent(appSettings.payeeName || 'Teer Online');
  const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=250x250&data=upi://pay?pa=${upi}%26pn=${name}%26cu=INR`;
  
  const qrImg = document.getElementById('dynamicQrImage');
  if (qrImg) qrImg.src = qrUrl;

  const upiDisp = document.getElementById('upiIdDisplay');
  if (upiDisp) upiDisp.value = upi;

  const hlBtn = document.getElementById('helplineBtn');
  const blkHl = document.getElementById('blockHelplineBtn');
  const hlLink = `https://wa.me/${appSettings.helpline || '919876543210'}?text=Hello%20Support`;
  if (hlBtn) hlBtn.href = hlLink;
  if (blkHl) blkHl.href = hlLink;
}

function copyUpi() {
  const upi = document.getElementById('upiIdDisplay').value;
  navigator.clipboard.writeText(upi);
  alert('UPI ID copied: ' + upi);
}

// Listen to Markets & Timers
function listenMarkets() {
  db.ref('markets').on('value', (snap) => {
    markets = snap.val();
    if (!markets) {
      // Default initial seeds if database is empty
      markets = {
        shillong: { name: 'Shillong Teer', frCutoff: '15:30', frResult: '15:45', srCutoff: '16:30', srResult: '16:45', active: true },
        khanapara: { name: 'Khanapara Teer', frCutoff: '15:55', frResult: '16:15', srCutoff: '16:25', srResult: '16:45', active: true },
        juwai: { name: 'Juwai Teer', frCutoff: '14:00', frResult: '14:15', srCutoff: '15:00', srResult: '15:15', active: true }
      };
      db.ref('markets').set(markets);
    }
    renderMarkets();
  });
}

function renderMarkets() {
  const container = document.getElementById('marketsContainer');
  container.innerHTML = '';

  Object.entries(markets).forEach(([id, m]) => {
    const card = document.createElement('div');
    card.className = 'market-card';
    card.innerHTML = `
      <div class="d-flex justify-content-between align-items-center mb-2">
        <h5 class="fw-bold mb-0 text-warning">${m.name}</h5>
        <span class="market-badge ${m.active ? 'bg-success text-white' : 'bg-danger text-white'}">${m.active ? 'LIVE' : 'CLOSED'}</span>
      </div>
      
      <div class="row g-2 mt-1">
        <div class="col-6">
          <div class="round-pill">
            <div class="fw-bold text-light">FR Round</div>
            <div class="small text-secondary">Cutoff: ${m.frCutoff}</div>
            <div class="timer-display my-1" id="timer-${id}-FR">--:--:--</div>
            <button class="btn btn-warning btn-sm w-100 fw-bold mt-1" id="btn-${id}-FR" onclick="openBetModal('${id}', '${m.name}', 'FR')">
              <i class="fas fa-crosshairs me-1"></i> Play FR
            </button>
          </div>
        </div>
        <div class="col-6">
          <div class="round-pill">
            <div class="fw-bold text-light">SR Round</div>
            <div class="small text-secondary">Cutoff: ${m.srCutoff}</div>
            <div class="timer-display my-1" id="timer-${id}-SR">--:--:--</div>
            <button class="btn btn-warning btn-sm w-100 fw-bold mt-1" id="btn-${id}-SR" onclick="openBetModal('${id}', '${m.name}', 'SR')">
              <i class="fas fa-crosshairs me-1"></i> Play SR
            </button>
          </div>
        </div>
      </div>
    `;
    container.appendChild(card);
  });

  updateCutoffCountdowns();
}

// Cutoff countdown timer updater loop
setInterval(updateCutoffCountdowns, 1000);

function updateCutoffCountdowns() {
  if (!markets) return;
  const now = new Date();

  Object.entries(markets).forEach(([id, m]) => {
    ['FR', 'SR'].forEach(round => {
      const cutoffStr = round === 'FR' ? m.frCutoff : m.srCutoff;
      const timerElem = document.getElementById(`timer-${id}-${round}`);
      const btnElem = document.getElementById(`btn-${id}-${round}`);
      if (!timerElem || !cutoffStr) return;

      const [hours, minutes] = cutoffStr.split(':').map(Number);
      const target = new Date();
      target.setHours(hours, minutes, 0, 0);

      const diff = target - now;
      if (diff > 0) {
        const hrs = Math.floor(diff / (1000 * 60 * 60));
        const mins = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
        const secs = Math.floor((diff % (1000 * 60)) / 1000);
        timerElem.innerText = `${pad(hrs)}:${pad(mins)}:${pad(secs)}`;
        if (btnElem) {
          btnElem.disabled = false;
          btnElem.innerHTML = `<i class="fas fa-crosshairs me-1"></i> Play ${round}`;
        }
      } else {
        timerElem.innerText = "CLOSED";
        timerElem.style.color = "#ef4444";
        if (btnElem) {
          btnElem.disabled = true;
          btnElem.innerHTML = `<i class="fas fa-lock me-1"></i> Closed`;
        }
      }
    });
  });
}

function pad(n) { return n < 10 ? '0' + n : n; }

// Auth & User State
function initMockAuth() {
  // Demo mock user or Firebase Auth listener
  const storedUid = localStorage.getItem('teer_demo_uid') || 'USR_' + Math.floor(100000 + Math.random() * 900000);
  localStorage.setItem('teer_demo_uid', storedUid);

  db.ref('users/' + storedUid).on('value', (snap) => {
    let data = snap.val();
    if (!data) {
      data = {
        name: 'Player ' + storedUid.slice(-4),
        phone: '987654' + storedUid.slice(-4),
        balance: 500,
        isBlocked: false,
        password: 'password123'
      };
      db.ref('users/' + storedUid).set(data);
    }
    currentUser = { uid: storedUid, ...data };
    document.getElementById('userDisplayName').innerText = currentUser.name;
    document.getElementById('userBalance').innerText = (currentUser.balance || 0).toFixed(2);

    // Account block check
    const blockScreen = document.getElementById('blockedScreen');
    if (currentUser.isBlocked) {
      blockScreen.style.display = 'flex';
    } else {
      blockScreen.style.display = 'none';
    }
  });
}

function openBetModal(marketId, marketName, round) {
  currentMarketId = marketId;
  currentRound = round;
  document.getElementById('betMarketTitle').innerText = marketName;
  document.getElementById('betRoundTitle').innerText = `Round: ${round}`;
  const modal = new bootstrap.Modal(document.getElementById('betModal'));
  modal.show();
}

function openDepositModal() {
  const modal = new bootstrap.Modal(document.getElementById('depositModal'));
  modal.show();
}

function placeBet() {
  if (!selectedGuti) {
    alert('Please select a number (00-99) first!');
    return;
  }
  const amt = parseFloat(document.getElementById('betAmountInput').value);
  if (!amt || amt <= 0) {
    alert('Please enter valid amount!');
    return;
  }
  if (currentUser.balance < amt) {
    alert('Insufficient balance! Please add funds.');
    return;
  }

  // Deduct balance
  const newBal = currentUser.balance - amt;
  db.ref('users/' + currentUser.uid + '/balance').set(newBal);

  // Push Bet to Realtime DB
  const betKey = db.ref('bets').push().key;
  const betRecord = {
    id: betKey,
    uid: currentUser.uid,
    userName: currentUser.name,
    marketId: currentMarketId,
    round: currentRound,
    guti: selectedGuti,
    amount: amt,
    potentialWin: amt * 90,
    timestamp: Date.now()
  };
  db.ref('bets/' + betKey).set(betRecord);

  alert(`Bet of ₹${amt} placed successfully on [${selectedGuti}]!`);
  bootstrap.Modal.getInstance(document.getElementById('betModal')).hide();
}

function submitDepositRequest() {
  const utr = document.getElementById('depositUtrInput').value.trim();
  const amt = parseFloat(document.getElementById('depositAmountInput').value);
  if (!utr || utr.length < 6) {
    alert('Enter valid 12-digit UTR transaction reference!');
    return;
  }
  if (!amt || amt <= 0) {
    alert('Enter valid deposit amount!');
    return;
  }
  db.ref('deposits').push({
    uid: currentUser.uid,
    userName: currentUser.name,
    amount: amt,
    utr: utr,
    status: 'PENDING',
    timestamp: Date.now()
  });
  alert('Deposit request submitted! Admin will approve balance shortly.');
  bootstrap.Modal.getInstance(document.getElementById('depositModal')).hide();
}
