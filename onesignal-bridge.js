import OneSignal from '@onesignal/capacitor-plugin';
import { Capacitor } from '@capacitor/core';

const APP_ID = '5c602eb8-04b1-4007-8edf-936fd353fcc1';
let initialization = null;
let permissionRequest = null;
let permissionPromptVisible = false;
let pushStateListenerRegistered = false;

function isNativeApp() {
  return Capacitor.isNativePlatform();
}

function registerPushStateListener() {
  if (pushStateListenerRegistered) return;
  try {
    OneSignal.User.pushSubscription.addEventListener('change', (event) => {
      const current = event && event.current ? event.current : {};
      console.info('OneSignal push subscription changed:', {
        hasSubscriptionId: Boolean(current.id),
        hasPushToken: Boolean(current.token),
        optedIn: Boolean(current.optedIn)
      });
    });
    pushStateListenerRegistered = true;
  } catch (error) {
    console.warn('OneSignal push subscription listener could not be registered:', error);
  }
}

async function readPushRegistrationStatus() {
  try {
    const subscription = OneSignal.User.pushSubscription;
    const [id, token, optedIn] = await Promise.all([
      subscription.getIdAsync(),
      subscription.getTokenAsync(),
      subscription.getOptedInAsync()
    ]);
    return { hasSubscriptionId: Boolean(id), hasPushToken: Boolean(token), optedIn: Boolean(optedIn) };
  } catch (error) {
    console.warn('OneSignal push registration status could not be read:', error);
    return { hasSubscriptionId: false, hasPushToken: false, optedIn: false };
  }
}

async function waitForPushRegistration(timeoutMs = 12000) {
  const deadline = Date.now() + timeoutMs;
  let status = await readPushRegistrationStatus();
  while ((!status.hasSubscriptionId || !status.hasPushToken || !status.optedIn) && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 750));
    status = await readPushRegistrationStatus();
  }
  return status;
}

async function showInAppPermissionPrompt() {
  if (!isNativeApp() || !document.body) return false;
  if (!(await initialize())) return false;

  try {
    if (await OneSignal.Notifications.hasPermission()) {
      try {
        await OneSignal.User.pushSubscription.optIn();
        const status = await waitForPushRegistration();
        console.info('OneSignal startup push registration:', status);
      } catch (error) {
        console.warn('OneSignal opt-in failed:', error);
      }
      document.getElementById('teerNotificationPermissionPrompt')?.remove();
      permissionPromptVisible = false;
      return true;
    }
  } catch (error) {
    console.warn('Could not read notification permission:', error);
  }

  if (permissionPromptVisible || document.getElementById('teerNotificationPermissionPrompt')) return false;
  permissionPromptVisible = true;

  const overlay = document.createElement('div');
  overlay.id = 'teerNotificationPermissionPrompt';
  overlay.style.cssText = 'position:fixed;inset:0;z-index:100000;background:rgba(0,0,0,.72);display:flex;align-items:center;justify-content:center;padding:22px;font-family:Arial,sans-serif;';
  overlay.innerHTML = `
    <div style="width:100%;max-width:360px;background:#fff;border-radius:18px;padding:22px;color:#123;box-shadow:0 18px 60px #0008">
      <div style="font-size:20px;font-weight:800;margin-bottom:8px;color:#063b3d">Allow Notifications</div>
      <div id="teerNotificationPermissionMessage" style="font-size:14px;line-height:1.55;color:#52616b;margin-bottom:18px">FR/SR result aur updates paane ke liye notifications allow karein.</div>
      <div style="display:flex;gap:10px;margin-top:18px">
        <button id="teerNotificationLater" type="button" style="flex:1;padding:12px;border:1px solid #cbd5d9;border-radius:10px;background:#fff;font-weight:700">Later</button>
        <button id="teerNotificationAllow" type="button" style="flex:1;padding:12px;border:0;border-radius:10px;background:#087d67;color:#fff;font-weight:800">Allow</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);

  const close = () => {
    overlay.remove();
    permissionPromptVisible = false;
  };
  overlay.querySelector('#teerNotificationLater').addEventListener('click', close);
  overlay.querySelector('#teerNotificationAllow').addEventListener('click', async () => {
    const allow = overlay.querySelector('#teerNotificationAllow');
    const later = overlay.querySelector('#teerNotificationLater');
    const message = overlay.querySelector('#teerNotificationPermissionMessage');
    allow.disabled = true;
    later.disabled = true;
    allow.textContent = 'Please wait…';
    try {
      let granted = await OneSignal.Notifications.hasPermission();
      if (!granted) {
        const canPrompt = await OneSignal.Notifications.canRequestPermission();
        if (!canPrompt) {
          message.textContent = 'Notifications ON karne ke liye Phone Settings > Apps > Teer Online > Notifications kholen.';
          const closeButton = allow.cloneNode(true);
          closeButton.textContent = 'Got it';
          closeButton.disabled = false;
          allow.replaceWith(closeButton);
          later.disabled = false;
          closeButton.addEventListener('click', close);
          return;
        }
        granted = await OneSignal.Notifications.requestPermission(false);
      }
      if (!granted) {
        message.textContent = 'Notification permission abhi allow nahi hui. Phone Settings mein Teer Online notifications ON karein.';
        allow.disabled = false;
        later.disabled = false;
        allow.textContent = 'Try Again';
        return;
      }

      await OneSignal.User.pushSubscription.optIn();
      const status = await waitForPushRegistration();
      console.info('OneSignal permission and push registration result:', status);
      if (status.hasSubscriptionId && status.hasPushToken && status.optedIn) {
        close();
        return;
      }

      message.textContent = 'Permission ON hai, lekin OneSignal push token abhi register nahi hua. Internet check karein; agar phir bhi na ho to Firebase FCM / OneSignal credentials verify karne honge.';
      allow.disabled = false;
      later.disabled = false;
      allow.textContent = 'Retry Registration';
    } catch (error) {
      console.warn('Notification permission action failed:', error);
      message.textContent = 'Notification setup complete nahi hua. Phone Settings > Apps > Teer Online > Notifications check karein aur dobara try karein.';
      allow.disabled = false;
      later.disabled = false;
      allow.textContent = 'Try Again';
    }
  });
  return false;
}

async function initialize() {
  if (!Capacitor.isNativePlatform()) return false;
  if (!initialization) {
    initialization = OneSignal.initialize(APP_ID).then(() => {
      registerPushStateListener();
      return true;
    }).catch((error) => {
      initialization = null;
      console.warn('OneSignal initialization failed:', error);
      return false;
    });
  }
  return initialization;
}

// Ask after the native screen has had time to become active. If Android
// cannot show the dialog yet, leave the request retryable after user login.
async function requestStartupPermission() {
  if (!(await initialize())) return false;
  if (!permissionRequest) {
    permissionRequest = (async () => {
      try {
        await new Promise((resolve) => setTimeout(resolve, 1500));
        const hasPermission = await OneSignal.Notifications.hasPermission();
        if (!hasPermission) {
          const canPrompt = await OneSignal.Notifications.canRequestPermission();
          if (!canPrompt) {
            console.info('Notification permission cannot be prompted again; enable it in Android app settings.');
            return false;
          }
          const granted = await OneSignal.Notifications.requestPermission(false);
          if (!granted) return false;
        }

        // Android permission and OneSignal subscription opt-in are separate states.
        // Ensure an already-permitted device is also opted in to push.
        await OneSignal.User.pushSubscription.optIn();
        return true;
      } catch (error) {
        console.warn('OneSignal notification permission request failed:', error);
        return false;
      }
    })().then((granted) => {
      // Do not cache a failed/early attempt. A later login tap can retry.
      if (!granted) permissionRequest = null;
      return granted;
    }).catch((error) => {
      permissionRequest = null;
      console.warn('OneSignal permission flow failed:', error);
      return false;
    });
  }
  return permissionRequest;
}

window.TeerOneSignalBridge = {
  async enableNotifications() {
    return await requestStartupPermission();
  },
  async identify(userId) {
    const externalId = String(userId == null ? '' : userId).trim();
    if (!externalId || !(await initialize())) return false;
    try {
      // Link this native installation to the authenticated Teer Online account.
      // The account-api returns the database UUID as user.id; never use the
      // display UID/phone number as the OneSignal external ID.
      await OneSignal.login(externalId);

      // Verify the SDK actually switched identities. login() resolving alone
      // is not enough to prove that the external_id alias is present.
      let confirmedExternalId = await OneSignal.User.getExternalId();
      if (confirmedExternalId !== externalId) {
        await new Promise((resolve) => setTimeout(resolve, 900));
        await OneSignal.login(externalId);
        confirmedExternalId = await OneSignal.User.getExternalId();
      }
      if (confirmedExternalId !== externalId) {
        console.warn('OneSignal external ID verification failed:', {
          expected: externalId,
          actual: confirmedExternalId
        });
        return false;
      }

      // Show our own reminder after account login whenever Android permission is off.
      // The Android system dialog is requested only after the user taps Allow.
      await showInAppPermissionPrompt();

      // Re-check identity; subscription is created after permission is granted.
      confirmedExternalId = await OneSignal.User.getExternalId();
      const subscriptionId = await OneSignal.User.pushSubscription.getIdAsync();
      console.info('OneSignal account identity check:', {
        externalIdMatches: confirmedExternalId === externalId,
        hasPushSubscription: Boolean(subscriptionId)
      });
      return confirmedExternalId === externalId;
    } catch (error) {
      console.warn('OneSignal user registration failed:', error);
      return false;
    }
  },
  async logout() {
    if (!(await initialize())) return;
    try { await OneSignal.logout(); }
    catch (error) { console.warn('OneSignal logout failed:', error); }
  }
};

// Re-check on every native app launch. If permission is off, show the in-app
// reminder; the Android system permission dialog appears only after Allow is tapped.
function showPromptWhenReady() {
  if (document.body) {
    setTimeout(() => { void showInAppPermissionPrompt(); }, 900);
  } else {
    document.addEventListener('DOMContentLoaded', () => {
      setTimeout(() => { void showInAppPermissionPrompt(); }, 900);
    }, { once: true });
  }
}
showPromptWhenReady();
