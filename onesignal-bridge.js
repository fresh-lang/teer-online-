import OneSignal from '@onesignal/capacitor-plugin';
import { Capacitor } from '@capacitor/core';

const APP_ID = '5c602eb8-04b1-4007-8edf-936fd353fcc1';
let initialization = null;
let permissionRequest = null;

async function initialize() {
  if (!Capacitor.isNativePlatform()) return false;
  if (!initialization) {
    initialization = OneSignal.initialize(APP_ID).then(() => true).catch((error) => {
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
        // Restore the previous permission flow; do not force push opt-in.
        if (hasPermission) return true;

        const canPrompt = await OneSignal.Notifications.canRequestPermission();
        if (!canPrompt) {
          console.info('Notification permission cannot be prompted again; enable it in Android app settings.');
          return false;
        }
        return await OneSignal.Notifications.requestPermission(false);
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

      // Ask for permission/registration only after identity has been linked.
      await requestStartupPermission();

      // Re-check after the permission flow in case native startup was delayed.
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

void requestStartupPermission();
