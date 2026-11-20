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
        if (!hasPermission) {
          const canPrompt = await OneSignal.Notifications.canRequestPermission();
          if (!canPrompt) {
            console.info('Notification permission cannot be prompted again; enable it in Android app settings.');
            return false;
          }
          const granted = await OneSignal.Notifications.requestPermission(false);
          if (!granted) return false;
        }

        // Android permission can already be allowed while the OneSignal
        // push subscription is opted out. Explicitly opt the device back in.
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
      // Await login before opting in so the subscription is associated with the
      // same OneSignal user instead of remaining an anonymous device.
      await OneSignal.login(externalId);
      try {
        await OneSignal.User.pushSubscription.optIn();
      } catch (optInError) {
        console.warn('OneSignal push opt-in after login failed:', optInError);
      }
      // Retry permission/registration after the user identity has been linked.
      await requestStartupPermission();
      console.info('OneSignal account linked:', externalId);
      return true;
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
