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
    if (!userId || !(await initialize())) return;
    try {
      await OneSignal.login(String(userId));
      // Login/register is a user gesture, so retry the permission request here
      // if the initial startup attempt happened before Android was ready.
      void requestStartupPermission();
    } catch (error) {
      console.warn('OneSignal user registration failed:', error);
    }
  },
  async logout() {
    if (!(await initialize())) return;
    try { await OneSignal.logout(); }
    catch (error) { console.warn('OneSignal logout failed:', error); }
  }
};

void requestStartupPermission();
