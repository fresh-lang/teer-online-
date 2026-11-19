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

// Initialize on native app startup and request Android 13+ notification
// permission immediately, rather than waiting for the user to log in.
async function requestStartupPermission() {
  if (!(await initialize())) return false;
  if (!permissionRequest) {
    permissionRequest = (async () => {
      try {
        const hasPermission = await OneSignal.Notifications.hasPermission();
        if (hasPermission) return true;

        const canPrompt = await OneSignal.Notifications.canRequestPermission();
        if (!canPrompt) {
          console.info('OneSignal notification permission cannot be prompted again; user may enable it in Android settings.');
          return false;
        }

        return await OneSignal.Notifications.requestPermission(false);
      } catch (error) {
        console.warn('OneSignal notification permission request failed:', error);
        return false;
      }
    })();
  }
  return permissionRequest;
}

window.TeerOneSignalBridge = {
  async identify(userId) {
    if (!userId || !(await initialize())) return;
    try {
      await OneSignal.login(String(userId));
      // If startup happened before the bridge was ready, this safely retries
      // the same one-time permission request; it will not repeatedly prompt.
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
