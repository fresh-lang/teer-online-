import OneSignal from '@onesignal/capacitor-plugin';
import { Capacitor } from '@capacitor/core';

const APP_ID = '5c602eb8-04b1-4007-8edf-936fd353fcc1';
let initialization = null;

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

window.TeerOneSignalBridge = {
  async identify(userId) {
    if (!userId || !(await initialize())) return;
    try {
      await OneSignal.login(String(userId));
      const canPrompt = await OneSignal.Notifications.canRequestPermission();
      if (canPrompt) await OneSignal.Notifications.requestPermission(false);
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

void initialize();
