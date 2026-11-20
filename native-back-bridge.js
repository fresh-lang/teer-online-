import { App } from '@capacitor/app';
import { Capacitor } from '@capacitor/core';

// Capture Android's hardware Back button before the WebView exits.
if (Capacitor.isNativePlatform()) {
  App.addListener('backButton', () => {
    window.dispatchEvent(new Event('teerNativeBack'));
  });
}

window.TeerNativeBackBridge = {
  async exitApp() {
    if (Capacitor.isNativePlatform()) {
      await App.exitApp();
    }
  }
};
