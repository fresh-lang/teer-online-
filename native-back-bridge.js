import { App } from '@capacitor/app';
import { Capacitor } from '@capacitor/core';

// Capture Android's hardware Back button before the WebView exits.
if (Capacitor.isNativePlatform()) {
  App.addListener('backButton', ({ canGoBack }) => {
    // Always let the app's own tab stack decide whether to go back or show Exit/Stay.
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
