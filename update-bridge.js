import { Browser } from '@capacitor/browser';

// Open the official APK download in the Android browser. The app deliberately
// does not request REQUEST_INSTALL_PACKAGES or install APKs itself.
window.TeerAppUpdater = {
  async openDownloadPage(url) {
    if (!url || !/^https:\/\//i.test(url)) {
      throw new Error('A secure APK download link is required.');
    }
    await Browser.open({ url });
    return true;
  }
};
