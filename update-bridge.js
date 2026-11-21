import { Capacitor } from '@capacitor/core';
import { Directory, Filesystem } from '@capacitor/filesystem';
import { registerPlugin } from '@capacitor/core';

const ApkInstaller = registerPlugin('ApkInstaller');

let updateInProgress = false;

window.TeerAppUpdater = {
  async downloadAndInstall(url, onProgress = () => {}) {
    if (!Capacitor.isNativePlatform()) throw new Error('In-app APK installation is available only in the Android app.');
    if (updateInProgress) throw new Error('An update is already downloading.');
    updateInProgress = true;
    let listener = null;
    const path = 'teer-online-update.apk';
    try {
      try { await Filesystem.deleteFile({ path, directory: Directory.Cache }); } catch (_) {}
      listener = await Filesystem.addListener('progress', event => {
        if (!event.url || event.url.includes('teer-online')) {
          onProgress({ bytes: Number(event.bytes || 0), total: Number(event.contentLength || 0) });
        }
      });
      const result = await Filesystem.downloadFile({
        url,
        path,
        directory: Directory.Cache,
        progress: true,
        recursive: true
      });
      if (!result || !result.path) throw new Error('The APK download did not complete.');
      const info = await Filesystem.stat({ path, directory: Directory.Cache });
      if (!info || Number(info.size || 0) < 1000000) throw new Error('Downloaded APK file is incomplete. Please try again.');
      const file = await Filesystem.getUri({ path, directory: Directory.Cache });
      if (!file || !file.uri) throw new Error('Could not prepare the downloaded APK for Android installer.');
      await ApkInstaller.install({ fileUri: file.uri });
      return true;
    } finally {
      if (listener) {
        try { await listener.remove(); } catch (_) {}
      }
      updateInProgress = false;
    }
  }
};
