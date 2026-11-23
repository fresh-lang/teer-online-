import { registerPlugin } from '@capacitor/core';

const NativeUpdater = registerPlugin('TeerAppUpdater');

window.TeerAppUpdater = {
  async downloadAndInstall(url, onProgress) {
    if (!url || !/^https:\/\//i.test(url) || !/github\.com/i.test(new URL(url).hostname)) {
      throw new Error('A valid official GitHub APK link is required.');
    }
    const listener = await NativeUpdater.addListener('downloadProgress', event => {
      if (typeof onProgress === 'function') onProgress(Number(event.percent || 0));
    });
    try {
      return await NativeUpdater.downloadAndInstall({ url });
    } finally {
      await listener.remove();
    }
  }
};
