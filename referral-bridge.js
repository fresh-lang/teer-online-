import { App } from '@capacitor/app';
const native = !!(window.Capacitor && typeof window.Capacitor.isNativePlatform === 'function' && window.Capacitor.isNativePlatform());
if (native) {
  const receive = url => {
    try {
      const parsed = new URL(url);
      const code = parsed.searchParams.get('ref') || parsed.searchParams.get('referral');
      if (!code) return;
      let attempts = 0;
      const apply = () => {
        attempts += 1;
        if (typeof window.__teerCaptureReferralCode !== 'function' && attempts < 40) {
          setTimeout(apply, 100);
          return;
        }
        if (typeof window.__teerCaptureReferralCode === 'function') window.__teerCaptureReferralCode(code);
        const modal = document.getElementById('authModal');
        if (modal) modal.classList.remove('hidden');
        if (typeof window.switchAuthTab === 'function') window.switchAuthTab('register');
      };
      apply();
    } catch (error) { console.warn('Referral deep link parse failed:', error); }
  };
  App.getLaunchUrl().then(result => { if (result && result.url) receive(result.url); }).catch(() => {});
  App.addListener('appUrlOpen', event => { if (event && event.url) receive(event.url); });
}
