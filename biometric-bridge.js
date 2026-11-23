import { BiometricAuth } from '@aparajita/capacitor-biometric-auth';
import { Capacitor } from '@capacitor/core';

window.TeerBiometricBridge = {
  isNative: () => Capacitor.isNativePlatform(),
  check: () => BiometricAuth.checkBiometry(),
  authenticate: () => BiometricAuth.authenticate({
    reason: 'Unlock Teer Online',
    cancelTitle: 'Cancel',
    allowDeviceCredential: false,
    androidTitle: 'Unlock Teer Online',
    androidSubtitle: 'Use fingerprint or face',
    androidConfirmationRequired: false
  })
};
