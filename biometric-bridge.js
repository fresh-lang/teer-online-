import { BiometricAuth } from '@aparajita/capacitor-biometric-auth';
import { Capacitor, registerPlugin } from '@capacitor/core';
import { App } from '@capacitor/app';

const TeerDeviceCredential = registerPlugin('TeerDeviceCredential');

window.TeerBiometricBridge = {
  isNative: () => Capacitor.isNativePlatform(),
  onAppStateChange: (callback) => App.addListener('appStateChange', ({ isActive }) => callback(isActive)),
  check: () => BiometricAuth.checkBiometry(),
  authenticateDeviceCredential: () => TeerDeviceCredential.authenticate(),
  authenticate: () => BiometricAuth.authenticate({
    reason: 'Unlock Teer Online',
    cancelTitle: 'Cancel',
    allowDeviceCredential: false,
    androidTitle: 'Unlock Teer Online',
    androidSubtitle: 'Use fingerprint',
    androidConfirmationRequired: false
  })
};
