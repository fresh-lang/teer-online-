# Teer Online

Supabase-backed web app with a Capacitor Android build. The canonical Android workflow is `.github/workflows/android-debug.yml`; it requires the persistent `ANDROID_DEBUG_KEYSTORE_BASE64` GitHub Actions secret so successive APKs retain the same signing identity and can update an existing installation.

## Result timestamps

The app displays the source website's published/updated timestamp when the source provides a verifiable timestamp, separately from the app's own detection/save timestamp. Missing source timestamps are left blank rather than guessed. The Android app is built from the `main` branch by `.github/workflows/android-debug.yml`.
