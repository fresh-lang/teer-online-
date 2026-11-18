# Teer Online — Supabase-only source

## Backend
- Registration, login, custom sessions, wallet, bets, deposits and withdrawals use the `account-api` Edge Function.
- The browser does not persist account, session, wallet or bet state in localStorage. UI-only notices/preferences use an in-memory cache.
- Results and app settings are read from `teer_results` and `app_settings`; admin changes are authorized by `admin_allowlist`.
- Deposit approval and withdrawal review call server-side RPCs. Result publication settles bets server-side.
- Legacy Firebase SDK/database references and the old Firebase messaging worker are removed. Client-side random Teer Play results are disabled.

## Existing Supabase project
Project ref: `qzbqmbrzmfggzzeufkyh`

The production `account-api` Edge Function is already active at version 9 with `verify_jwt = false`. It uses the app's custom `x-session-token` and checks admin authorization itself. Existing bcrypt passwords are accepted and upgraded to PBKDF2 after a successful login.

The `admin_results_settings` migration is already applied to production. Do not rerun it blindly. The current schema contains `admin_allowlist`, `teer_results` and `app_settings`.

Ensure Edge Function secrets `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` remain configured. Never put the service-role key in web or Android assets. Keep the intended admin phone active in `public.admin_allowlist`; admin login uses the matching `app_users` account password.

## Android build
This repository includes Capacitor configuration and a GitHub Actions workflow. A push to `main` builds an installable debug APK and uploads it as the `teer-online-debug-apk` workflow artifact. The APK is not committed to source. A signed release APK/AAB requires a private signing keystore and GitHub Actions secrets.

## Not enabled yet
User block/unblock, admin password reset, manual wallet adjustment, broadcast notifications and referral commission payout remain disabled until dedicated secure server-side APIs and audited ledger operations are implemented. The Teer Play countdown is display-only; results must come from Supabase admin publication.

- Fabricated live-bet ticker and random demo-user feed are removed from the user app.
- Teer Play UI reads server minute-round IDs and published results from Supabase; each new Teer Play bet must include the active FR/SR round ID.
