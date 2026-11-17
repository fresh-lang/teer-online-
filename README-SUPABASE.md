# Teer Online — Supabase migration

## Existing backend
The app uses the existing Supabase Account API for registration, login, sessions, wallet balance, bet placement, deposits and withdrawals. The Edge Function source is `supabase/functions/account-api/index.ts`.

## Required database migration
Before using the migrated Admin Panel or live Results/Settings, run `supabase/migrations/20261118_admin_results_settings.sql` once in the Supabase SQL Editor. It creates only `teer_results` and `app_settings`; it does not alter existing users, wallets, bets, deposits or withdrawals.

## Deploy
1. Deploy the updated `account-api` Edge Function from `supabase/functions/account-api/index.ts`. Keep `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` configured as Edge Function secrets.
2. Add the admin account phone to `public.admin_allowlist` (replace the placeholder with the exact 10-digit phone used by the admin's `app_users` account):
   ```sql
   insert into public.admin_allowlist (phone, is_active)
   values ('YOUR_10_DIGIT_ADMIN_PHONE', true)
   on conflict (phone) do update set is_active = true;
   ```
   Admin login uses that app account's password; there is no hardcoded panel PIN.
3. Publish `index.html` and `admin.html` with the rest of the PWA assets.

## Admin behavior
- Admin authentication and authorization are checked by the Edge Function and `admin_allowlist`.
- Deposit approval/rejection and withdrawal approval/rejection call existing server-side RPCs. Wallet credits/refunds are not performed in browser code.
- Results are stored in `teer_results`; publishing numeric FR/SR results settles matching pending bets via `api_settle_bet`.
- Settings and market schedules are stored in `app_settings`.
- Client-side Firebase listeners and local persistence of authoritative account balances/bets/results have been disabled.

## Not yet implemented
Legacy user block/unblock, admin password reset, direct manual wallet adjustment, broadcast notifications, and agent commission reporting remain disabled until secure Supabase RPCs/tables are added. Do not use the old APK in this archive; rebuild the Android package from the updated web app after deployment and testing.
