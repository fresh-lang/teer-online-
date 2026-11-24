-- Bank and UPI payout profiles are accessed only through the authenticated
-- account-api, which derives user_id from the server-side app session.
ALTER TABLE public.user_payout_profiles ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.user_payout_profiles FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.user_payout_profiles TO service_role;
