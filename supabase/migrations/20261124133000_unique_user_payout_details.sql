-- Prevent the same payout destination from being registered by multiple app accounts.
-- UPI IDs are case-insensitive. Bank accounts are unique by account number + IFSC.
CREATE UNIQUE INDEX IF NOT EXISTS user_payout_profiles_upi_unique_idx
  ON public.user_payout_profiles (lower(btrim(upi_id)))
  WHERE nullif(btrim(upi_id), '') IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS user_payout_profiles_bank_account_ifsc_unique_idx
  ON public.user_payout_profiles (
    regexp_replace(bank_account_number, '[^0-9]', '', 'g'),
    upper(btrim(bank_ifsc))
  )
  WHERE nullif(btrim(bank_account_number), '') IS NOT NULL
    AND nullif(btrim(bank_ifsc), '') IS NOT NULL;
