-- One-time ₹10 social-channel visit bonus.
-- The claim and wallet credit are committed atomically by the SECURITY DEFINER RPC.
CREATE TABLE IF NOT EXISTS public.social_follow_bonus_claims (
  user_id uuid PRIMARY KEY REFERENCES public.app_users(id) ON DELETE CASCADE,
  id uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
  amount numeric NOT NULL DEFAULT 10 CHECK (amount = 10),
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.social_follow_bonus_claims ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.social_follow_bonus_claims FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.social_follow_bonus_claims TO service_role;

CREATE OR REPLACE FUNCTION public.api_claim_social_follow_bonus(p_user_id uuid)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO ''
AS $function$
DECLARE
  v_balance numeric;
  v_new_balance numeric;
  v_claim_id uuid;
BEGIN
  IF p_user_id IS NULL THEN
    RAISE EXCEPTION 'A valid user is required';
  END IF;

  SELECT balance INTO v_balance
  FROM public.wallet_accounts
  WHERE user_id = p_user_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Wallet not found';
  END IF;

  INSERT INTO public.social_follow_bonus_claims (user_id)
  VALUES (p_user_id)
  ON CONFLICT (user_id) DO NOTHING
  RETURNING id INTO v_claim_id;

  IF v_claim_id IS NULL THEN
    RETURN jsonb_build_object(
      'success', true,
      'already_claimed', true,
      'amount', 0,
      'balance', v_balance
    );
  END IF;

  v_new_balance := v_balance + 10;

  UPDATE public.wallet_accounts
  SET balance = v_new_balance, updated_at = now()
  WHERE user_id = p_user_id;

  INSERT INTO public.wallet_ledger (
    user_id, ref_type, ref_id, amount, direction, balance_after, description
  ) VALUES (
    p_user_id, 'bonus', v_claim_id::text, 10, 'credit', v_new_balance,
    'One-time Telegram and Facebook visit bonus'
  );

  INSERT INTO public.wallet_transactions (
    user_id, ref_id, type, amount, status, description
  ) VALUES (
    p_user_id, v_claim_id, 'bonus', 10, 'completed',
    'One-time Telegram and Facebook visit bonus'
  );

  RETURN jsonb_build_object(
    'success', true,
    'already_claimed', false,
    'amount', 10,
    'balance', v_new_balance
  );
END;
$function$;

REVOKE ALL ON FUNCTION public.api_claim_social_follow_bonus(uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.api_claim_social_follow_bonus(uuid) TO service_role;
