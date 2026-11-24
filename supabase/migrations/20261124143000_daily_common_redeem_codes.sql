-- Common daily redeem codes with atomic one-claim-per-user wallet credits.
create table if not exists public.redeem_code_settings (
  id boolean primary key default true check (id),
  daily_enabled boolean not null default true,
  daily_limit integer not null default 100 check (daily_limit in (100, 500)),
  updated_at timestamptz not null default now(),
  updated_by uuid
);
insert into public.redeem_code_settings(id) values (true) on conflict (id) do nothing;

create table if not exists public.redeem_codes (
  id uuid primary key default gen_random_uuid(),
  code text not null unique,
  max_redemptions integer not null check (max_redemptions in (100, 500)),
  redeemed_count integer not null default 0 check (redeemed_count >= 0 and redeemed_count <= max_redemptions),
  active boolean not null default true,
  source text not null check (source in ('daily', 'manual')),
  india_date date,
  created_by uuid,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  telegram_posted_at timestamptz,
  telegram_error text,
  push_sent_at timestamptz,
  push_error text
);
create unique index if not exists redeem_codes_one_daily_per_day
  on public.redeem_codes(india_date) where source = 'daily' and india_date is not null;
create index if not exists redeem_codes_active_created_idx
  on public.redeem_codes(active, created_at desc);

create table if not exists public.redeem_code_claims (
  id uuid primary key default gen_random_uuid(),
  code_id uuid not null references public.redeem_codes(id) on delete restrict,
  user_id uuid not null references public.app_users(id) on delete cascade,
  reward_amount numeric(10,2) not null check (reward_amount in (2, 3, 5, 10, 20)),
  created_at timestamptz not null default now(),
  unique(code_id, user_id)
);
create index if not exists redeem_code_claims_user_created_idx
  on public.redeem_code_claims(user_id, created_at desc);

alter table public.redeem_code_settings enable row level security;
alter table public.redeem_codes enable row level security;
alter table public.redeem_code_claims enable row level security;
revoke all on public.redeem_code_settings, public.redeem_codes, public.redeem_code_claims from public, anon, authenticated;
grant select, insert, update, delete on public.redeem_code_settings, public.redeem_codes, public.redeem_code_claims to service_role;

create or replace function public.api_create_redeem_code(
  p_limit integer,
  p_source text,
  p_india_date date default null,
  p_admin_id uuid default null
) returns public.redeem_codes
language plpgsql security definer set search_path = public
as $$
declare
  v_code text;
  v_row public.redeem_codes;
begin
  if p_limit not in (100, 500) or p_source not in ('daily', 'manual') then
    raise exception 'Invalid redeem code settings';
  end if;
  v_code := 'TEER' || to_char(coalesce(p_india_date, (now() at time zone 'Asia/Kolkata')::date), 'YYYYMMDD')
            || upper(substr(encode(gen_random_bytes(6), 'hex'), 1, 6));
  insert into public.redeem_codes(code, max_redemptions, source, india_date, created_by, expires_at)
  values (v_code, p_limit, p_source, p_india_date,
          p_admin_id,
          ((now() at time zone 'Asia/Kolkata')::date + 1)::timestamp at time zone 'Asia/Kolkata')
  returning * into v_row;

  insert into public.user_notifications(user_id, event_key, type, title, message)
  select u.id, 'redeem_code:' || v_row.id::text, 'redeem_code',
         '🎁 New Redeem Code Available',
         'Common redeem code: ' || v_row.code || '. Open Redeem Code in the menu and claim your random ₹2–₹20 reward. Limited to the first ' || p_limit || ' users.'
  from public.app_users u
  on conflict (user_id, event_key) do nothing;
  return v_row;
end;
$$;

create or replace function public.api_generate_daily_redeem_code()
returns public.redeem_codes
language plpgsql security definer set search_path = public
as $$
declare
  v_date date := (now() at time zone 'Asia/Kolkata')::date;
  v_settings public.redeem_code_settings;
  v_row public.redeem_codes;
begin
  perform pg_advisory_xact_lock(hashtext('teer-online-daily-redeem-code'));
  select * into v_settings from public.redeem_code_settings where id = true for update;
  if not found or not v_settings.daily_enabled then return null; end if;
  select * into v_row from public.redeem_codes
    where source = 'daily' and india_date = v_date limit 1;
  if found then return v_row; end if;
  return public.api_create_redeem_code(v_settings.daily_limit, 'daily', v_date, null);
end;
$$;

create or replace function public.api_claim_redeem_code(p_user_id uuid, p_code text)
returns jsonb
language plpgsql security definer set search_path = public
as $$
declare
  v_code public.redeem_codes;
  v_reward numeric(10,2);
  v_claim_id uuid;
  v_balance numeric(14,2);
begin
  if p_user_id is null or length(trim(coalesce(p_code, ''))) < 6 then
    raise exception 'Enter a valid redeem code';
  end if;
  select * into v_code from public.redeem_codes
    where code = upper(trim(p_code)) and active = true
    for update;
  if not found then raise exception 'Invalid or expired redeem code'; end if;
  if v_code.expires_at <= now() then raise exception 'This redeem code has expired'; end if;
  if exists (select 1 from public.redeem_code_claims where code_id = v_code.id and user_id = p_user_id) then
    raise exception 'You have already used this redeem code';
  end if;
  if v_code.redeemed_count >= v_code.max_redemptions then
    raise exception 'Redeem code user limit has been reached';
  end if;

  v_reward := case
    when random() < 0.25 then 2
    when random() < 0.333333 then 3
    when random() < 0.75 then 5
    when random() < 0.80 then 10
    else 20
  end;
  insert into public.redeem_code_claims(code_id, user_id, reward_amount)
    values (v_code.id, p_user_id, v_reward) returning id into v_claim_id;
  insert into public.wallet_accounts(user_id, balance)
    values (p_user_id, 0) on conflict (user_id) do nothing;
  update public.wallet_accounts
    set balance = balance + v_reward, updated_at = now()
    where user_id = p_user_id returning balance into v_balance;
  update public.redeem_codes set redeemed_count = redeemed_count + 1,
    active = (redeemed_count + 1 < max_redemptions)
    where id = v_code.id;
  insert into public.wallet_ledger(user_id, ref_type, ref_id, amount, direction, balance_after, description)
    values (p_user_id, 'bonus', v_claim_id::text, v_reward, 'credit', v_balance, 'Redeem code reward');
  insert into public.wallet_transactions(user_id, type, amount, status, description, ref_id)
    values (p_user_id, 'bonus', v_reward, 'completed', 'Redeem code reward', v_claim_id);
  insert into public.user_notifications(user_id, event_key, type, title, message)
    values (p_user_id, 'redeem_claim:' || v_claim_id::text, 'redeem_code',
            '🎉 Redeem Reward Credited', '₹' || v_reward::text || ' has been added to your wallet.')
    on conflict (user_id, event_key) do nothing;
  return jsonb_build_object('success', true, 'reward', v_reward, 'balance', v_balance, 'claim_id', v_claim_id);
end;
$$;

create or replace function public.api_set_redeem_code_settings(p_daily_enabled boolean, p_daily_limit integer, p_admin_id uuid)
returns public.redeem_code_settings
language plpgsql security definer set search_path = public
as $$
declare v_row public.redeem_code_settings;
begin
  if p_daily_limit not in (100, 500) then raise exception 'User limit must be 100 or 500'; end if;
  insert into public.redeem_code_settings(id, daily_enabled, daily_limit, updated_at, updated_by)
  values (true, p_daily_enabled, p_daily_limit, now(), p_admin_id)
  on conflict (id) do update set daily_enabled = excluded.daily_enabled,
    daily_limit = excluded.daily_limit, updated_at = now(), updated_by = excluded.updated_by
  returning * into v_row;
  return v_row;
end;
$$;

revoke all on function public.api_create_redeem_code(integer,text,date,uuid) from public, anon, authenticated;
revoke all on function public.api_generate_daily_redeem_code() from public, anon, authenticated;
revoke all on function public.api_claim_redeem_code(uuid,text) from public, anon, authenticated;
revoke all on function public.api_set_redeem_code_settings(boolean,integer,uuid) from public, anon, authenticated;
grant execute on function public.api_create_redeem_code(integer,text,date,uuid) to service_role;
grant execute on function public.api_generate_daily_redeem_code() to service_role;
grant execute on function public.api_claim_redeem_code(uuid,text) to service_role;
grant execute on function public.api_set_redeem_code_settings(boolean,integer,uuid) to service_role;
