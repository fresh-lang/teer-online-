-- Teer Play: bind every bet to its immutable FR/SR minute round and settle on the server.
-- Review and apply only after the matching account-api source is uploaded.
alter table public.bets
  add column if not exists round_id bigint
  references public.teer_minute_rounds(id) on delete restrict;

create index if not exists idx_bets_round_id_active
  on public.bets(round_id, status)
  where round_id is not null;

create unique index if not exists idx_bets_user_client_ref_unique
  on public.bets(user_id, client_ref);

create or replace function public.api_place_bet(
  p_user_id uuid,
  p_client_ref text,
  p_market text,
  p_round text,
  p_bet_mode text,
  p_bet_number text,
  p_amount numeric,
  p_round_id bigint
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_balance numeric;
  v_bet_id uuid;
  v_existing_id uuid;
  v_new_balance numeric;
  v_round public.teer_minute_rounds%rowtype;
begin
  if p_market <> 'Teer Play' then
    raise exception 'Round ID betting is only for Teer Play';
  end if;
  if p_user_id is null or p_client_ref is null or length(trim(p_client_ref)) < 8
     or p_round not in ('FR','SR') or p_bet_mode is null or trim(p_bet_mode) = ''
     or p_bet_number is null or trim(p_bet_number) = ''
     or p_amount is null or p_amount <= 0 or p_round_id is null then
    raise exception 'Invalid Teer Play bet details';
  end if;

  select * into v_round
  from public.teer_minute_rounds
  where id = p_round_id
  for update;

  if not found or v_round.result_type <> p_round
     or v_round.status <> 'open' or v_round.ends_at <= now() then
    raise exception 'Selected round is closed or does not match FR/SR';
  end if;

  select id into v_existing_id
  from public.bets
  where user_id = p_user_id and client_ref = p_client_ref;

  if found then
    select balance into v_balance from public.wallet_accounts where user_id = p_user_id;
    return jsonb_build_object('success',true,'duplicate',true,'bet_id',v_existing_id,'round_id',p_round_id,'balance',v_balance);
  end if;

  select balance into v_balance
  from public.wallet_accounts
  where user_id = p_user_id
  for update;

  if not found then raise exception 'Wallet not found'; end if;
  if v_balance < p_amount then raise exception 'Insufficient balance'; end if;

  update public.wallet_accounts
  set balance = balance - p_amount, updated_at = now()
  where user_id = p_user_id
  returning balance into v_new_balance;

  insert into public.bets(user_id,client_ref,market,round,round_id,bet_mode,bet_number,amount,status,payout)
  values(p_user_id,trim(p_client_ref),trim(p_market),p_round,p_round_id,trim(p_bet_mode),trim(p_bet_number),p_amount,'active',0)
  returning id into v_bet_id;

  insert into public.wallet_ledger(user_id,ref_type,ref_id,amount,direction,balance_after,description)
  values(p_user_id,'bet',p_client_ref,p_amount,'debit',v_new_balance,'Teer Play bet placed');

  insert into public.wallet_transactions(user_id,type,amount,status,description,ref_id)
  values(p_user_id,'bet',p_amount,'completed','Teer Play bet placed',v_bet_id);

  return jsonb_build_object('success',true,'duplicate',false,'bet_id',v_bet_id,'round_id',p_round_id,'balance',v_new_balance);
end;
$function$;

revoke all on function public.api_place_bet(uuid,text,text,text,text,text,numeric,bigint) from public, anon, authenticated;
grant execute on function public.api_place_bet(uuid,text,text,text,text,text,numeric,bigint) to service_role;

create or replace function public.process_teer_minute_rounds()
returns integer
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_now timestamptz := date_trunc('minute', now());
  v_round public.teer_minute_rounds%rowtype;
  v_bet record;
  v_result smallint;
  v_closed integer := 0;
begin
  insert into public.teer_minute_rounds(result_type,starts_at,ends_at,status)
  select t.result_type,t.start_at,t.start_at + interval '1 minute',
         case when t.start_at <= now() then 'open' else 'scheduled' end
  from (values
    ('FR'::text,v_now),('SR'::text,v_now),
    ('FR'::text,v_now + interval '1 minute'),('SR'::text,v_now + interval '1 minute')
  ) as t(result_type,start_at)
  on conflict (result_type,starts_at) do nothing;

  update public.teer_minute_rounds
  set status='open'
  where starts_at <= now() and ends_at > now() and status='scheduled';

  for v_round in
    select *
    from public.teer_minute_rounds
    where ends_at <= now() and status <> 'settled'
    order by ends_at,id
    for update skip locked
  loop
    v_result := coalesce(v_round.result_number,public.teer_secure_random_00_99());

    update public.teer_minute_rounds
    set result_number=v_result,
        result_source=coalesce(v_round.result_source,'auto'),
        status='settled',
        published_at=coalesce(v_round.published_at,now())
    where id=v_round.id;

    for v_bet in
      select id from public.bets
      where round_id=v_round.id and status='active'
      order by created_at,id
    loop
      perform public.api_settle_bet(v_bet.id,lpad(v_result::text,2,'0'));
    end loop;

    v_closed := v_closed + 1;
  end loop;

  return v_closed;
end;
$function$;


-- Mirror the one-time ₹10 registration credit into the user-visible transaction feed.
create or replace function public.api_register_user(
  p_name text,
  p_phone text,
  p_password_hash text,
  p_referred_by text default null
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_user_id uuid;
  v_uid bigint;
begin
  if p_name is null or length(trim(p_name)) < 2 then raise exception 'Invalid name'; end if;
  if p_phone is null or p_phone !~ '^[0-9]{10,15}$' then raise exception 'Invalid phone number'; end if;
  if p_password_hash is null or length(p_password_hash) < 40 then raise exception 'Invalid password hash'; end if;

  v_uid := nextval('public.app_uid_seq'::regclass);
  insert into public.app_users(uid,name,phone,password_hash,referred_by)
  values(v_uid,trim(p_name),p_phone,p_password_hash,p_referred_by)
  returning id into v_user_id;

  insert into public.wallet_accounts(user_id,balance) values(v_user_id,10);
  insert into public.wallet_ledger(user_id,ref_type,ref_id,amount,direction,balance_after,description)
  values(v_user_id,'welcome',v_user_id::text,10,'credit',10,'One-time registration bonus');

  insert into public.wallet_transactions(user_id,ref_id,type,amount,status,description)
  values(v_user_id,v_user_id,'bonus',10,'completed','One-time registration bonus');

  return jsonb_build_object('success',true,'user_id',v_user_id,'uid',v_uid,'registration_bonus',10);
end;
$function$;

revoke all on function public.api_register_user(text,text,text,text) from public, anon, authenticated;
grant execute on function public.api_register_user(text,text,text,text) to service_role;
