-- Durable per-user notifications, including automatic bet refunds.
create table if not exists public.user_notifications (
 id uuid primary key default gen_random_uuid(),
 user_id uuid not null references public.app_users(id) on delete cascade,
 event_key text not null,
 type text not null default 'refund',
 title text not null,
 message text not null,
 created_at timestamptz not null default now(),
 read_at timestamptz,
 push_sent_at timestamptz,
 push_error text,
 constraint user_notifications_user_event_key unique(user_id,event_key)
);
create index if not exists user_notifications_user_created_idx on public.user_notifications(user_id,created_at desc);
create index if not exists user_notifications_pending_push_idx on public.user_notifications(created_at) where push_sent_at is null;
alter table public.user_notifications enable row level security;
revoke all on public.user_notifications from anon, authenticated;

create or replace function public.refund_unresolved_teer_bets(p_before_date date)
returns jsonb language plpgsql security definer set search_path to ''
as $function$
declare v_bet record; v_result text; v_new_balance numeric; v_refunded integer:=0; v_total numeric:=0;
begin
 if p_before_date is null or p_before_date >= (now() at time zone 'Asia/Kolkata')::date then raise exception 'Refund cutoff must be a past India date'; end if;
 for v_bet in
  select b.id,b.user_id,b.market,b.round,b.amount from public.bets b
  where b.status='active' and (b.created_at at time zone 'Asia/Kolkata')::date=p_before_date
   and b.market in ('Shilong Morning Teer','Khanapara Morning Teer','Shillong Teer (Evening)','Khanapara Teer (Evening)','Shillong Night Teer','Khanapara Night Teer')
   and upper(b.round) in ('FR','SR') order by b.created_at,b.id for update of b skip locked
 loop
  select case when upper(v_bet.round)='FR' then tr.fr else tr.sr end into v_result from public.teer_results tr
  where tr.market=v_bet.market and (
   case when tr.result_date ~ '^[0-9]{2}/[0-9]{2}/[0-9]{4}$' then to_date(tr.result_date,'DD/MM/YYYY')
    when tr.result_date ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' then tr.result_date::date else null end
  )=p_before_date limit 1;
  if v_result is not null and v_result ~ '^[0-9]{2}$' then continue; end if;
  update public.wallet_accounts set balance=balance+v_bet.amount,updated_at=now() where user_id=v_bet.user_id returning balance into v_new_balance;
  if not found then raise exception 'Wallet not found for bet %',v_bet.id; end if;
  update public.bets set status='refunded',payout=v_bet.amount,settled_at=now() where id=v_bet.id and status='active';
  if not found then raise exception 'Bet status changed during refund %',v_bet.id; end if;
  insert into public.wallet_ledger(user_id,ref_type,ref_id,amount,direction,balance_after,description)
   values(v_bet.user_id,'refund',v_bet.id::text,v_bet.amount,'credit',v_new_balance,'Refund: result not published for market and date');
  insert into public.wallet_transactions(user_id,type,amount,status,description,ref_id)
   values(v_bet.user_id,'refund',v_bet.amount,'completed','Bet refunded because result was not published for that date',v_bet.id);
  insert into public.user_notifications(user_id,event_key,type,title,message)
   values(v_bet.user_id,'bet_refund:'||v_bet.id::text,'refund','Bet Refund Successful',
    to_char(p_before_date,'DD Mon YYYY')||' '||v_bet.market||' '||upper(v_bet.round)||' bet refund of ₹'||to_char(v_bet.amount,'FM999999990.00')||' has been credited to your wallet.')
   on conflict(user_id,event_key) do nothing;
  v_refunded:=v_refunded+1; v_total:=v_total+v_bet.amount;
 end loop;
 return jsonb_build_object('success',true,'date',p_before_date,'refunded_bets',v_refunded,'refunded_amount',v_total);
end;
$function$;
