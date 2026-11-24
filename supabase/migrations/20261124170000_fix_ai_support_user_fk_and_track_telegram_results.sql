-- App users authenticate through public.app_users, not Supabase Auth.
alter table public.ai_support_daily_usage
  drop constraint if exists ai_support_daily_usage_user_id_fkey;

delete from public.ai_support_daily_usage u
where not exists (select 1 from public.app_users a where a.id = u.user_id);

alter table public.ai_support_daily_usage
  add constraint ai_support_daily_usage_user_id_fkey
  foreign key (user_id) references public.app_users(id) on delete cascade;

-- Track Telegram delivery independently from OneSignal push delivery.
alter table public.broadcast_notifications
  add column if not exists telegram_posted_at timestamptz,
  add column if not exists telegram_error text;

-- Do not replay old result notifications when the Telegram publisher is enabled.
update public.broadcast_notifications
set telegram_posted_at = coalesce(sent_at, created_at)
where telegram_posted_at is null
  and event_key ~ ':(FR|SR):[0-9]{1,2}$';
