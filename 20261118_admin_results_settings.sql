-- Admin access list plus public results and app settings for Supabase migration.
-- Existing account, wallet, bets, deposit and withdrawal tables are not modified.
create table if not exists public.admin_allowlist (
  phone text primary key check (phone ~ '^\d{10}$'),
  is_active boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.teer_results (
  market text primary key,
  fr text not null default '**' check (fr = '**' or fr ~ '^\d{1,2}$'),
  sr text not null default '**' check (sr = '**' or sr ~ '^\d{1,2}$'),
  result_date text,
  updated_at timestamptz not null default now(),
  updated_by uuid references public.app_users(id)
);

create table if not exists public.app_settings (
  id integer primary key check (id = 1),
  helpline text not null default '',
  deposit_upi text not null default '',
  marquee_text text not null default '',
  market_schedules jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now(),
  updated_by uuid references public.app_users(id)
);

insert into public.app_settings (id) values (1) on conflict (id) do nothing;

alter table public.admin_allowlist enable row level security;
alter table public.teer_results enable row level security;
alter table public.app_settings enable row level security;
-- Reads/writes are performed by the Edge Function using the service role key.
-- No anon/authenticated policies are intentionally added.
