  -- ScamCheck AI database schema
  -- Run this file in Supabase Dashboard > SQL Editor.

  create extension if not exists pgcrypto;

  create table if not exists public.users (
    id uuid primary key default gen_random_uuid(),
    email text not null unique,
    name text not null default 'User',
    password_hash text,
    provider text not null default 'email',
    role text not null default 'Standard User',
    status text not null default 'Active',
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint users_status_check check (status in ('Active', 'Suspended')),
    constraint users_role_check check (role in ('Admin', 'Security Analyst', 'Standard User'))
  );

  create table if not exists public.audit_logs (
    id text primary key,
    timestamp timestamptz not null default now(),
    ip text,
    device text,
    os text,
    browser text,
    method text,
    path text,
    user_email text,
    threat_type text,
    threat_level text,
    payload text,
    user_agent text,
    is_blocked boolean not null default false
  );

  create index if not exists audit_logs_timestamp_idx
    on public.audit_logs (timestamp desc);
  create index if not exists audit_logs_ip_idx
    on public.audit_logs (ip);

  create table if not exists public.blocked_ips (
    ip text primary key,
    created_at timestamptz not null default now()
  );

  create table if not exists public.password_resets (
    token_hash text primary key,
    user_email text not null references public.users(email) on delete cascade,
    expires_at timestamptz not null,
    used_at timestamptz,
    created_at timestamptz not null default now()
  );

  create index if not exists password_resets_expiry_idx
    on public.password_resets (expires_at);

  create table if not exists public.backups (
    id uuid primary key default gen_random_uuid(),
    filename text not null unique,
    storage_path text,
    payload jsonb,
    created_at timestamptz not null default now(),
    created_by text
  );
  alter table public.backups add column if not exists payload jsonb;

  create table if not exists public.scan_results (
    id uuid primary key default gen_random_uuid(),
    user_email text references public.users(email) on delete set null,
    scan_type text not null,
    input_text text,
    source_url text,
    file_name text,
    risk_score integer,
    risk_level text,
    recommendation text,
    result jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now()
  );
  create index if not exists scan_results_user_idx on public.scan_results (user_email);
  create index if not exists scan_results_created_idx on public.scan_results (created_at desc);

  create table if not exists public.oauth_identities (
    id uuid primary key default gen_random_uuid(),
    user_email text not null references public.users(email) on delete cascade,
    provider text not null,
    provider_user_id text not null,
    provider_email text,
    profile jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique (provider, provider_user_id)
  );

  create table if not exists public.login_attempts (
    id uuid primary key default gen_random_uuid(),
    email text,
    provider text not null default 'email',
    ip text,
    user_agent text,
    success boolean not null default false,
    failure_reason text,
    created_at timestamptz not null default now()
  );
  create index if not exists login_attempts_created_idx on public.login_attempts (created_at desc);
  create index if not exists login_attempts_email_idx on public.login_attempts (email);

  create table if not exists public.threat_events (
    id uuid primary key default gen_random_uuid(),
    event_type text not null,
    severity text not null,
    ip text,
    path text,
    payload text,
    source text not null default 'system',
    metadata jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now()
  );
  create index if not exists threat_events_created_idx on public.threat_events (created_at desc);

  create table if not exists public.vulnerability_scans (
    id uuid primary key default gen_random_uuid(),
    risk_score integer,
    status text not null default 'COMPLETED',
    findings jsonb not null default '[]'::jsonb,
    scanned_by text,
    created_at timestamptz not null default now()
  );

  create table if not exists public.maintenance_runs (
    id uuid primary key default gen_random_uuid(),
    action text not null,
    status text not null,
    details jsonb not null default '{}'::jsonb,
    started_by text,
    created_at timestamptz not null default now()
  );

  create table if not exists public.system_settings (
    setting_key text primary key,
    setting_value jsonb not null default '{}'::jsonb,
    updated_by text,
    updated_at timestamptz not null default now()
  );

  create table if not exists public.notifications (
    id uuid primary key default gen_random_uuid(),
    user_email text references public.users(email) on delete cascade,
    title text not null,
    message text not null,
    notification_type text not null default 'INFO',
    is_read boolean not null default false,
    created_at timestamptz not null default now()
  );
  create index if not exists notifications_user_idx on public.notifications (user_email, is_read);

  create table if not exists public.file_uploads (
    id uuid primary key default gen_random_uuid(),
    user_email text references public.users(email) on delete set null,
    original_name text not null,
    storage_path text,
    mime_type text,
    size_bytes bigint,
    ocr_text text,
    created_at timestamptz not null default now()
  );

  create or replace function public.set_updated_at()
  returns trigger
  language plpgsql
  as $$
  begin
    new.updated_at = now();
    return new;
  end;
  $$;

  drop trigger if exists users_set_updated_at on public.users;
  create trigger users_set_updated_at
  before update on public.users
  for each row execute function public.set_updated_at();

  alter table public.users enable row level security;
  alter table public.audit_logs enable row level security;
  alter table public.blocked_ips enable row level security;
  alter table public.password_resets enable row level security;
  alter table public.backups enable row level security;
  alter table public.scan_results enable row level security;
  alter table public.oauth_identities enable row level security;
  alter table public.login_attempts enable row level security;
  alter table public.threat_events enable row level security;
  alter table public.vulnerability_scans enable row level security;
  alter table public.maintenance_runs enable row level security;
  alter table public.system_settings enable row level security;
  alter table public.notifications enable row level security;
  alter table public.file_uploads enable row level security;

  -- The Flask backend uses the service-role key for server-side access.
  -- No public client policies are created here, so these tables remain private.
