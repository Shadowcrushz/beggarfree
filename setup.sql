-- Paste this whole file in Supabase > SQL Editor > Run. Safe to run again if you already ran the old version.
create extension if not exists pgcrypto;

create table if not exists public.registrations (
  id uuid primary key default gen_random_uuid(),      -- this random id is what the QR contains
  name text not null check (length(name) between 2 and 80),
  dob date not null,
  phone text not null unique check (phone ~ '^[6-9][0-9]{9}$'),  -- one registration per number
  category text not null check (category in ('Student','Public')),
  org text not null check (length(org) between 2 and 120),
  created_at timestamptz default now(),                -- registration time
  checked_in boolean default false,
  checked_in_at timestamptz
);
create table if not exists public.login_attempts (phone text primary key, fails int default 0, last_fail timestamptz);
create table if not exists public.master_admins (user_id uuid primary key references auth.users(id) on delete cascade);

alter table public.registrations enable row level security;
alter table public.login_attempts enable row level security;
alter table public.master_admins enable row level security;

-- Normal admins can read and update (check-in). Only the master can delete (through reset functions).
drop policy if exists admin_all on public.registrations;
drop policy if exists admin_read on public.registrations;
create policy admin_read on public.registrations for select to authenticated using (true);

create or replace function public.register(p_name text, p_dob date, p_phone text, p_cat text, p_org text)
returns json language plpgsql security definer set search_path = public as $$
declare r registrations;
begin
  insert into registrations(name,dob,phone,category,org)
  values (trim(p_name), p_dob, p_phone, p_cat, trim(p_org)) returning * into r;
  return json_build_object('ok',true,'id',r.id,'name',r.name,'phone',r.phone,'org',r.org,'at',r.created_at);
exception
  when unique_violation then return json_build_object('ok',false,'error','ALREADY');
  when others then return json_build_object('ok',false,'error','INVALID');
end $$;

create or replace function public.my_qr(p_phone text, p_dob date)
returns json language plpgsql security definer set search_path = public as $$
declare r registrations; a login_attempts;
begin
  select * into a from login_attempts where phone = p_phone;
  if a.fails >= 5 and a.last_fail > now() - interval '15 minutes' then
    return json_build_object('ok',false,'error','LOCKED');
  end if;
  select * into r from registrations where phone = p_phone and dob = p_dob;
  if r.id is null then
    insert into login_attempts(phone,fails,last_fail) values (p_phone,1,now())
    on conflict (phone) do update set
      fails = case when login_attempts.last_fail < now() - interval '15 minutes' then 1 else login_attempts.fails + 1 end,
      last_fail = now();
    return json_build_object('ok',false,'error','NOTFOUND');
  end if;
  delete from login_attempts where phone = p_phone;
  return json_build_object('ok',true,'id',r.id,'name',r.name,'phone',r.phone,'org',r.org,'at',r.created_at);
end $$;

create or replace function public.check_in(p_id uuid)
returns json language plpgsql security definer set search_path = public as $$
declare r registrations;
begin
  if auth.uid() is null then return json_build_object('status','error'); end if;
  update registrations set checked_in = true, checked_in_at = now()
    where id = p_id and not checked_in returning * into r;
  if found then
    return json_build_object('status','valid','name',r.name,'phone',r.phone,'category',r.category,'org',r.org);
  end if;
  select * into r from registrations where id = p_id;
  if not found then return json_build_object('status','invalid'); end if;
  return json_build_object('status','already','name',r.name,'phone',r.phone,'at',r.checked_in_at);
end $$;

-- Master admin functions
create or replace function public.is_master() returns boolean
language sql security definer set search_path = public as
$$ select exists (select 1 from master_admins where user_id = auth.uid()) $$;

create or replace function public.reset_checkins() returns json
language plpgsql security definer set search_path = public as $$
begin
  if not is_master() then return json_build_object('ok',false); end if;
  update registrations set checked_in = false, checked_in_at = null where true;
  return json_build_object('ok',true);
end $$;

create or replace function public.reset_all() returns json
language plpgsql security definer set search_path = public as $$
begin
  if not is_master() then return json_build_object('ok',false); end if;
  delete from registrations where true;
  delete from login_attempts where true;
  return json_build_object('ok',true);
end $$;

revoke all on function public.check_in(uuid), public.is_master(), public.reset_checkins(), public.reset_all() from public, anon;
grant execute on function public.check_in(uuid), public.is_master(), public.reset_checkins(), public.reset_all() to authenticated;
grant execute on function public.register(text,date,text,text,text) to anon, authenticated;
grant execute on function public.my_qr(text,date) to anon, authenticated;

-- ===== AFTER running the above: create the master user in Authentication > Users, then run this one line
-- (change the email) in a new query:
-- insert into public.master_admins select id from auth.users where email = 'MASTER_EMAIL_HERE';
