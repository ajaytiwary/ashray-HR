-- ASHRAY HR & Payroll — Supabase schema
-- Run once in Supabase SQL Editor. Review before production use.

create extension if not exists pgcrypto;

create table if not exists public.organizations (
  id uuid primary key default gen_random_uuid(),
  code text not null unique,
  name text not null,
  created_at timestamptz not null default now()
);

insert into public.organizations(code,name)
values ('ASHRAY','South Vihar Welfare Society for Tribal')
on conflict (code) do nothing;

create table if not exists public.sites (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations(id) on delete cascade,
  code text not null,
  name text not null,
  address text,
  active boolean not null default true,
  created_at timestamptz not null default now(),
  unique(org_id,code)
);

-- Temporary labels: replace with the five actual project/office names.
insert into public.sites(org_id,code,name)
select o.id, v.code, v.name
from public.organizations o
cross join (values
 ('SITE-01','Ranchi'),
 ('SITE-02','Project 2 - Name Pending'),
 ('SITE-03','Project 3 - Name Pending'),
 ('SITE-04','Project 4 - Name Pending'),
 ('SITE-05','Project 5 - Name Pending')
) as v(code,name)
where o.code='ASHRAY'
on conflict (org_id,code) do nothing;

create table if not exists public.user_profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  org_id uuid not null references public.organizations(id) on delete cascade,
  site_id uuid references public.sites(id) on delete set null,
  role text not null check (role in ('super_admin','hr','manager','employee')),
  full_name text not null,
  active boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.employees (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations(id) on delete cascade,
  site_id uuid not null references public.sites(id),
  user_id uuid unique references auth.users(id) on delete set null,
  employee_code text not null,
  full_name text not null,
  phone text,
  email text,
  department text,
  designation text,
  joining_date date,
  employment_status text not null default 'active' check (employment_status in ('active','inactive','exited')),
  monthly_salary numeric(12,2) not null default 0 check (monthly_salary >= 0),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(org_id,employee_code)
);

create table if not exists public.attendance (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations(id) on delete cascade,
  site_id uuid not null references public.sites(id),
  employee_id uuid not null references public.employees(id) on delete cascade,
  attendance_date date not null,
  status text not null check (status in ('present','absent','half_day','weekly_off','holiday','leave')),
  check_in timestamptz,
  check_out timestamptz,
  note text,
  marked_by uuid references auth.users(id),
  created_at timestamptz not null default now(),
  unique(employee_id,attendance_date)
);

create table if not exists public.leave_requests (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations(id) on delete cascade,
  site_id uuid not null references public.sites(id),
  employee_id uuid not null references public.employees(id) on delete cascade,
  leave_type text not null check (leave_type in ('casual','sick','earned','unpaid','other')),
  start_date date not null,
  end_date date not null,
  days numeric(5,2) not null check (days > 0),
  reason text,
  status text not null default 'pending' check (status in ('pending','approved','rejected','cancelled')),
  reviewed_by uuid references auth.users(id),
  reviewed_at timestamptz,
  created_at timestamptz not null default now(),
  check (end_date >= start_date)
);

create table if not exists public.payroll_runs (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations(id) on delete cascade,
  site_id uuid references public.sites(id),
  payroll_month date not null,
  status text not null default 'draft' check (status in ('draft','reviewed','approved','paid')),
  created_by uuid references auth.users(id),
  approved_by uuid references auth.users(id),
  created_at timestamptz not null default now(),
  unique(org_id,site_id,payroll_month)
);

create table if not exists public.payslips (
  id uuid primary key default gen_random_uuid(),
  payroll_run_id uuid not null references public.payroll_runs(id) on delete cascade,
  org_id uuid not null references public.organizations(id) on delete cascade,
  site_id uuid not null references public.sites(id),
  employee_id uuid not null references public.employees(id) on delete cascade,
  paid_days numeric(6,2) not null default 0,
  earnings jsonb not null default '{}'::jsonb,
  deductions jsonb not null default '{}'::jsonb,
  gross_pay numeric(12,2) not null default 0,
  net_pay numeric(12,2) not null default 0,
  created_at timestamptz not null default now(),
  unique(payroll_run_id,employee_id)
);

create table if not exists public.audit_logs (
  id bigint generated always as identity primary key,
  org_id uuid not null references public.organizations(id) on delete cascade,
  actor uuid references auth.users(id),
  action text not null,
  table_name text not null,
  record_id text,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists employees_site_idx on public.employees(org_id,site_id);
create index if not exists attendance_date_idx on public.attendance(org_id,attendance_date);
create index if not exists leave_site_idx on public.leave_requests(org_id,site_id,status);
create index if not exists payslips_employee_idx on public.payslips(employee_id);

-- Helper functions use SECURITY DEFINER to read the signed-in user's own profile
-- without causing recursive RLS evaluation. They expose only boolean scope checks.
create or replace function public.my_org_id()
returns uuid language sql stable security definer set search_path=public
as $$ select org_id from public.user_profiles where user_id=auth.uid() and active=true limit 1 $$;

create or replace function public.my_role()
returns text language sql stable security definer set search_path=public
as $$ select role from public.user_profiles where user_id=auth.uid() and active=true limit 1 $$;

create or replace function public.my_site_id()
returns uuid language sql stable security definer set search_path=public
as $$ select site_id from public.user_profiles where user_id=auth.uid() and active=true limit 1 $$;

create or replace function public.is_org_admin()
returns boolean language sql stable security definer set search_path=public
as $$ select coalesce(public.my_role() in ('super_admin','hr'),false) $$;

create or replace function public.can_access_site(target_site uuid)
returns boolean language sql stable security definer set search_path=public
as $$ select coalesce(public.my_role() in ('super_admin','hr') or (public.my_role()='manager' and public.my_site_id()=target_site),false) $$;

alter table public.organizations enable row level security;
alter table public.sites enable row level security;
alter table public.user_profiles enable row level security;
alter table public.employees enable row level security;
alter table public.attendance enable row level security;
alter table public.leave_requests enable row level security;
alter table public.payroll_runs enable row level security;
alter table public.payslips enable row level security;
alter table public.audit_logs enable row level security;

-- Organisations and sites
create policy "org members read own org" on public.organizations for select
using (id=public.my_org_id());
create policy "members read sites in own org" on public.sites for select
using (org_id=public.my_org_id());
create policy "admins manage sites" on public.sites for all
using (org_id=public.my_org_id() and public.is_org_admin())
with check (org_id=public.my_org_id() and public.is_org_admin());

-- User profiles: user can read self; admins read/manage organisation profiles.
create policy "read own profile or admin" on public.user_profiles for select
using (user_id=auth.uid() or (org_id=public.my_org_id() and public.is_org_admin()));
create policy "admins manage profiles" on public.user_profiles for all
using (org_id=public.my_org_id() and public.is_org_admin())
with check (org_id=public.my_org_id() and public.is_org_admin());

-- Employees: admin/HR all; manager own site; employee own linked record.
create policy "read scoped employees" on public.employees for select
using (org_id=public.my_org_id() and (
 public.is_org_admin() or public.can_access_site(site_id) or user_id=auth.uid()
));
create policy "admins and site managers insert employees" on public.employees for insert
with check (org_id=public.my_org_id() and (public.is_org_admin() or public.can_access_site(site_id)));
create policy "admins and site managers update employees" on public.employees for update
using (org_id=public.my_org_id() and (public.is_org_admin() or public.can_access_site(site_id)))
with check (org_id=public.my_org_id() and (public.is_org_admin() or public.can_access_site(site_id)));
create policy "admins delete employees" on public.employees for delete
using (org_id=public.my_org_id() and public.is_org_admin());

-- Attendance
create policy "read scoped attendance" on public.attendance for select
using (org_id=public.my_org_id() and (
 public.is_org_admin() or public.can_access_site(site_id) or
 exists(select 1 from public.employees e where e.id=employee_id and e.user_id=auth.uid())
));
create policy "managers and admins mark attendance" on public.attendance for insert
with check (org_id=public.my_org_id() and (public.is_org_admin() or public.can_access_site(site_id)));
create policy "managers and admins update attendance" on public.attendance for update
using (org_id=public.my_org_id() and (public.is_org_admin() or public.can_access_site(site_id)))
with check (org_id=public.my_org_id() and (public.is_org_admin() or public.can_access_site(site_id)));
create policy "admins delete attendance" on public.attendance for delete
using (org_id=public.my_org_id() and public.is_org_admin());

-- Leave requests
create policy "read scoped leave" on public.leave_requests for select
using (org_id=public.my_org_id() and (
 public.is_org_admin() or public.can_access_site(site_id) or
 exists(select 1 from public.employees e where e.id=employee_id and e.user_id=auth.uid())
));
create policy "employee or manager creates leave" on public.leave_requests for insert
with check (org_id=public.my_org_id() and (
 public.can_access_site(site_id) or
 exists(select 1 from public.employees e where e.id=employee_id and e.user_id=auth.uid() and e.site_id=site_id)
));
create policy "managers and admins review leave" on public.leave_requests for update
using (org_id=public.my_org_id() and (public.is_org_admin() or public.can_access_site(site_id)))
with check (org_id=public.my_org_id() and (public.is_org_admin() or public.can_access_site(site_id)));

-- Payroll is restricted to HR/Admin; employees can read only their payslips.
create policy "admins read payroll runs" on public.payroll_runs for select
using (org_id=public.my_org_id() and public.is_org_admin());
create policy "admins manage payroll runs" on public.payroll_runs for all
using (org_id=public.my_org_id() and public.is_org_admin())
with check (org_id=public.my_org_id() and public.is_org_admin());
create policy "admins or employee read payslips" on public.payslips for select
using (org_id=public.my_org_id() and (
 public.is_org_admin() or exists(select 1 from public.employees e where e.id=employee_id and e.user_id=auth.uid())
));
create policy "admins manage payslips" on public.payslips for all
using (org_id=public.my_org_id() and public.is_org_admin())
with check (org_id=public.my_org_id() and public.is_org_admin());

-- Audit log: only admins can inspect; inserts are limited to organisation members.
create policy "admins read audit logs" on public.audit_logs for select
using (org_id=public.my_org_id() and public.is_org_admin());
create policy "members add audit logs" on public.audit_logs for insert
with check (org_id=public.my_org_id() and actor=auth.uid());
