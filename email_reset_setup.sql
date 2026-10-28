-- Checks: verified email + password reset. Run ONCE in Supabase -> SQL Editor, AFTER codes_setup.sql.
-- Emails are sent by Supabase Auth (see the setup notes in the chat: edit the email templates to include {{ .Token }}, and add custom SMTP).

create table if not exists public.checks_recovery (
  username    text primary key,                 -- lowercase game username
  user_id     uuid not null,                    -- the Supabase Auth user that proved they own the email
  email       text not null,
  verified_at timestamptz not null default now()
);
alter table public.checks_recovery enable row level security;
revoke all on public.checks_recovery from anon, authenticated;

-- Link a verified email to a username. Credentials are checked by your existing checks_api('ver') so nobody can link an email to someone else's name.
create or replace function public.checks_link_email(p_u text, p_h text)
returns json language plpgsql security definer set search_path = public as $$
declare u text := lower(trim(coalesce(p_u, ''))); r jsonb; em text := lower(auth.jwt() ->> 'email');
begin
  if auth.uid() is null or em is null then return json_build_object('e', 'Verify your email first.'); end if;
  r := to_jsonb(public.checks_api(p_a => 'ver', p_u => u, p_h => p_h, p_v => 0, p_d => ''));
  if r ? 'e' then return json_build_object('e', 'Wrong username or password.'); end if;
  insert into public.checks_recovery(username, user_id, email) values (u, auth.uid(), em)
  on conflict (username) do update set user_id = excluded.user_id, email = excluded.email, verified_at = now();
  return json_build_object('ok', true);
end $$;

-- Sets a new password hash for a username (same hashing as checks_api uses). Only called by checks_reset_password below.
create or replace function public.checks_set_hash(p_u text, p_h text)
returns void language plpgsql security definer set search_path = public as $$
begin
  update public.checks_acc
     set ph = encode(sha256(convert_to('srv|' || p_u || '|' || p_h, 'UTF8')), 'hex'), fails = 0
   where checks_acc.u = p_u;
  if not found then raise exception 'No such account.'; end if;
end $$;
revoke all on function public.checks_set_hash(text, text) from public, anon, authenticated;

-- Reset: only works if the signed-in email code belongs to the email linked to that username.
create or replace function public.checks_reset_password(p_u text, p_h text)
returns json language plpgsql security definer set search_path = public as $$
declare u text := lower(trim(coalesce(p_u, '')));
begin
  if auth.uid() is null then return json_build_object('e', 'Verify your email first.'); end if;
  if coalesce(p_h, '') !~ '^[0-9a-f]{64}$' then return json_build_object('e', 'Bad password data.'); end if;
  if not exists (select 1 from public.checks_recovery where username = u and user_id = auth.uid()) then
    return json_build_object('e', 'That email is not verified on this username.');
  end if;
  perform public.checks_set_hash(u, p_h);
  return json_build_object('ok', true);
end $$;

grant execute on function public.checks_link_email(text, text), public.checks_reset_password(text, text) to anon, authenticated;
