-- Run this ONCE in Supabase: SQL Editor > New query > paste > Run.
-- Adds public player profiles (picture, bio, colour, favourite piece) so they show up in "Find players".
-- It reuses your existing checks_api('ver', ...) to check the username + password hash, so it does not touch your accounts table.

create table if not exists public.checks_profiles (
  u          text primary key,
  dn         text not null default '',
  pf         text not null default '',
  bio        text not null default '',
  col        int  not null default 0,
  fav        text not null default '',
  updated_at timestamptz not null default now()
);

alter table public.checks_profiles add column if not exists dn text not null default '';
alter table public.checks_profiles enable row level security;
revoke all on table public.checks_profiles from anon, authenticated;

-- Save your own profile (needs the right username + password hash)
drop function if exists public.checks_profile_set(text, text, text, text, int, text);
create or replace function public.checks_profile_set(
  p_u text, p_h text, p_pf text, p_bio text, p_col int, p_fav text, p_dn text default ''
) returns json
language plpgsql
security definer
set search_path = public
as $$
declare
  n  text := lower(coalesce(p_u, ''));
  v  jsonb;
  pf text := coalesce(p_pf, '');
begin
  if n !~ '^[a-z0-9_]{3,20}$' then
    return json_build_object('e', 'Bad username.');
  end if;

  v := (public.checks_api('ver', n, coalesce(p_h, ''), 0, ''))::jsonb;
  if v ? 'e' then
    return json_build_object('e', coalesce(v ->> 'e', 'Wrong username or password.'));
  end if;

  if not (
    pf ~ '^p:(sword|ninja|fish|shark|king):[0-5]$'
    or (pf ~ '^data:image/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$' and length(pf) < 24000)
  ) then
    pf := '';
  end if;

  insert into public.checks_profiles as t (u, dn, pf, bio, col, fav, updated_at)
  values (
    n,
    left(btrim(regexp_replace(coalesce(p_dn, ''), '[<>[:cntrl:]]', '', 'g')), 16),
    pf,
    left(btrim(regexp_replace(coalesce(p_bio, ''), '[<>[:cntrl:]]', '', 'g')), 60),
    greatest(0, least(5, coalesce(p_col, 0))),
    case when p_fav in ('sword', 'ninja', 'fish', 'shark', 'king') then p_fav else '' end,
    now()
  )
  on conflict (u) do update
    set dn = excluded.dn,
        pf = excluded.pf,
        bio = excluded.bio,
        col = excluded.col,
        fav = excluded.fav,
        updated_at = now();

  return json_build_object('ok', true);
end;
$$;

-- Read profiles for a list of usernames (what Find players shows)
create or replace function public.checks_profiles(p_names text[])
returns json
language sql
security definer
set search_path = public
stable
as $$
  select coalesce(json_agg(json_build_object('u', u, 'dn', dn, 'pf', pf, 'bio', bio, 'col', col, 'fav', fav)), '[]'::json)
  from public.checks_profiles
  where u in (select lower(x) from unnest(p_names[1:50]) as x);
$$;

grant execute on function public.checks_profile_set(text, text, text, text, int, text, text) to anon, authenticated;
grant execute on function public.checks_profiles(text[]) to anon, authenticated;

notify pgrst, 'reload schema';
