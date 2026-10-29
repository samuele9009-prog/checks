-- Checks: reserved usernames + player finder + owner account delete.
-- Run ONCE in Supabase -> SQL Editor -> New query -> Run. Safe to run again.
-- Needs the checks_acc table your account system already uses (column u = lowercase username).

-- Is this username already owned by a registered account? (Used to stop guests picking it.)
create or replace function public.checks_name_taken(p_u text)
returns boolean language sql security definer stable set search_path = public as $$
  select exists (select 1 from public.checks_acc where u = lower(trim(coalesce(p_u, ''))));
$$;

-- Find players: usernames that start with the text (empty text = everyone, first 30).
create or replace function public.checks_find(p_q text default '')
returns json language plpgsql security definer stable set search_path = public as $$
declare q text := lower(trim(coalesce(p_q, '')));
begin
  if q !~ '^[a-z0-9_]{0,20}$' then return '[]'::json; end if;
  return coalesce((
    select json_agg(u order by u)
    from (select u from public.checks_acc where left(u, length(q)) = q order by u limit 30) t
  ), '[]'::json);
end $$;

-- Owner only: list / delete accounts. Uses the same owner-code hash as checks_code_admin.
create or replace function public.checks_acc_admin(p_key text, p_op text, p_u text default '')
returns json language plpgsql security definer set search_path = public as $$
declare k text := lower(trim(coalesce(p_u, ''))); n integer;
begin
  if encode(sha256(convert_to('checks|' || coalesce(p_key, ''), 'UTF8')), 'hex')
     <> '3a5369129d2a0a3e3cbfe450125ed518cab98c2e78d261626f7d06fc30be1ca9' then
    return json_build_object('e', 'Wrong owner code.');
  end if;

  if p_op = 'list' then
    return json_build_object(
      'n', (select count(*) from public.checks_acc),
      'names', coalesce((select json_agg(u order by u) from (
                 select u from public.checks_acc where left(u, length(k)) = k order by u limit 100) t), '[]'::json));

  elsif p_op = 'delete' then
    if k !~ '^[a-z0-9_]{3,20}$' then return json_build_object('e', 'Bad username.'); end if;
    if to_regclass('public.checks_recovery') is not null then
      execute 'delete from public.checks_recovery where username = $1' using k;
    end if;
    delete from public.checks_acc where u = k;
    get diagnostics n = row_count;
    return json_build_object('ok', true, 'n', n);
  end if;

  return json_build_object('e', 'Unknown operation.');
end $$;

grant execute on function public.checks_name_taken(text), public.checks_find(text), public.checks_acc_admin(text, text, text) to anon, authenticated;
