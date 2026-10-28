-- Checks: redeem codes. Run this ONCE in Supabase -> SQL Editor -> New query -> Run.
-- It makes a shared code list so "only 1 person" codes really can only be used once.

create table if not exists public.checks_codes (
  code       text primary key,                 -- always stored UPPERCASE
  pts        integer not null check (pts > 0),
  max_uses   integer not null default 0,       -- 0 = unlimited people, 1 = only one person, N = N people
  uses       integer not null default 0,
  kind       text not null default 'custom',   -- single / inf / custom
  created_at timestamptz not null default now()
);

create table if not exists public.checks_code_uses (
  code     text not null references public.checks_codes(code) on delete cascade,
  who_dev  text not null,                      -- the browser/device id
  who_name text not null,                      -- the username (lowercase)
  at       timestamptz not null default now(),
  primary key (code, who_dev),
  unique (code, who_name)                      -- one redeem per person per code
);

-- Nobody can touch the tables directly with the public key. Only the two functions below can.
alter table public.checks_codes     enable row level security;
alter table public.checks_code_uses enable row level security;
revoke all on public.checks_codes, public.checks_code_uses from anon, authenticated;

-- Owner commands (gencode / codes / delcode). Needs your real owner code, checked against its hash.
create or replace function public.checks_code_admin(
  p_key text, p_op text, p_code text default '', p_pts integer default 0, p_max integer default 0, p_kind text default 'custom'
) returns json language plpgsql security definer set search_path = public as $$
declare k text := upper(trim(coalesce(p_code, ''))); n integer;
begin
  if encode(sha256(convert_to('checks|' || coalesce(p_key, ''), 'UTF8')), 'hex')
     <> '3a5369129d2a0a3e3cbfe450125ed518cab98c2e78d261626f7d06fc30be1ca9' then
    return json_build_object('e', 'Wrong owner code.');
  end if;

  if p_op = 'create' then
    if k !~ '^[A-Z0-9_-]{3,30}$' then return json_build_object('e', 'Bad code text.'); end if;
    if p_pts < 1 or p_max < 0 then return json_build_object('e', 'Bad points or uses.'); end if;
    if exists (select 1 from public.checks_codes where code = k) then
      return json_build_object('e', 'That code already exists. Delete it first with: delcode ' || k);
    end if;
    insert into public.checks_codes(code, pts, max_uses, kind) values (k, p_pts, p_max, left(coalesce(p_kind, 'custom'), 10));
    return json_build_object('ok', true);

  elsif p_op = 'list' then
    return json_build_object('codes', coalesce((
      select json_agg(json_build_object('code', code, 'pts', pts, 'max_uses', max_uses, 'uses', uses) order by created_at desc)
      from (select * from public.checks_codes order by created_at desc limit 100) t
    ), '[]'::json));

  elsif p_op = 'delete' then
    delete from public.checks_codes where code = k;
    get diagnostics n = row_count;
    return json_build_object('ok', true, 'n', n);
  end if;

  return json_build_object('e', 'Unknown operation.');
end $$;

-- Player redeem. Locks the code row so two people can never both take a one-use code.
create or replace function public.checks_code_redeem(p_code text, p_name text, p_dev text)
returns json language plpgsql security definer set search_path = public as $$
declare c public.checks_codes%rowtype;
        k text := upper(trim(coalesce(p_code, '')));
        nm text := lower(trim(coalesce(p_name, '')));
        d text := trim(coalesce(p_dev, ''));
begin
  if k = '' or nm = '' or d = '' then return json_build_object('e', 'Missing info.'); end if;
  select * into c from public.checks_codes where code = k for update;
  if not found then return json_build_object('e', 'That code is not valid.'); end if;
  if c.max_uses > 0 and c.uses >= c.max_uses then
    return json_build_object('e', case when c.max_uses = 1 then 'That code has already been used.' else 'That code has run out.' end);
  end if;
  if exists (select 1 from public.checks_code_uses u where u.code = k and (u.who_dev = d or u.who_name = nm)) then
    return json_build_object('e', 'You already used that code.');
  end if;
  insert into public.checks_code_uses(code, who_dev, who_name) values (k, d, nm);
  update public.checks_codes set uses = uses + 1 where code = k;
  return json_build_object('ok', true, 'pts', c.pts);
end $$;

grant execute on function public.checks_code_admin(text, text, text, integer, integer, text) to anon, authenticated;
grant execute on function public.checks_code_redeem(text, text, text) to anon, authenticated;
