-- Banco de dados do app de gestão (Supabase). Rodar uma vez no SQL Editor do projeto.

-- Quem pode entrar: um perfil por usuário do Supabase Auth
create table if not exists public.perfis (
  id uuid primary key references auth.users on delete cascade,
  nome text not null,
  email text,
  admin boolean not null default false,
  ativo boolean not null default false
);

-- Todos os cadastros do app: cada item de cada lista é uma linha
create table if not exists public.registros (
  colecao text not null,
  id text not null,
  dados jsonb not null,
  atualizado timestamptz not null default now(),
  atualizado_por uuid default auth.uid(),
  primary key (colecao, id)
);

create or replace function public.perfil_ativo() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select ativo from perfis where id = auth.uid()), false)
$$;
create or replace function public.eh_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select ativo and admin from perfis where id = auth.uid()), false)
$$;

-- Novo usuário ganha um perfil bloqueado até um administrador liberar.
-- O primeiro usuário do sistema já entra como administrador.
create or replace function public.novo_perfil() returns trigger
language plpgsql security definer set search_path = public as $$
declare primeiro boolean := not exists (select 1 from perfis);
begin
  insert into perfis (id, nome, email, admin, ativo)
  values (new.id, coalesce(nullif(new.raw_user_meta_data->>'nome', ''), split_part(new.email, '@', 1)), new.email, primeiro, primeiro);
  return new;
end $$;
drop trigger if exists ao_criar_usuario on auth.users;
create trigger ao_criar_usuario after insert on auth.users for each row execute function public.novo_perfil();

create or replace function public.marcar_atualizacao() returns trigger
language plpgsql as $$
begin new.atualizado := now(); new.atualizado_por := auth.uid(); return new; end $$;
drop trigger if exists ao_atualizar on public.registros;
create trigger ao_atualizar before update on public.registros for each row execute function public.marcar_atualizacao();

alter table public.perfis enable row level security;
alter table public.registros enable row level security;

drop policy if exists "ver perfis" on public.perfis;
-- Toda a equipe liberada vê os nomes de quem está no sistema (para escolher responsáveis)
create policy "ver perfis" on public.perfis for select to authenticated using (id = auth.uid() or perfil_ativo());
drop policy if exists "admin altera perfis" on public.perfis;
create policy "admin altera perfis" on public.perfis for update to authenticated using (eh_admin()) with check (eh_admin());

-- Financeiro só para administradores; o resto para toda a equipe liberada
drop policy if exists "equipe usa registros" on public.registros;
create policy "equipe usa registros" on public.registros for all to authenticated
  using (perfil_ativo() and (eh_admin() or colecao not in ('contas', 'categorias', 'centros', 'tags', 'fornecedores', 'lancamentos')))
  with check (perfil_ativo() and (eh_admin() or colecao not in ('contas', 'categorias', 'centros', 'tags', 'fornecedores', 'lancamentos')));

-- Tempo real: avisa os outros navegadores quando algo muda
alter table public.registros replica identity full;
do $$ begin
  alter publication supabase_realtime add table public.registros;
exception when duplicate_object then null; end $$;

-- ===== Área restrita (Financeiro / Equipe) =====
-- A senha da área restrita fica só como hash bcrypt em config_privada, gravado direto no SQL Editor:
--   insert into public.config_privada values ('senha_area_restrita', '<hash bcrypt>')
--   on conflict (chave) do update set valor = excluded.valor;
-- (para trocar a senha: gere o hash com extensions.crypt('nova senha', extensions.gen_salt('bf')))
create extension if not exists pg_net;
create table if not exists public.config_privada (chave text primary key, valor text not null);
alter table public.config_privada enable row level security; -- sem políticas: o app não lê

-- Registro de quem abriu o Financeiro / Equipe
create table if not exists public.acessos (
  id bigint generated always as identity primary key,
  usuario uuid default auth.uid(),
  nome text,
  area text not null,
  quando timestamptz not null default now()
);
alter table public.acessos enable row level security;
drop policy if exists "admin vê acessos" on public.acessos;
create policy "admin vê acessos" on public.acessos for select to authenticated using (eh_admin());

-- Confere a senha, registra o acesso e manda e-mail para o Renan (via Resend, se a chave
-- "resend_api_key" estiver no Vault do Supabase)
create or replace function public.abrir_area_restrita(senha text, area text) returns boolean
language plpgsql security definer set search_path = public, extensions as $$
declare h text; quem text; chave text;
begin
  if not eh_admin() then return false; end if;
  select valor into h from config_privada where config_privada.chave = 'senha_area_restrita';
  if h is null or crypt(senha, h) <> h then return false; end if;
  select nome into quem from perfis where id = auth.uid();
  insert into acessos (nome, area) values (quem, area);
  select decrypted_secret into chave from vault.decrypted_secrets where name = 'resend_api_key';
  if chave is not null then
    perform net.http_post(
      url := 'https://api.resend.com/emails',
      headers := jsonb_build_object('Authorization', 'Bearer ' || chave, 'Content-Type', 'application/json'),
      body := jsonb_build_object(
        'from', 'Gestão do Escritório <onboarding@resend.dev>',
        'to', jsonb_build_array('renangrolliarquitetura@gmail.com'),
        'subject', 'Acesso ao ' || area || ': ' || coalesce(quem, '?'),
        'text', coalesce(quem, '?') || ' abriu ' || area || ' no app de gestão em '
          || to_char(now() at time zone 'America/Cuiaba', 'DD/MM/YYYY "às" HH24:MI') || ' (horário de Sorriso-MT).'));
  end if;
  return true;
end $$;
revoke execute on function public.abrir_area_restrita(text, text) from public, anon;
grant execute on function public.abrir_area_restrita(text, text) to authenticated;
