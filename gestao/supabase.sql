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

-- ===== Acesso por menu e edição de usuários (aba Equipe) =====
-- Cada pessoa vê só os menus marcados; administrador vê todos.
alter table public.perfis add column if not exists menus text[] not null default '{painel,esteira,tarefas,clientes,prospeccoes}';
create or replace function public.pode(menu text) returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select ativo and (admin or menu = any(menus)) from perfis where id = auth.uid()), false)
$$;

-- Financeiro: quem tem o menu Financeiro; equipe: quem tem o menu Equipe
drop policy if exists "equipe usa registros" on public.registros;
create policy "equipe usa registros" on public.registros for all to authenticated
  using (perfil_ativo() and (pode('financeiro') or colecao not in ('contas', 'categorias', 'centros', 'tags', 'fornecedores', 'lancamentos')))
  with check (perfil_ativo() and (pode('financeiro') or colecao not in ('contas', 'categorias', 'centros', 'tags', 'fornecedores', 'lancamentos')));
drop policy if exists "admin altera perfis" on public.perfis;
create policy "admin altera perfis" on public.perfis for update to authenticated using (pode('equipe')) with check (pode('equipe'));
drop policy if exists "admin vê acessos" on public.acessos;
create policy "admin vê acessos" on public.acessos for select to authenticated using (pode('equipe'));

-- A senha da área restrita vale para quem tem o menu correspondente
create or replace function public.abrir_area_restrita(senha text, area text) returns boolean
language plpgsql security definer set search_path = public, extensions as $$
declare h text; quem text; chave text;
begin
  if not pode(case when area = 'Financeiro' then 'financeiro' else 'equipe' end) then return false; end if;
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

-- Troca nome, e-mail e (se informada) senha de um usuário. Só quem tem o menu Equipe.
create or replace function public.editar_usuario(alvo uuid, novo_nome text, novo_email text, nova_senha text default null) returns text
language plpgsql security definer set search_path = public, extensions, auth as $$
declare em text := lower(trim(novo_email));
begin
  if not pode('equipe') then return 'Sem permissão.'; end if;
  if coalesce(trim(novo_nome), '') = '' or em !~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' then return 'Nome ou e-mail inválido.'; end if;
  if nova_senha is not null and nova_senha <> '' and length(nova_senha) < 6 then return 'A senha precisa ter pelo menos 6 caracteres.'; end if;
  if exists (select 1 from auth.users where lower(email) = em and id <> alvo) then return 'Esse e-mail já é de outra pessoa.'; end if;
  update auth.users set
    email = em,
    email_confirmed_at = coalesce(email_confirmed_at, now()),
    encrypted_password = case when coalesce(nova_senha, '') = '' then encrypted_password else crypt(nova_senha, gen_salt('bf')) end,
    raw_user_meta_data = coalesce(raw_user_meta_data, '{}'::jsonb) || jsonb_build_object('nome', trim(novo_nome)),
    updated_at = now()
  where id = alvo;
  if not found then return 'Usuário não encontrado.'; end if;
  update auth.identities set identity_data = identity_data || jsonb_build_object('email', em), updated_at = now()
  where user_id = alvo and provider = 'email';
  update perfis set nome = trim(novo_nome), email = em where id = alvo;
  return 'ok';
end $$;
revoke execute on function public.editar_usuario(uuid, text, text, text) from public, anon;
grant execute on function public.editar_usuario(uuid, text, text, text) to authenticated;
