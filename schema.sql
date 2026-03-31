-- ══════════════════════════════════════════════════════════
--  BrisaDev — Schema Supabase (PostgreSQL)
--  Executa este ficheiro no SQL Editor do Supabase:
--  https://supabase.com/dashboard → project → SQL Editor
-- ══════════════════════════════════════════════════════════

-- ─── Extensões ────────────────────────────────────────────
create extension if not exists "uuid-ossp";

-- ─── Tabela: projetos ─────────────────────────────────────
create table if not exists projects (
  id          uuid primary key default uuid_generate_v4(),
  name        text not null,
  description text,
  category    text not null check (category in ('website','ecommerce','webapp','landing')),
  status      text not null default 'development' check (status in ('live','development')),
  url         text,
  icon        text default '🌐',
  tech        text[] default '{}',
  img_url     text,           -- URL pública (Supabase Storage ou externa)
  video_url   text,
  gallery     text[] default '{}',  -- Array de URLs públicas
  created_at  timestamptz default now(),
  updated_at  timestamptz default now()
);

-- ─── Tabela: site_config ──────────────────────────────────
-- Uma única linha com todas as configurações do site
create table if not exists site_config (
  id              int primary key default 1 check (id = 1),  -- single-row table
  email           text default 'brisadev@email.com',
  whatsapp        text default '+351 936 698 894',
  response_time   text default 'Menos de 24h',
  hero_badge      text default '⚡ Desenvolvimento Web Premium',
  hero_line1      text default 'Sites que',
  hero_line2      text default 'Convertem.',
  hero_line3      text default 'Experiências que ficam.',
  hero_sub        text default 'Criamos websites modernos e futuristas que elevam a tua marca.',
  stat1_num       text default '50+',
  stat1_lbl       text default 'Projetos',
  stat2_num       text default '1-3',
  stat2_lbl       text default 'Dias entrega',
  stat3_num       text default '100%',
  stat3_lbl       text default 'Satisfação',
  stat4_num       text default '24/7',
  stat4_lbl       text default 'Suporte',
  about_p1        text default 'Olá! Sou o fundador da BrisaDev.',
  about_p2        text default 'Com mais de 5 anos de experiência no desenvolvimento web.',
  about_p3        text default 'A minha especialidade é transformar ideias em experiências digitais.',
  p1_price        text default '299',
  p1_delivery     text default 'Entrega em 1-2 dias úteis',
  p1_features     text default 'Landing Page Profissional\nDesign Personalizado\nMobile Responsivo\nFormulário de Contacto\nSEO Básico\n1 Revisão Incluída',
  p2_price        text default '699',
  p2_delivery     text default 'Entrega em 2-3 dias úteis',
  p2_features     text default 'Site Completo (até 5 páginas)\nDesign Premium Único\nAnimações & Interatividade\nSEO Avançado\n3 Revisões Incluídas\nSuporte 30 dias',
  p3_price        text default '1299',
  p3_delivery     text default 'Entrega em 3 dias úteis',
  p3_features     text default 'Loja Online Completa\nGestão de Produtos\nPagamentos Online\nCarrinho & Checkout\nSEO E-commerce\nSuporte 60 dias',
  admin_user      text default 'brisadev',
  admin_pass_hash text default '$2b$10$placeholder',  -- bcrypt hash — updated via API
  updated_at      timestamptz default now()
);

-- Garante que existe sempre 1 linha de config
insert into site_config (id) values (1) on conflict (id) do nothing;

-- ─── Tabela: orders (pagamentos Stripe) ───────────────────
create table if not exists orders (
  id                  uuid primary key default uuid_generate_v4(),
  stripe_payment_id   text unique not null,
  stripe_customer_id  text,
  plan                text not null,
  amount_eur          numeric(10,2) not null,
  currency            text default 'eur',
  status              text default 'pending' check (status in ('pending','succeeded','failed','refunded')),
  customer_name       text,
  customer_email      text,
  customer_phone      text,
  project_desc        text,
  created_at          timestamptz default now(),
  updated_at          timestamptz default now()
);

-- ─── Tabela: contact_messages ─────────────────────────────
create table if not exists contact_messages (
  id          uuid primary key default uuid_generate_v4(),
  name        text not null,
  email       text not null,
  phone       text,
  project_type text,
  message     text,
  read        boolean default false,
  created_at  timestamptz default now()
);

-- ─── Trigger: auto updated_at ────────────────────────────
create or replace function set_updated_at()
returns trigger language plpgsql as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

create trigger trg_projects_updated
  before update on projects
  for each row execute procedure set_updated_at();

create trigger trg_config_updated
  before update on site_config
  for each row execute procedure set_updated_at();

create trigger trg_orders_updated
  before update on orders
  for each row execute procedure set_updated_at();

-- ─── Row Level Security (RLS) ─────────────────────────────
-- Projetos e config são públicos para leitura (o site precisa)
alter table projects      enable row level security;
alter table site_config   enable row level security;
alter table orders        enable row level security;
alter table contact_messages enable row level security;

-- Leitura pública de projetos
create policy "projetos_public_read" on projects
  for select using (true);

-- Leitura pública de config
create policy "config_public_read" on site_config
  for select using (true);

-- Tudo o resto requer service_role key (só o backend Node.js tem acesso)
create policy "projetos_service_write" on projects
  for all using (auth.role() = 'service_role');

create policy "config_service_write" on site_config
  for all using (auth.role() = 'service_role');

create policy "orders_service_all" on orders
  for all using (auth.role() = 'service_role');

create policy "messages_service_all" on contact_messages
  for all using (auth.role() = 'service_role');

-- ─── Storage bucket para imagens/vídeos ───────────────────
-- Executa isto separadamente no Supabase Dashboard → Storage
-- ou descomenta e executa:
--
-- insert into storage.buckets (id, name, public) values ('brisadev-media', 'brisadev-media', true);
--
-- create policy "media_public_read" on storage.objects
--   for select using (bucket_id = 'brisadev-media');
--
-- create policy "media_service_write" on storage.objects
--   for insert with check (bucket_id = 'brisadev-media' and auth.role() = 'service_role');
