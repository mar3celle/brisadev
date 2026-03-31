/**
 * BrisaDev — Seed Script
 * ========================
 * Cria o hash da password admin e insere a config inicial no Supabase.
 * Executa UMA VEZ após criar as tabelas:
 *   node scripts/seed.js
 */

require('dotenv').config({ path: require('path').join(__dirname, '../.env') });
const bcrypt = require('bcrypt');
const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

async function seed() {
  const ADMIN_USER = 'brisadev';
  const ADMIN_PASS = 'brisa2025';  // ← muda aqui antes de executar!

  console.log('🌱 A criar hash da password...');
  const hash = await bcrypt.hash(ADMIN_PASS, 10);

  const { error } = await supabase
    .from('site_config')
    .update({ admin_user: ADMIN_USER, admin_pass_hash: hash })
    .eq('id', 1);

  if (error) {
    console.error('❌ Erro:', error.message);
    process.exit(1);
  }

  console.log('✅ Admin configurado:', ADMIN_USER);
  console.log('✅ Password hash guardado no Supabase');
  console.log('\n⚠️  Apaga este ficheiro ou as credenciais do código após executar!\n');
}

seed();
