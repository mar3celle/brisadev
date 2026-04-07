require('dotenv').config();
const bcrypt = require('bcryptjs');
const { createClient } = require('@supabase/supabase-js');

const sb = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

async function check() {
  const { data, error } = await sb.from('site_config').select('admin_user, admin_pass_hash').single();
  if (error) { console.error('❌ Erro DB:', error.message); return; }

  console.log('admin_user:      ', data.admin_user);
  console.log('admin_pass_hash: ', data.admin_pass_hash);

  const isPlaceholder = !data.admin_pass_hash || data.admin_pass_hash.includes('placeholder');
  console.log('hash válido:     ', !isPlaceholder);

  if (!isPlaceholder) {
    const test = await bcrypt.compare('brisa2025', data.admin_pass_hash);
    console.log('password brisa2025 ok:', test);
  }
}

check();
