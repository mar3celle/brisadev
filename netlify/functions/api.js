/**
 * BrisaDev — Netlify Function CRUD completo
 * Sem Express, sem bcrypt nativo — usa bcryptjs (puro JS)
 */

const crypto = require('crypto');
const bcrypt = require('bcryptjs');   // ← puro JS, funciona em Netlify
const { createClient } = require('@supabase/supabase-js');

// Stripe só inicializa se a chave existir (evita crash se não estiver configurado)
const stripe = process.env.STRIPE_SECRET_KEY
  ? require('stripe')(process.env.STRIPE_SECRET_KEY)
  : null;

// ── Supabase clients ──────────────────────────────────────────────────────────
const sb = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);
const sbp = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

// ── Resposta helpers ──────────────────────────────────────────────────────────
const CORS = {
  'Content-Type': 'application/json',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,PATCH,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,x-admin-token,X-Admin-Token'
};

const ok    = (data, code = 200) => ({ statusCode: code, headers: CORS, body: JSON.stringify(data) });
const fail  = (msg,  code = 500) => ({ statusCode: code, headers: CORS, body: JSON.stringify({ error: msg }) });

function parseBody(event) {
  if (!event.body) return {};
  try { return JSON.parse(event.body); } catch { return {}; }
}

// ── JWT helpers (sem dependências externas) ───────────────────────────────────
function signToken(payload) {
  const data = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig  = crypto.createHmac('sha256', process.env.JWT_SECRET).update(data).digest('base64url');
  return `${data}.${sig}`;
}
function verifyToken(token) {
  if (!token || !process.env.JWT_SECRET) return null;
  const dot = token.lastIndexOf('.');
  if (dot === -1) return null;
  const data = token.slice(0, dot);
  const sig  = token.slice(dot + 1);
  const expected = crypto.createHmac('sha256', process.env.JWT_SECRET).update(data).digest('base64url');
  if (sig !== expected) return null;
  try {
    const payload = JSON.parse(Buffer.from(data, 'base64url').toString());
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch { return null; }
}

function adminOk(event) {
  const t = (event.headers['x-admin-token'] || event.headers['X-Admin-Token'] || '').trim();
  return !!verifyToken(t);
}

// ── Handler principal ─────────────────────────────────────────────────────────
exports.handler = async (event) => {
  // CORS preflight
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers: CORS, body: '' };
  }

  const method = event.httpMethod;

  // Normaliza o path: remove qualquer prefixo até /api/
  // /.netlify/functions/api/projects/123  →  projects/123
  // /api/projects/123                     →  projects/123
  let raw = event.path || '';
  // Usa rawPath se disponível (Netlify v2)
  if (event.rawPath) raw = event.rawPath;

  // Remove tudo antes de (e incluindo) /api/
  const apiIdx = raw.indexOf('/api/');
  if (apiIdx !== -1) {
    raw = raw.slice(apiIdx + 5); // +5 = len('/api/')
  } else {
    // fallback: remove prefixo da function
    raw = raw.replace(/^\/.netlify\/functions\/[^/]+\/?/, '');
  }

  const parts    = raw.split('/').filter(Boolean);
  const resource = parts[0] || '';
  const id       = parts[1] || '';
  const sub      = parts[2] || '';
  const qs       = event.queryStringParameters || {};

  console.log(`[api] ${method} /${resource}${id ? '/' + id : ''}${sub ? '/' + sub : ''} | admin=${adminOk(event)}`);

  try {

    // ================================================================
    // SETUP  →  POST /api/setup
    // Cria as credenciais iniciais se ainda não existirem.
    // Protegido por um SETUP_SECRET definido nas env vars do Netlify.
    // Só funciona UMA VEZ (se já existir hash configurado, bloqueia).
    // ================================================================
    if (resource === 'setup') {
      if (method !== 'POST') return fail('Method not allowed', 405);

      const { setup_secret, username, password } = parseBody(event);

      // Verifica o setup_secret
      const expectedSecret = process.env.SETUP_SECRET;
      if (!expectedSecret) return fail('SETUP_SECRET não configurado nas env vars do Netlify', 500);
      if (setup_secret !== expectedSecret) return fail('setup_secret inválido', 401);

      if (!username || !password) return fail('username e password obrigatórios', 400);
      if (password.length < 6) return fail('Password mínimo 6 caracteres', 400);

      // Verifica se já existe hash configurado
      const { data: cfg } = await sb.from('site_config').select('admin_pass_hash').single();
      const alreadySetup = cfg && cfg.admin_pass_hash && !cfg.admin_pass_hash.includes('placeholder');
      if (alreadySetup) return fail('Setup já foi feito. Para alterar credenciais usa o painel Admin → Configurações.', 403);

      // Cria o hash e guarda
      const hash = await bcrypt.hash(password, 10);
      const { error } = await sb.from('site_config')
        .update({ admin_user: username, admin_pass_hash: hash })
        .eq('id', 1);

      if (error) return fail('Erro ao guardar: ' + error.message);

      return ok({
        ok: true,
        message: `✅ Admin configurado! Utilizador: "${username}". Agora podes fazer login no painel Admin.`
      });
    }

    // ================================================================
    // HEALTH
    // ================================================================
    if (resource === 'health') {
      const { error } = await sb.from('site_config').select('id').single();
      return ok({
        status: 'ok',
        supabase: error ? '❌ ' + error.message : '✅ Ligado',
        env: {
          supabase_url:  !!process.env.SUPABASE_URL,
          service_key:   !!process.env.SUPABASE_SERVICE_ROLE_KEY,
          anon_key:      !!process.env.SUPABASE_ANON_KEY,
          jwt_secret:    !!process.env.JWT_SECRET,
          stripe:        !!process.env.STRIPE_SECRET_KEY
        }
      });
    }

    // ================================================================
    // AUTH  →  POST /api/auth/login
    // ================================================================
    if (resource === 'auth') {
      if (method !== 'POST') return fail('Method not allowed', 405);
      const { username, password } = parseBody(event);
      if (!username || !password) return fail('username e password obrigatórios', 400);

      const { data: cfg, error: dbErr } = await sb
        .from('site_config')
        .select('admin_user, admin_pass_hash')
        .single();

      if (dbErr || !cfg) return fail('Erro DB: ' + (dbErr ? dbErr.message : 'sem config'), 500);
      if (cfg.admin_user !== username) return fail('Credenciais inválidas', 401);

      const valid = await bcrypt.compare(password, cfg.admin_pass_hash);
      if (!valid) return fail('Credenciais inválidas', 401);

      const token = signToken({ role: 'admin', exp: Date.now() + 24 * 60 * 60 * 1000 });
      return ok({ token, ok: true });
    }

    // ================================================================
    // PROJECTS
    // ================================================================
    if (resource === 'projects') {

      // GET /api/projects  ou  GET /api/projects/:id
      if (method === 'GET') {
        if (id) {
          const { data, error } = await sbp.from('projects').select('*').eq('id', id).single();
          if (error) return fail('Projeto não encontrado', 404);
          return ok(data);
        }
        let q = sbp.from('projects').select('*').order('created_at', { ascending: false });
        if (qs.category && qs.category !== 'all') q = q.eq('category', qs.category);
        const { data, error } = await q;
        if (error) return fail(error.message);
        return ok(data || []);
      }

      // POST /api/projects
      if (method === 'POST') {
        if (!adminOk(event)) return fail('Não autorizado', 401);
        const b = parseBody(event);
        if (!b.name || !b.category) return fail('name e category obrigatórios', 400);
        const { data, error } = await sb.from('projects').insert([{
          name: b.name,
          description: b.description || '',
          category: b.category,
          status: b.status || 'development',
          url: b.url || '',
          icon: b.icon || '🌐',
          tech: b.tech || [],
          img_url: b.img_url || '',
          video_url: b.video_url || '',
          gallery: b.gallery || []
        }]).select().single();
        if (error) return fail(error.message);
        return ok(data, 201);
      }

      // PUT /api/projects/:id
      if (method === 'PUT') {
        if (!adminOk(event)) return fail('Não autorizado', 401);
        if (!id) return fail('ID em falta', 400);
        const b = parseBody(event);
        const { data, error } = await sb.from('projects').update({
          name: b.name,
          description: b.description || '',
          category: b.category,
          status: b.status,
          url: b.url || '',
          icon: b.icon || '🌐',
          tech: b.tech || [],
          img_url: b.img_url || '',
          video_url: b.video_url || '',
          gallery: b.gallery || []
        }).eq('id', id).select().single();
        if (error) return fail(error.message);
        return ok(data);
      }

      // DELETE /api/projects/:id
      if (method === 'DELETE') {
        if (!adminOk(event)) return fail('Não autorizado', 401);
        if (!id) return fail('ID em falta', 400);
        const { error } = await sb.from('projects').delete().eq('id', id);
        if (error) return fail(error.message);
        return ok({ ok: true });
      }

      return fail('Method not allowed', 405);
    }

    // ================================================================
    // CONFIG
    // ================================================================
    if (resource === 'config') {
      if (method === 'GET') {
        const { data, error } = await sbp.from('site_config')
          .select('email,whatsapp,response_time,hero_badge,hero_line1,hero_line2,hero_line3,hero_sub,stat1_num,stat1_lbl,stat2_num,stat2_lbl,stat3_num,stat3_lbl,stat4_num,stat4_lbl,about_p1,about_p2,about_p3,p1_price,p1_delivery,p1_features,p2_price,p2_delivery,p2_features,p3_price,p3_delivery,p3_features')
          .single();
        if (error) return fail(error.message);
        return ok(data);
      }
      if (method === 'PATCH') {
        if (!adminOk(event)) return fail('Não autorizado', 401);
        const b = parseBody(event);
        const allowed = ['email','whatsapp','response_time','hero_badge','hero_line1','hero_line2','hero_line3','hero_sub','stat1_num','stat1_lbl','stat2_num','stat2_lbl','stat3_num','stat3_lbl','stat4_num','stat4_lbl','about_p1','about_p2','about_p3','p1_price','p1_delivery','p1_features','p2_price','p2_delivery','p2_features','p3_price','p3_delivery','p3_features'];
        const updates = {};
        allowed.forEach(k => { if (b[k] !== undefined) updates[k] = b[k]; });
        if (b.admin_user) updates.admin_user = b.admin_user;
        if (b.admin_pass) updates.admin_pass_hash = await bcrypt.hash(b.admin_pass, 10);
        const { data, error } = await sb.from('site_config').update(updates).eq('id', 1).select().single();
        if (error) return fail(error.message);
        return ok(data);
      }
      return fail('Method not allowed', 405);
    }

    // ================================================================
    // CONTACT
    // ================================================================
    if (resource === 'contact') {
      if (method === 'POST' && !id) {
        const b = parseBody(event);
        if (!b.name || !b.email) return fail('Nome e email obrigatórios', 400);
        const { error } = await sb.from('contact_messages').insert([{
          name: b.name, email: b.email,
          phone: b.phone || '', project_type: b.project_type || '', message: b.message || ''
        }]);
        if (error) return fail(error.message);
        return ok({ ok: true });
      }
      if (method === 'GET') {
        if (!adminOk(event)) return fail('Não autorizado', 401);
        const { data, error } = await sb.from('contact_messages')
          .select('*').order('created_at', { ascending: false });
        if (error) return fail(error.message);
        return ok(data || []);
      }
      if (method === 'PATCH' && sub === 'read') {
        if (!adminOk(event)) return fail('Não autorizado', 401);
        await sb.from('contact_messages').update({ read: true }).eq('id', id);
        return ok({ ok: true });
      }
      return fail('Method not allowed', 405);
    }

    // ================================================================
    // UPLOAD  →  POST /api/upload  (base64 JSON)
    // ================================================================
    if (resource === 'upload') {
      if (!adminOk(event)) return fail('Não autorizado', 401);
      if (method !== 'POST') return fail('Method not allowed', 405);
      const b = parseBody(event);
      if (!b.fileData || !b.fileName || !b.mimeType) {
        return fail('fileData, fileName e mimeType são obrigatórios', 400);
      }
      const buffer = Buffer.from(b.fileData, 'base64');
      const { error } = await sb.storage
        .from('brisadev-media')
        .upload(b.fileName, buffer, { contentType: b.mimeType, upsert: true });
      if (error) return fail(error.message);
      const { data: { publicUrl } } = sb.storage.from('brisadev-media').getPublicUrl(b.fileName);
      return ok({ url: publicUrl });
    }

    // ================================================================
    // STRIPE — Payment Intent
    // ================================================================
    if (resource === 'create-payment-intent') {
      if (!stripe) return fail('Stripe não configurado', 500);
      if (method !== 'POST') return fail('Method not allowed', 405);
      const b = parseBody(event);
      if (!b.amount || !b.email) return fail('amount e email obrigatórios', 400);
      const existing = await stripe.customers.list({ email: b.email, limit: 1 });
      const customer = existing.data.length > 0
        ? existing.data[0]
        : await stripe.customers.create({ email: b.email, name: b.name });
      const pi = await stripe.paymentIntents.create({
        amount: Math.round(b.amount),
        currency: b.currency || 'eur',
        customer: customer.id,
        receipt_email: b.email,
        description: `BrisaDev — ${b.plan}`,
        metadata: { customer_name: b.name, customer_email: b.email, plan: b.plan || '' },
        automatic_payment_methods: { enabled: true }
      });
      await sb.from('orders').insert([{
        stripe_payment_id: pi.id, stripe_customer_id: customer.id,
        plan: b.plan, amount_eur: b.amount / 100, status: 'pending',
        customer_name: b.name, customer_email: b.email
      }]);
      return ok({ clientSecret: pi.client_secret });
    }

    // ================================================================
    // STRIPE — Webhook
    // ================================================================
    if (resource === 'webhook') {
      if (!stripe) return fail('Stripe não configurado', 500);
      if (method !== 'POST') return fail('Method not allowed', 405);
      let ev;
      try {
        ev = stripe.webhooks.constructEvent(
          event.body,
          event.headers['stripe-signature'],
          process.env.STRIPE_WEBHOOK_SECRET
        );
      } catch (e) { return fail('Webhook error: ' + e.message, 400); }
      const obj = ev.data.object;
      if (ev.type === 'payment_intent.succeeded')
        await sb.from('orders').update({ status: 'succeeded' }).eq('stripe_payment_id', obj.id);
      if (ev.type === 'payment_intent.payment_failed')
        await sb.from('orders').update({ status: 'failed' }).eq('stripe_payment_id', obj.id);
      return ok({ received: true });
    }

    // ================================================================
    // ORDERS
    // ================================================================
    if (resource === 'orders') {
      if (!adminOk(event)) return fail('Não autorizado', 401);
      const { data, error } = await sb.from('orders')
        .select('*').order('created_at', { ascending: false });
      if (error) return fail(error.message);
      return ok(data || []);
    }

    // 404 — log what we received to help debug
    return fail(`Rota desconhecida: ${method} /${resource} (path original: ${event.path})`, 404);

  } catch (e) {
    console.error('[api] ERRO:', e.message, '\n', e.stack);
    return fail('Erro interno: ' + e.message, 500);
  }
};
