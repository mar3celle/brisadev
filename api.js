/**
 * BrisaDev — Netlify Function handler (sem Express, routing manual)
 * O netlify.toml redireciona /api/* → /.netlify/functions/api/:splat
 * req.path dentro da function chega como /projects/123, /config, etc.
 */

const bcrypt   = require('bcrypt');
const stripe   = require('stripe')(process.env.STRIPE_SECRET_KEY);
const { createClient } = require('@supabase/supabase-js');

const sb  = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
const sbp = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);

// ─── helpers ─────────────────────────────────────────────────────────────────
const json  = (data, status = 200) => ({ statusCode: status, headers: cors(), body: JSON.stringify(data) });
const err   = (msg,  status = 500) => json({ error: msg }, status);
const cors  = () => ({
  'Content-Type':                'application/json',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods':'GET,POST,PUT,DELETE,PATCH,OPTIONS',
  'Access-Control-Allow-Headers':'Content-Type,x-admin-token'
});

function body(event) {
  if (!event.body) return {};
  try { return JSON.parse(event.body); } catch { return {}; }
}

function isAdmin(event) {
  const token = event.headers['x-admin-token'] || event.headers['X-Admin-Token'];
  return token === process.env.ADMIN_SESSION_TOKEN;
}

// ─── main handler ────────────────────────────────────────────────────────────
exports.handler = async (event) => {
  // Preflight CORS
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers: cors(), body: '' };
  }

  const method = event.httpMethod;

  // Strip the function prefix — Netlify passes the full path
  // e.g.  /.netlify/functions/api/projects/123  →  /projects/123
  //       /api/projects/123  (via redirect :splat) → path in event.path is full path
  // We normalise to just the part after /api
  let path = event.path || '/';
  // Remove known prefixes
  path = path.replace(/^\/.netlify\/functions\/api/, '');
  path = path.replace(/^\/api/, '');
  if (!path) path = '/';

  // Split into segments, remove empty
  const segments = path.split('/').filter(Boolean);
  // segments[0] = resource (projects, config, auth, ...)
  // segments[1] = id (optional)
  const resource = segments[0] || '';
  const id       = segments[1] || '';
  const sub      = segments[2] || ''; // e.g. "read" in /contact/id/read

  console.log(`[BrisaDev] ${method} /${resource}${id?'/'+id:''}${sub?'/'+sub:''}`);

  try {

    // ── HEALTH ───────────────────────────────────────────────────────────────
    if (resource === 'health') {
      const { error } = await sb.from('site_config').select('id').single();
      return json({ status: 'ok', supabase: error ? '❌ '+error.message : '✅ Ligado' });
    }

    // ── AUTH ─────────────────────────────────────────────────────────────────
    if (resource === 'auth') {
      if (method !== 'POST') return err('Method not allowed', 405);
      const { username, password } = body(event);
      if (!username || !password) return err('Campos em falta', 400);
      const { data: cfg } = await sb.from('site_config').select('admin_user,admin_pass_hash').single();
      if (!cfg || cfg.admin_user !== username) return err('Credenciais inválidas', 401);
      const valid = await bcrypt.compare(password, cfg.admin_pass_hash);
      if (!valid) return err('Credenciais inválidas', 401);
      return json({ token: process.env.ADMIN_SESSION_TOKEN, ok: true });
    }

    // ── PROJECTS ─────────────────────────────────────────────────────────────
    if (resource === 'projects') {
      // GET /projects  or  GET /projects/:id
      if (method === 'GET') {
        if (id) {
          const { data, error } = await sbp.from('projects').select('*').eq('id', id).single();
          if (error) return err('Não encontrado', 404);
          return json(data);
        }
        const category = (event.queryStringParameters || {}).category;
        let q = sbp.from('projects').select('*').order('created_at', { ascending: false });
        if (category && category !== 'all') q = q.eq('category', category);
        const { data, error } = await q;
        if (error) return err(error.message);
        return json(data);
      }

      // POST /projects  (create)
      if (method === 'POST') {
        if (!isAdmin(event)) return err('Não autorizado', 401);
        const { name, description, category, status, url, icon, tech, img_url, video_url, gallery } = body(event);
        if (!name || !category) return err('name e category obrigatórios', 400);
        const { data, error } = await sb.from('projects')
          .insert([{ name, description, category, status: status||'development', url, icon: icon||'🌐', tech: tech||[], img_url, video_url, gallery: gallery||[] }])
          .select().single();
        if (error) return err(error.message);
        return json(data, 201);
      }

      // PUT /projects/:id  (update)
      if (method === 'PUT') {
        if (!isAdmin(event)) return err('Não autorizado', 401);
        if (!id) return err('ID em falta', 400);
        const { name, description, category, status, url, icon, tech, img_url, video_url, gallery } = body(event);
        const { data, error } = await sb.from('projects')
          .update({ name, description, category, status, url, icon, tech, img_url, video_url, gallery })
          .eq('id', id).select().single();
        if (error) return err(error.message);
        return json(data);
      }

      // DELETE /projects/:id
      if (method === 'DELETE') {
        if (!isAdmin(event)) return err('Não autorizado', 401);
        if (!id) return err('ID em falta', 400);
        const { error } = await sb.from('projects').delete().eq('id', id);
        if (error) return err(error.message);
        return json({ ok: true });
      }

      return err('Method not allowed', 405);
    }

    // ── CONFIG ───────────────────────────────────────────────────────────────
    if (resource === 'config') {
      if (method === 'GET') {
        const { data, error } = await sbp.from('site_config')
          .select('email,whatsapp,response_time,hero_badge,hero_line1,hero_line2,hero_line3,hero_sub,stat1_num,stat1_lbl,stat2_num,stat2_lbl,stat3_num,stat3_lbl,stat4_num,stat4_lbl,about_p1,about_p2,about_p3,p1_price,p1_delivery,p1_features,p2_price,p2_delivery,p2_features,p3_price,p3_delivery,p3_features')
          .single();
        if (error) return err(error.message);
        return json(data);
      }
      if (method === 'PATCH') {
        if (!isAdmin(event)) return err('Não autorizado', 401);
        const allowed = ['email','whatsapp','response_time','hero_badge','hero_line1','hero_line2','hero_line3','hero_sub','stat1_num','stat1_lbl','stat2_num','stat2_lbl','stat3_num','stat3_lbl','stat4_num','stat4_lbl','about_p1','about_p2','about_p3','p1_price','p1_delivery','p1_features','p2_price','p2_delivery','p2_features','p3_price','p3_delivery','p3_features'];
        const b = body(event);
        const updates = {};
        allowed.forEach(k => { if (b[k] !== undefined) updates[k] = b[k]; });
        if (b.admin_user) updates.admin_user = b.admin_user;
        if (b.admin_pass) updates.admin_pass_hash = await bcrypt.hash(b.admin_pass, 10);
        const { data, error } = await sb.from('site_config').update(updates).eq('id', 1).select().single();
        if (error) return err(error.message);
        return json(data);
      }
      return err('Method not allowed', 405);
    }

    // ── CONTACT ──────────────────────────────────────────────────────────────
    if (resource === 'contact') {
      if (method === 'POST' && !id) {
        const { name, email, phone, project_type, message } = body(event);
        if (!name || !email) return err('Nome e email obrigatórios', 400);
        await sb.from('contact_messages').insert([{ name, email, phone, project_type, message }]);
        return json({ ok: true });
      }
      if (method === 'GET') {
        if (!isAdmin(event)) return err('Não autorizado', 401);
        const { data, error } = await sb.from('contact_messages').select('*').order('created_at', { ascending: false });
        if (error) return err(error.message);
        return json(data);
      }
      if (method === 'PATCH' && sub === 'read') {
        if (!isAdmin(event)) return err('Não autorizado', 401);
        await sb.from('contact_messages').update({ read: true }).eq('id', id);
        return json({ ok: true });
      }
      return err('Method not allowed', 405);
    }

    // ── UPLOAD ───────────────────────────────────────────────────────────────
    if (resource === 'upload') {
      // Netlify Functions don't support multipart well — we receive base64 body
      // The frontend converts to base64 already in uploadFileToAPI()
      if (!isAdmin(event)) return err('Não autorizado', 401);
      if (method !== 'POST') return err('Method not allowed', 405);
      const b = body(event);
      if (!b.fileData || !b.fileName || !b.mimeType) return err('fileData, fileName e mimeType obrigatórios', 400);
      const buffer = Buffer.from(b.fileData, 'base64');
      const { error } = await sb.storage.from('brisadev-media').upload(b.fileName, buffer, { contentType: b.mimeType, upsert: false });
      if (error) return err(error.message);
      const { data: { publicUrl } } = sb.storage.from('brisadev-media').getPublicUrl(b.fileName);
      return json({ url: publicUrl });
    }

    // ── STRIPE PAYMENT INTENT ─────────────────────────────────────────────────
    if (resource === 'create-payment-intent') {
      if (method !== 'POST') return err('Method not allowed', 405);
      const { amount, currency, name, email, phone, desc, plan } = body(event);
      if (!amount || !email) return err('Campos em falta', 400);
      const existing = await stripe.customers.list({ email, limit: 1 });
      const customer = existing.data.length > 0
        ? existing.data[0]
        : await stripe.customers.create({ email, name, phone: phone||undefined });
      const pi = await stripe.paymentIntents.create({
        amount: Math.round(amount), currency: currency||'eur',
        customer: customer.id, receipt_email: email,
        description: `BrisaDev — ${plan}`,
        metadata: { customer_name: name, customer_email: email, customer_phone: phone||'', project_desc: desc||'', plan: plan||'' },
        automatic_payment_methods: { enabled: true }
      });
      await sb.from('orders').insert([{
        stripe_payment_id: pi.id, stripe_customer_id: customer.id,
        plan, amount_eur: amount/100, status: 'pending',
        customer_name: name, customer_email: email, customer_phone: phone||'', project_desc: desc||''
      }]);
      return json({ clientSecret: pi.client_secret });
    }

    // ── STRIPE WEBHOOK ────────────────────────────────────────────────────────
    if (resource === 'webhook') {
      if (method !== 'POST') return err('Method not allowed', 405);
      let event2;
      try {
        event2 = stripe.webhooks.constructEvent(
          event.body,
          event.headers['stripe-signature'],
          process.env.STRIPE_WEBHOOK_SECRET
        );
      } catch (e) { return err('Webhook error: ' + e.message, 400); }
      const pi = event2.data.object;
      if (event2.type === 'payment_intent.succeeded') {
        await sb.from('orders').update({ status: 'succeeded' }).eq('stripe_payment_id', pi.id);
      }
      if (event2.type === 'payment_intent.payment_failed') {
        await sb.from('orders').update({ status: 'failed' }).eq('stripe_payment_id', pi.id);
      }
      if (event2.type === 'charge.refunded') {
        await sb.from('orders').update({ status: 'refunded' }).eq('stripe_payment_id', event2.data.object.payment_intent);
      }
      return json({ received: true });
    }

    // ── ORDERS ────────────────────────────────────────────────────────────────
    if (resource === 'orders') {
      if (!isAdmin(event)) return err('Não autorizado', 401);
      const { data, error } = await sb.from('orders').select('*').order('created_at', { ascending: false });
      if (error) return err(error.message);
      return json(data);
    }

    // 404
    return err(`Rota não encontrada: ${method} /${resource}`, 404);

  } catch (e) {
    console.error('[BrisaDev] Erro não tratado:', e.message, e.stack);
    return err('Erro interno: ' + e.message, 500);
  }
};
