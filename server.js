/**
 * BrisaDev — Backend com Supabase + Stripe
 * ==========================================
 * INSTALAÇÃO:  npm install
 * CONFIGURAÇÃO: cp .env.example .env  →  preenche as variáveis
 * ARRANCAR:     npm start  |  npm run dev
 */

require('dotenv').config();

const express    = require('express');
const cors       = require('cors');
const path       = require('path');
const crypto     = require('crypto');
const bcrypt     = require('bcrypt');
const multer     = require('multer');
const stripe     = require('stripe')(process.env.STRIPE_SECRET_KEY);
const nodemailer = require('nodemailer');
const { createClient } = require('@supabase/supabase-js');

// ─── Supabase (service_role — só no backend, NUNCA expõe no frontend) ─────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);
// Supabase anon key — para leitura pública
const supabasePublic = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

const app    = express();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use('/api/webhook', express.raw({ type: 'application/json' }));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(cors({ origin: process.env.FRONTEND_URL || '*', methods: ['GET','POST','PUT','DELETE','PATCH'] }));
app.use(express.static(path.join(__dirname)));

// ─── Email ────────────────────────────────────────────────────────────────────
const mailer = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: Number(process.env.SMTP_PORT) || 587,
  secure: false,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
});
async function sendEmail({ to, subject, html }) {
  if (!process.env.SMTP_USER) return;
  try { await mailer.sendMail({ from: `"BrisaDev" <${process.env.SMTP_USER}>`, to, subject, html }); }
  catch (e) { console.error('Email error:', e.message); }
}

// ─── JWT helpers (sem dependências externas) ─────────────────────────────────
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

// ─── Admin auth middleware ────────────────────────────────────────────────────
async function requireAdmin(req, res, next) {
  const token = req.headers['x-admin-token'];
  if (!verifyToken(token)) {
    return res.status(401).json({ error: 'Não autorizado' });
  }
  next();
}

// ══════════════════════════════════════════════════════════════════════════════
// AUTH
// ══════════════════════════════════════════════════════════════════════════════

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Campos em falta' });
  const { data: cfg } = await supabase.from('site_config').select('admin_user,admin_pass_hash').single();
  if (!cfg || cfg.admin_user !== username) return res.status(401).json({ error: 'Credenciais inválidas' });
  const valid = await bcrypt.compare(password, cfg.admin_pass_hash);
  if (!valid) return res.status(401).json({ error: 'Credenciais inválidas' });
  const token = signToken({ role: 'admin', exp: Date.now() + 24 * 60 * 60 * 1000 });
  res.json({ token, ok: true });
});

// ══════════════════════════════════════════════════════════════════════════════
// PROJETOS
// ══════════════════════════════════════════════════════════════════════════════

app.get('/api/projects', async (req, res) => {
  const { category } = req.query;
  let q = supabasePublic.from('projects').select('*').order('created_at', { ascending: false });
  if (category && category !== 'all') q = q.eq('category', category);
  const { data, error } = await q;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.get('/api/projects/:id', async (req, res) => {
  const { data, error } = await supabasePublic.from('projects').select('*').eq('id', req.params.id).single();
  if (error) return res.status(404).json({ error: 'Não encontrado' });
  res.json(data);
});

app.post('/api/projects', requireAdmin, async (req, res) => {
  const { name, description, category, status, url, icon, tech, img_url, video_url, gallery } = req.body;
  if (!name || !category) return res.status(400).json({ error: 'name e category obrigatórios' });
  const { data, error } = await supabase.from('projects')
    .insert([{ name, description, category, status: status||'development', url, icon: icon||'🌐', tech: tech||[], img_url, video_url, gallery: gallery||[] }])
    .select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.status(201).json(data);
});

app.put('/api/projects/:id', requireAdmin, async (req, res) => {
  const { name, description, category, status, url, icon, tech, img_url, video_url, gallery } = req.body;
  const { data, error } = await supabase.from('projects')
    .update({ name, description, category, status, url, icon, tech, img_url, video_url, gallery })
    .eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/api/projects/:id', requireAdmin, async (req, res) => {
  const { error } = await supabase.from('projects').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════════════════════
// UPLOAD → Supabase Storage
// ══════════════════════════════════════════════════════════════════════════════

app.post('/api/upload', requireAdmin, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Ficheiro em falta' });
  const ext  = req.file.originalname.split('.').pop();
  const name = `${Date.now()}-${Math.random().toString(36).slice(2)}.${ext}`;
  const { error } = await supabase.storage
    .from('brisadev-media').upload(name, req.file.buffer, { contentType: req.file.mimetype });
  if (error) return res.status(500).json({ error: error.message });
  const { data: { publicUrl } } = supabase.storage.from('brisadev-media').getPublicUrl(name);
  res.json({ url: publicUrl });
});

// ══════════════════════════════════════════════════════════════════════════════
// CONFIGURAÇÕES DO SITE
// ══════════════════════════════════════════════════════════════════════════════

app.get('/api/config', async (req, res) => {
  const { data, error } = await supabasePublic
    .from('site_config')
    .select('email,whatsapp,response_time,hero_badge,hero_line1,hero_line2,hero_line3,hero_sub,stat1_num,stat1_lbl,stat2_num,stat2_lbl,stat3_num,stat3_lbl,stat4_num,stat4_lbl,about_p1,about_p2,about_p3,p1_price,p1_delivery,p1_features,p2_price,p2_delivery,p2_features,p3_price,p3_delivery,p3_features')
    .single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.patch('/api/config', requireAdmin, async (req, res) => {
  const allowed = ['email','whatsapp','response_time','hero_badge','hero_line1','hero_line2','hero_line3','hero_sub','stat1_num','stat1_lbl','stat2_num','stat2_lbl','stat3_num','stat3_lbl','stat4_num','stat4_lbl','about_p1','about_p2','about_p3','p1_price','p1_delivery','p1_features','p2_price','p2_delivery','p2_features','p3_price','p3_delivery','p3_features'];
  const updates = {};
  allowed.forEach(k => { if (req.body[k] !== undefined) updates[k] = req.body[k]; });
  if (req.body.admin_user) updates.admin_user = req.body.admin_user;
  if (req.body.admin_pass) updates.admin_pass_hash = await bcrypt.hash(req.body.admin_pass, 10);
  const { data, error } = await supabase.from('site_config').update(updates).eq('id', 1).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ══════════════════════════════════════════════════════════════════════════════
// MENSAGENS DE CONTACTO
// ══════════════════════════════════════════════════════════════════════════════

app.post('/api/contact', async (req, res) => {
  const { name, email, phone, project_type, message } = req.body;
  if (!name || !email) return res.status(400).json({ error: 'Nome e email obrigatórios' });
  await supabase.from('contact_messages').insert([{ name, email, phone, project_type, message }]);
  await sendEmail({
    to: process.env.SMTP_USER,
    subject: `📩 Nova mensagem de ${name}`,
    html: `<p><b>Nome:</b> ${name}</p><p><b>Email:</b> ${email}</p><p><b>Projeto:</b> ${project_type||'-'}</p><p><b>Mensagem:</b><br>${message||'-'}</p>`
  });
  res.json({ ok: true });
});

app.get('/api/contact', requireAdmin, async (req, res) => {
  const { data, error } = await supabase.from('contact_messages').select('*').order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.patch('/api/contact/:id/read', requireAdmin, async (req, res) => {
  await supabase.from('contact_messages').update({ read: true }).eq('id', req.params.id);
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════════════════════
// STRIPE
// ══════════════════════════════════════════════════════════════════════════════

app.post('/api/create-payment-intent', async (req, res) => {
  const { amount, currency, name, email, phone, desc, plan } = req.body;
  if (!amount || !email) return res.status(400).json({ error: 'Campos em falta' });
  try {
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

    await supabase.from('orders').insert([{
      stripe_payment_id: pi.id, stripe_customer_id: customer.id,
      plan, amount_eur: amount/100, status: 'pending',
      customer_name: name, customer_email: email, customer_phone: phone||'', project_desc: desc||''
    }]);

    res.json({ clientSecret: pi.client_secret });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/orders', requireAdmin, async (req, res) => {
  const { data, error } = await supabase.from('orders').select('*').order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/webhook', async (req, res) => {
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) { return res.status(400).send(`Webhook Error: ${err.message}`); }

  const pi = event.data.object;

  if (event.type === 'payment_intent.succeeded') {
    await supabase.from('orders').update({ status: 'succeeded' }).eq('stripe_payment_id', pi.id);
    const { customer_name, customer_email, plan } = pi.metadata;
    await sendEmail({
      to: customer_email,
      subject: `✅ Pagamento confirmado — ${plan}`,
      html: `<div style="font-family:sans-serif;padding:2rem"><h2 style="color:#ff2d78">BrisaDev</h2><p>Olá <b>${customer_name}</b>, pagamento de <b>€${(pi.amount/100).toFixed(2)}</b> confirmado para o plano <b>${plan}</b>. Entraremos em contacto em breve!</p></div>`
    });
    console.log(`✅ ${customer_email} | ${plan} | €${(pi.amount/100).toFixed(2)}`);
  }
  if (event.type === 'payment_intent.payment_failed') {
    await supabase.from('orders').update({ status: 'failed' }).eq('stripe_payment_id', pi.id);
  }
  if (event.type === 'charge.refunded') {
    await supabase.from('orders').update({ status: 'refunded' }).eq('stripe_payment_id', event.data.object.payment_intent);
  }

  res.json({ received: true });
});

// ─── Health check ─────────────────────────────────────────────────────────────
app.get('/api/health', async (req, res) => {
  const { error } = await supabase.from('site_config').select('id').single();
  res.json({
    status: 'ok', service: 'BrisaDev',
    supabase: error ? '❌ ' + error.message : '✅ Ligado',
    stripe: process.env.STRIPE_SECRET_KEY ? '✅ Configurado' : '⚠️ Em falta'
  });
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n🚀 BrisaDev em http://localhost:${PORT}`);
  console.log(`🗄️  Supabase: ${process.env.SUPABASE_URL ? '✅' : '⚠️  SUPABASE_URL em falta'}`);
  console.log(`💳 Stripe:   ${process.env.STRIPE_SECRET_KEY ? '✅' : '⚠️  STRIPE_SECRET_KEY em falta'}\n`);
});
