// File ini harus berada di: functions/api/[[path]].js
// Membutuhkan binding D1 bernama DB. Tabel dibuat otomatis saat pertama dipakai.

const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');
const rnd = (n) => hex(crypto.getRandomValues(new Uint8Array(n)));
const ITER = 30000; // dijaga rendah agar muat di batas CPU 10 ms paket gratis Cloudflare

const SCHEMA = [
  'CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT UNIQUE, salt TEXT, hash TEXT, created INTEGER)',
  'CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id TEXT, exp INTEGER)',
  'CREATE TABLE IF NOT EXISTS data (user_id TEXT PRIMARY KEY, json TEXT, updated INTEGER)',
];
let ready = false;
async function init(env) {
  if (ready) return;
  await env.DB.batch(SCHEMA.map((q) => env.DB.prepare(q)));
  ready = true;
}

async function hashPw(pw, salt) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: new TextEncoder().encode(salt), iterations: ITER },
    key, 256
  );
  return hex(bits);
}

async function newSession(env, id, username) {
  const token = rnd(32);
  const now = Date.now();
  await env.DB.prepare('INSERT INTO sessions(token,user_id,exp) VALUES(?,?,?)').bind(token, id, now + 30 * 24 * 3600 * 1000).run();
  if (Math.random() < 0.05) await env.DB.prepare('DELETE FROM sessions WHERE exp<?').bind(now).run();
  return { token, username };
}

async function who(request, env) {
  const t = (request.headers.get('authorization') || '').replace('Bearer ', '');
  if (!t) return null;
  return await env.DB.prepare(
    'SELECT s.user_id AS id, u.username AS username FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.exp>?'
  ).bind(t, Date.now()).first();
}

async function body(request) {
  try { return await request.json(); } catch (e) { return null; }
}

export async function onRequest({ request, env }) {
  const path = new URL(request.url).pathname.replace(/^\/api\/?/, '').replace(/\/$/, '');
  const method = request.method;
  if (!env.DB) return J({ error: 'Database belum terhubung. Buat binding D1 dengan nama DB lalu deploy ulang.' }, 500);
  try {
    await init(env);

    if (path === 'health') return J({ ok: true });

    if (path === 'register' && method === 'POST') {
      const b = await body(request);
      if (!b) return J({ error: 'Permintaan tidak valid.' }, 400);
      const u = String(b.username || '').trim().toLowerCase();
      const pw = String(b.password || '');
      if (!/^[a-z0-9._]{3,20}$/.test(u)) return J({ error: 'Username 3–20 karakter: huruf, angka, titik, atau garis bawah.' }, 400);
      if (pw.length < 6 || pw.length > 100) return J({ error: 'Kata sandi minimal 6 karakter.' }, 400);
      if (await env.DB.prepare('SELECT 1 AS x FROM users WHERE username=?').bind(u).first()) return J({ error: 'Username sudah dipakai.' }, 409);
      const id = rnd(8), salt = rnd(16);
      try {
        await env.DB.prepare('INSERT INTO users(id,username,salt,hash,created) VALUES(?,?,?,?,?)')
          .bind(id, u, salt, await hashPw(pw, salt), Date.now()).run();
      } catch (e) { return J({ error: 'Username sudah dipakai.' }, 409); }
      return J(await newSession(env, id, u));
    }

    if (path === 'login' && method === 'POST') {
      const b = await body(request);
      if (!b) return J({ error: 'Permintaan tidak valid.' }, 400);
      const u = String(b.username || '').trim().toLowerCase();
      const row = await env.DB.prepare('SELECT id,salt,hash FROM users WHERE username=?').bind(u).first();
      if (!row || (await hashPw(String(b.password || ''), row.salt)) !== row.hash) return J({ error: 'Username atau kata sandi salah.' }, 400);
      return J(await newSession(env, row.id, u));
    }

    const me = await who(request, env);
    if (!me) return J({ error: 'Belum masuk.' }, 401);

    if (path === 'me' && method === 'GET') return J({ username: me.username });

    if (path === 'logout' && method === 'POST') {
      const t = (request.headers.get('authorization') || '').replace('Bearer ', '');
      await env.DB.prepare('DELETE FROM sessions WHERE token=?').bind(t).run();
      return J({ ok: true });
    }

    if (path === 'data' && method === 'GET') {
      const r = await env.DB.prepare('SELECT json FROM data WHERE user_id=?').bind(me.id).first();
      return J({ data: r ? JSON.parse(r.json) : null });
    }

    if (path === 'data' && method === 'PUT') {
      const text = await request.text();
      if (text.length > 900000) return J({ error: 'Data terlalu besar.' }, 413);
      let b = null;
      try { b = JSON.parse(text); } catch (e) {}
      if (!b || !b.data || !Array.isArray(b.data.v) || !Array.isArray(b.data.t)) return J({ error: 'Format data tidak valid.' }, 400);
      await env.DB.prepare(
        'INSERT INTO data(user_id,json,updated) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET json=excluded.json, updated=excluded.updated'
      ).bind(me.id, JSON.stringify(b.data), Date.now()).run();
      return J({ ok: true });
    }

    return J({ error: 'Tidak ditemukan.' }, 404);
  } catch (e) {
    return J({ error: 'Terjadi kesalahan di server.' }, 500);
  }
}
