// CIT HOD Office Desk - single serverless API for Vercel. Roles: staff, admin (HOD), superadmin.
const { neon } = require('@neondatabase/serverless');
const c = require('crypto');
const SEC = process.env.AUTH_SECRET || '';
const sql = process.env.DATABASE_URL ? neon(process.env.DATABASE_URL) : null;
const q = (t, p) => (sql.query ? sql.query(t, p || []) : sql(t, p || []));
const ST = ['Pending', 'In progress', 'Done'];
let ready;

function init() {
  return ready || (ready = (async () => {
    const now = "to_char(now() at time zone 'Asia/Karachi','YYYY-MM-DD HH24:MI')";
    await q(`CREATE TABLE IF NOT EXISTS users(id serial PRIMARY KEY, username text UNIQUE NOT NULL, name text NOT NULL, role text NOT NULL, pass text NOT NULL, days text DEFAULT '1,2,3,4,5', active boolean DEFAULT true, created text DEFAULT ${now})`);
    await q(`CREATE TABLE IF NOT EXISTS tasks(id serial PRIMARY KEY, title text NOT NULL, type text, due text, time text, pri text, scope text, created_by int, created text DEFAULT ${now})`);
    await q(`CREATE TABLE IF NOT EXISTS assign(id serial PRIMARY KEY, task_id int NOT NULL, user_id int NOT NULL, status text DEFAULT 'Pending', note text DEFAULT '', image text, updated text DEFAULT ${now})`);
    await q(`CREATE TABLE IF NOT EXISTS leaves(id serial PRIMARY KEY, user_id int NOT NULL, from_d text, to_d text, type text, reason text, status text DEFAULT 'Pending', decided_by int, created text DEFAULT ${now})`);
    await q(`CREATE TABLE IF NOT EXISTS misconduct(id serial PRIMARY KEY, user_id int NOT NULL, date text, category text, descr text, action text, reported_by int, created text DEFAULT ${now})`);
    const n = await q('SELECT count(*)::int AS n FROM users');
    if (n[0].n === 0 && process.env.SUPERADMIN_USER && process.env.SUPERADMIN_PASS)
      await q('INSERT INTO users(username,name,role,pass,days) VALUES($1,$2,$3,$4,$5)', [process.env.SUPERADMIN_USER.toLowerCase(), 'Super Admin', 'superadmin', hash(process.env.SUPERADMIN_PASS), '1,2,3,4,5']);
  })().catch(e => { ready = null; throw e; }));
}
function hash(p) { const s = c.randomBytes(16).toString('hex'); return s + ':' + c.scryptSync(p, s, 32).toString('hex'); }
function check(p, h) { const [s, x] = h.split(':'); const y = c.scryptSync(p, s, 32); return c.timingSafeEqual(y, Buffer.from(x, 'hex')); }
const b64 = s => Buffer.from(s).toString('base64url');
const mac = s => c.createHmac('sha256', SEC).update(s).digest('base64url');
function sign(o) { const p = b64(JSON.stringify(o)); return p + '.' + mac(p); }
function unsign(t) {
  const [p, m] = String(t || '').split('.'); if (!p || !m) return null;
  const a = Buffer.from(m), b = Buffer.from(mac(p)); if (a.length !== b.length || !c.timingSafeEqual(a, b)) return null;
  const o = JSON.parse(Buffer.from(p, 'base64url').toString()); return o.exp > Date.now() ? o : null;
}
function cookie(req, k) { const m = (req.headers.cookie || '').split(/;\s*/).find(x => x.startsWith(k + '=')); return m ? m.slice(k.length + 1) : ''; }
const send = (res, code, o) => { res.statusCode = code; res.setHeader('Content-Type', 'application/json'); res.setHeader('Cache-Control', 'no-store'); res.end(JSON.stringify(o)); };
const setTok = (res, v, age) => res.setHeader('Set-Cookie', `tok=${v}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${age}`);
const S = v => String(v == null ? '' : v).trim().slice(0, 600);
const D = v => /^\d{4}-\d{2}-\d{2}$/.test(v) ? v : '';

module.exports = async (req, res) => {
  try {
    if (req.method !== 'POST') return send(res, 405, { e: 'Use POST.' });
    if (!sql || SEC.length < 16) return send(res, 500, { e: 'Server not configured. Set DATABASE_URL and AUTH_SECRET (16+ characters) in Vercel.' });
    await init();
    const b = req.body || {}, a = b.a;

    if (a === 'login') {
      const r = await q('SELECT * FROM users WHERE username=$1', [S(b.username).toLowerCase()]);
      if (!r[0] || !r[0].active || !check(String(b.password || ''), r[0].pass)) return send(res, 401, { e: 'Wrong username or password.' });
      setTok(res, sign({ id: r[0].id, exp: Date.now() + 12 * 3600e3 }), 43200);
      return send(res, 200, { ok: 1 });
    }
    if (a === 'logout') { setTok(res, '', 0); return send(res, 200, { ok: 1 }); }

    const t = unsign(cookie(req, 'tok'));
    const ur = t && await q('SELECT id,username,name,role,days,active FROM users WHERE id=$1', [t.id]);
    const u = ur && ur[0];
    if (!u || !u.active) return send(res, 401, { e: 'Please sign in.' });
    const ADM = u.role !== 'staff', SUP = u.role === 'superadmin';
    const deny = () => send(res, 403, { e: 'Not allowed for your role.' });

    if (a === 'me') return send(res, 200, { me: u });

    if (a === 'users.list') {
      if (!ADM) return deny();
      return send(res, 200, { users: await q('SELECT id,username,name,role,days,active,created FROM users ORDER BY role DESC,name') });
    }
    if (a === 'users.add') {
      if (!ADM) return deny();
      const role = ['staff', 'admin', 'superadmin'].includes(b.role) ? b.role : 'staff';
      if (role !== 'staff' && !SUP) return deny();
      const un = S(b.username).toLowerCase(), nm = S(b.name), pw = String(b.password || '');
      if (!/^[a-z0-9._-]{3,30}$/.test(un) || !nm || pw.length < 6) return send(res, 400, { e: 'Username (3-30 letters/numbers), name and a password of 6+ characters are required.' });
      const days = (Array.isArray(b.days) ? b.days : [1, 2, 3, 4, 5]).filter(x => x >= 0 && x <= 6).join(',');
      try { await q('INSERT INTO users(username,name,role,pass,days) VALUES($1,$2,$3,$4,$5)', [un, nm, role, hash(pw), days]); }
      catch (e) { return send(res, 400, { e: 'That username already exists.' }); }
      return send(res, 200, { ok: 1 });
    }
    if (a === 'users.set') {
      if (!ADM) return deny();
      const r = (await q('SELECT role FROM users WHERE id=$1', [+b.id]))[0];
      if (!r) return send(res, 404, { e: 'User not found.' });
      if (r.role !== 'staff' && !SUP) return deny();
      if (b.id === u.id && b.active === false) return send(res, 400, { e: 'You cannot deactivate yourself.' });
      if (typeof b.active === 'boolean') await q('UPDATE users SET active=$1 WHERE id=$2', [b.active, +b.id]);
      if (b.pass) { if (String(b.pass).length < 6) return send(res, 400, { e: 'Password must be 6+ characters.' }); await q('UPDATE users SET pass=$1 WHERE id=$2', [hash(String(b.pass)), +b.id]); }
      if (Array.isArray(b.days)) await q('UPDATE users SET days=$1 WHERE id=$2', [b.days.filter(x => x >= 0 && x <= 6).join(','), +b.id]);
      return send(res, 200, { ok: 1 });
    }

    if (a === 'tasks.add') {
      if (!ADM) return deny();
      const scope = ['single', 'partial', 'all'].includes(b.scope) ? b.scope : 'single';
      let ids;
      if (scope === 'all') ids = (await q("SELECT id FROM users WHERE role='staff' AND active")).map(x => x.id);
      else {
        const want = (Array.isArray(b.ids) ? b.ids : []).map(Number);
        ids = (await q("SELECT id FROM users WHERE role='staff' AND active AND id=ANY($1::int[])", [want])).map(x => x.id);
        if (scope === 'single') ids = ids.slice(0, 1);
      }
      if (!S(b.title) || !D(b.due) || !ids.length) return send(res, 400, { e: 'Title, deadline and at least one staff member are required.' });
      const tk = await q('INSERT INTO tasks(title,type,due,time,pri,scope,created_by) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id', [S(b.title), S(b.type), b.due, S(b.time), ['High', 'Medium', 'Low'].includes(b.pri) ? b.pri : 'Medium', scope, u.id]);
      for (const i of ids) await q('INSERT INTO assign(task_id,user_id) VALUES($1,$2)', [tk[0].id, i]);
      return send(res, 200, { ok: 1, count: ids.length });
    }
    if (a === 'tasks.list') {
      const sel = 'SELECT a.id,a.task_id,a.user_id,u.name,a.status,a.note,(a.image IS NOT NULL) AS img,a.updated FROM assign a JOIN users u ON u.id=a.user_id';
      if (ADM) return send(res, 200, { tasks: await q('SELECT * FROM tasks ORDER BY due,id'), as: await q(sel + ' ORDER BY a.id') });
      return send(res, 200, {
        tasks: await q('SELECT * FROM tasks WHERE id IN (SELECT task_id FROM assign WHERE user_id=$1) ORDER BY due,id', [u.id]),
        as: await q(sel + ' WHERE a.user_id=$1 ORDER BY a.id', [u.id])
      });
    }
    if (a === 'task.set') {
      const r = (await q('SELECT user_id FROM assign WHERE id=$1', [+b.id]))[0];
      if (!r) return send(res, 404, { e: 'Task not found.' });
      if (!ADM && r.user_id !== u.id) return deny();
      if (!ST.includes(b.status)) return send(res, 400, { e: 'Invalid status.' });
      let img = undefined;
      if (b.image === '') img = null;
      else if (b.image) {
        if (!/^data:image\/(jpeg|png|webp);base64,/.test(b.image) || b.image.length > 600000) return send(res, 400, { e: 'Photo must be a JPEG, PNG or WebP under about 400 KB.' });
        img = b.image;
      }
      if (img === undefined) await q("UPDATE assign SET status=$1,note=$2,updated=to_char(now() at time zone 'Asia/Karachi','YYYY-MM-DD HH24:MI') WHERE id=$3", [b.status, S(b.note), +b.id]);
      else await q("UPDATE assign SET status=$1,note=$2,image=$3,updated=to_char(now() at time zone 'Asia/Karachi','YYYY-MM-DD HH24:MI') WHERE id=$4", [b.status, S(b.note), img, +b.id]);
      return send(res, 200, { ok: 1 });
    }
    if (a === 'task.img') {
      const r = (await q('SELECT user_id,image FROM assign WHERE id=$1', [+b.id]))[0];
      if (!r || (!ADM && r.user_id !== u.id)) return deny();
      return send(res, 200, { image: r.image });
    }
    if (a === 'task.del') {
      if (!ADM) return deny();
      await q('DELETE FROM assign WHERE task_id=$1', [+b.id]); await q('DELETE FROM tasks WHERE id=$1', [+b.id]);
      return send(res, 200, { ok: 1 });
    }

    if (a === 'leave.apply') {
      const uid = ADM && b.uid ? +b.uid : u.id;
      if (!D(b.from) || !D(b.to) || b.to < b.from) return send(res, 400, { e: 'Enter valid from and to dates.' });
      await q('INSERT INTO leaves(user_id,from_d,to_d,type,reason,status,decided_by) VALUES($1,$2,$3,$4,$5,$6,$7)', [uid, b.from, b.to, S(b.type) || 'Casual', S(b.reason), ADM && b.uid ? 'Approved' : 'Pending', ADM && b.uid ? u.id : null]);
      return send(res, 200, { ok: 1 });
    }
    if (a === 'leave.list') {
      const sel = 'SELECT l.*,u.name FROM leaves l JOIN users u ON u.id=l.user_id';
      return send(res, 200, { leaves: ADM ? await q(sel + ' ORDER BY l.from_d DESC') : await q(sel + ' WHERE l.user_id=$1 ORDER BY l.from_d DESC', [u.id]) });
    }
    if (a === 'leave.decide') {
      if (!ADM || !['Approved', 'Rejected'].includes(b.status)) return deny();
      await q('UPDATE leaves SET status=$1,decided_by=$2 WHERE id=$3', [b.status, u.id, +b.id]);
      return send(res, 200, { ok: 1 });
    }

    if (a === 'mis.add') {
      if (!ADM) return deny();
      if (!+b.uid || !D(b.date) || !S(b.descr)) return send(res, 400, { e: 'Staff member, date and description are required.' });
      await q('INSERT INTO misconduct(user_id,date,category,descr,action,reported_by) VALUES($1,$2,$3,$4,$5,$6)', [+b.uid, b.date, S(b.category), S(b.descr), S(b.action), u.id]);
      return send(res, 200, { ok: 1 });
    }
    if (a === 'mis.list') {
      if (!ADM) return deny();
      return send(res, 200, { mis: await q('SELECT m.*,u.name,r.name AS reporter FROM misconduct m JOIN users u ON u.id=m.user_id LEFT JOIN users r ON r.id=m.reported_by ORDER BY m.date DESC') });
    }
    if (a === 'mis.del') {
      if (!SUP) return deny();
      await q('DELETE FROM misconduct WHERE id=$1', [+b.id]); return send(res, 200, { ok: 1 });
    }
    return send(res, 400, { e: 'Unknown action.' });
  } catch (e) {
    console.error(e);
    return send(res, 500, { e: 'Server error. Check the Vercel function logs.' });
  }
};
