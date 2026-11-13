// CIT HOD Office Desk - single serverless API for Vercel. Roles: staff, admin (HOD), superadmin.
const { neon } = require('@neondatabase/serverless');
const c = require('crypto');
const SEC = process.env.AUTH_SECRET || '';
const sql = process.env.DATABASE_URL ? neon(process.env.DATABASE_URL) : null;
const q = (t, p) => (sql.query ? sql.query(t, p || []) : sql(t, p || []));
const ST = ['Pending', 'In progress', 'Done'];
const NOW = "to_char(now() at time zone 'Asia/Karachi','YYYY-MM-DD HH24:MI')";
const MUT = { 'users.add': 'Account created', 'users.set': 'Account changed', 'users.edit': 'Staff details edited', 'tasks.add': 'Task assigned', 'task.set': 'Task status updated', 'task.del': 'Task deleted', 'leave.apply': 'Leave recorded', 'leave.decide': 'Leave decision', 'mis.add': 'Misconduct report filed', 'mis.del': 'Misconduct report deleted', 'tutors.save': 'Tutor assignment saved', 'tutors.del': 'Tutor assignment removed', 'tt.save': 'Timetable entry saved', 'tt.del': 'Timetable entry removed', 'notes.add': 'Note added' };
let ready;

const SCHEMA = 'v4';
async function ddl() {
    const now = "to_char(now() at time zone 'Asia/Karachi','YYYY-MM-DD HH24:MI')";
    await q(`CREATE TABLE IF NOT EXISTS users(id serial PRIMARY KEY, username text UNIQUE NOT NULL, name text NOT NULL, role text NOT NULL, pass text NOT NULL, days text DEFAULT '1,2,3,4,5', active boolean DEFAULT true, created text DEFAULT ${now})`);
    await q(`CREATE TABLE IF NOT EXISTS tasks(id serial PRIMARY KEY, title text NOT NULL, type text, due text, time text, pri text, scope text, created_by int, created text DEFAULT ${now})`);
    await q(`CREATE TABLE IF NOT EXISTS assign(id serial PRIMARY KEY, task_id int NOT NULL, user_id int NOT NULL, status text DEFAULT 'Pending', note text DEFAULT '', image text, updated text DEFAULT ${now})`);
    await q(`CREATE TABLE IF NOT EXISTS leaves(id serial PRIMARY KEY, user_id int NOT NULL, from_d text, to_d text, type text, reason text, status text DEFAULT 'Pending', decided_by int, created text DEFAULT ${now})`);
    await q(`CREATE TABLE IF NOT EXISTS misconduct(id serial PRIMARY KEY, user_id int NOT NULL, date text, category text, descr text, action text, reported_by int, created text DEFAULT ${now})`);
    for (const col of ["designation text DEFAULT ''", "subjects text DEFAULT ''", "phone text DEFAULT ''", "email text DEFAULT ''", "updated text", "updated_by text"]) await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS ${col}`);
    await q(`CREATE TABLE IF NOT EXISTS tutors(id serial PRIMARY KEY, user_id int NOT NULL, class_name text, year text, section text, since text, created text DEFAULT ${now}, updated text, updated_by text)`);
    await q(`CREATE TABLE IF NOT EXISTS tt(id serial PRIMARY KEY, user_id int NOT NULL, day int, t_from text, t_to text, subject text, class_name text, room text, created text DEFAULT ${now}, updated text, updated_by text)`);
    await q(`CREATE TABLE IF NOT EXISTS notes(id serial PRIMARY KEY, ref text, ref_id int, user_id int, body text, created text DEFAULT ${now})`);
    await q(`CREATE TABLE IF NOT EXISTS audit(id serial PRIMARY KEY, at text DEFAULT ${now}, user_id int, name text, action text, detail text)`);
    await q("CREATE TABLE IF NOT EXISTS login_fail(k text PRIMARY KEY, n int, t bigint)");
    await q('CREATE TABLE IF NOT EXISTS meta(k text PRIMARY KEY, v text)');
    await q("INSERT INTO meta(k,v) VALUES('schema',$1) ON CONFLICT (k) DO UPDATE SET v=$1", [SCHEMA]);
}
async function schemaOk() {
  const m = await q("SELECT to_regclass('public.meta') AS m");
  if (!m[0].m) return false;
  const v = await q("SELECT v FROM meta WHERE k='schema'");
  return !!(v[0] && v[0].v === SCHEMA);
}
function init() {
  return ready || (ready = (async () => {
    if (!(await schemaOk())) {
      try { await ddl(); } catch (e) { await new Promise(r => setTimeout(r, 400)); if (!(await schemaOk())) await ddl(); }
    }
    const n = await q('SELECT count(*)::int AS n FROM users');
    if (n[0].n === 0 && process.env.SUPERADMIN_USER && process.env.SUPERADMIN_PASS)
      await q('INSERT INTO users(username,name,role,pass,days) VALUES($1,$2,$3,$4,$5) ON CONFLICT (username) DO NOTHING', [process.env.SUPERADMIN_USER.toLowerCase(), 'Super Admin', 'superadmin', hash(process.env.SUPERADMIN_PASS), '1,2,3,4,5']);
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
const send = async (res, code, o) => {
  if (code === 200 && res._a && MUT[res._a]) { try { await q('INSERT INTO audit(user_id,name,action,detail) VALUES($1,$2,$3,$4)', [res._u.id, res._u.name, MUT[res._a], res._d]); } catch (e) { console.error(e); } }
  res.statusCode = code; res.setHeader('Content-Type', 'application/json'); res.setHeader('Cache-Control', 'no-store'); res.end(JSON.stringify(o));
};
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
      const un = S(b.username).toLowerCase(), ip = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim(), key = (un + '|' + ip).slice(0, 120), nowMs = Date.now(), WIN = 15 * 60e3;
      const f = (await q('SELECT n,t FROM login_fail WHERE k=$1', [key]))[0];
      if (f && f.n >= 5 && nowMs - Number(f.t) < WIN) return send(res, 429, { e: 'Too many wrong attempts. Try again in ' + Math.ceil((WIN - (nowMs - Number(f.t))) / 60e3) + ' minutes.' });
      const r = await q('SELECT * FROM users WHERE username=$1', [un]);
      if (!r[0] || !r[0].active || !check(String(b.password || ''), r[0].pass)) {
        const n = f && nowMs - Number(f.t) < WIN ? f.n + 1 : 1;
        await q('INSERT INTO login_fail(k,n,t) VALUES($1,$2,$3) ON CONFLICT (k) DO UPDATE SET n=$2,t=$3', [key, n, nowMs]);
        return send(res, 401, { e: 'Wrong username or password.' });
      }
      if (f) await q('DELETE FROM login_fail WHERE k=$1', [key]);
      setTok(res, sign({ id: r[0].id, exp: Date.now() + 12 * 3600e3 }), 43200);
      return send(res, 200, { ok: 1 });
    }
    if (a === 'logout') { setTok(res, '', 0); return send(res, 200, { ok: 1 }); }

    const t = unsign(cookie(req, 'tok'));
    const ur = t && await q('SELECT id,username,name,role,days,active,designation,subjects,phone,email,updated,updated_by FROM users WHERE id=$1', [t.id]);
    const u = ur && ur[0];
    if (!u || !u.active) return send(res, 401, { e: 'Please sign in.' });
    const ADM = u.role !== 'staff', SUP = u.role === 'superadmin';
    const deny = () => send(res, 403, { e: 'Not allowed for your role.' });
    res._a = a; res._u = u;
    res._d = Object.entries(b).filter(([k]) => !['a', 'pass', 'password', 'image', 'text', 'descr', 'note', 'action'].includes(k)).map(([k, v]) => k + '=' + String(Array.isArray(v) ? v.join(',') : v).slice(0, 40)).join(', ').slice(0, 200);

    if (a === 'me') return send(res, 200, { me: u });

    if (a === 'progress') {
      const td = new Date(Date.now() + 5 * 3600e3).toISOString().slice(0, 10);
      return send(res, 200, { rows: await q("SELECT u.id,u.name,count(a.id)::int AS total,(count(*) FILTER (WHERE a.status='Done'))::int AS done,(count(*) FILTER (WHERE a.status<>'Done' AND t.due<$1))::int AS late FROM users u LEFT JOIN assign a ON a.user_id=u.id LEFT JOIN tasks t ON t.id=a.task_id WHERE u.role='staff' AND u.active GROUP BY u.id,u.name ORDER BY u.name", [td]) });
    }
    if (a === 'users.list') {
      if (!ADM) return deny();
      return send(res, 200, { users: await q('SELECT id,username,name,role,days,active,designation,subjects,phone,email,updated,updated_by,created FROM users ORDER BY role DESC,name') });
    }
    if (a === 'users.add') {
      if (!ADM) return deny();
      const role = ['staff', 'admin', 'superadmin'].includes(b.role) ? b.role : 'staff';
      if (role !== 'staff' && !SUP) return deny();
      const un = S(b.username).toLowerCase(), nm = S(b.name), pw = String(b.password || '');
      if (!/^[a-z0-9._-]{3,30}$/.test(un) || !nm || pw.length < 6) return send(res, 400, { e: 'Username (3-30 letters/numbers), name and a password of 6+ characters are required.' });
      const days = (Array.isArray(b.days) ? b.days : [1, 2, 3, 4, 5]).filter(x => x >= 0 && x <= 6).join(',');
      try { await q(`INSERT INTO users(username,name,role,pass,days,designation,subjects,phone,email,updated,updated_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,${NOW},$10)`, [un, nm, role, hash(pw), days, S(b.designation), S(b.subjects), S(b.phone).slice(0, 30), S(b.email).slice(0, 100), u.name]); }
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
      await q("DELETE FROM notes WHERE ref='task' AND ref_id IN (SELECT id FROM assign WHERE task_id=$1)", [+b.id]);
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

    if (a === 'users.edit') {
      const id = +b.id, r = (await q('SELECT role FROM users WHERE id=$1', [id]))[0];
      if (!r) return send(res, 404, { e: 'User not found.' });
      if (!ADM && id !== u.id) return deny();
      if (ADM && r.role !== 'staff' && !SUP && id !== u.id) return deny();
      const ph = S(b.phone).slice(0, 30), em = S(b.email).slice(0, 100);
      if (ADM) {
        if (!S(b.name)) return send(res, 400, { e: 'Name is required.' });
        await q(`UPDATE users SET name=$1,designation=$2,subjects=$3,phone=$4,email=$5,updated=${NOW},updated_by=$6 WHERE id=$7`, [S(b.name), S(b.designation), S(b.subjects), ph, em, u.name, id]);
      } else await q(`UPDATE users SET phone=$1,email=$2,updated=${NOW},updated_by=$3 WHERE id=$4`, [ph, em, u.name, id]);
      return send(res, 200, { ok: 1 });
    }

    if (a === 'tutors.list') {
      const sel = 'SELECT t.*,u.name FROM tutors t JOIN users u ON u.id=t.user_id';
      return send(res, 200, { tutors: ADM ? await q(sel + ' ORDER BY u.name,t.class_name') : await q(sel + ' WHERE t.user_id=$1 ORDER BY t.class_name', [u.id]) });
    }
    if (a === 'tutors.save') {
      if (!ADM) return deny();
      const uid = +b.uid;
      if (!S(b.class_name) || !(await q("SELECT 1 FROM users WHERE id=$1 AND role='staff'", [uid])).length) return send(res, 400, { e: 'Choose a staff member and enter the class.' });
      if (+b.id) await q(`UPDATE tutors SET user_id=$1,class_name=$2,year=$3,section=$4,since=$5,updated=${NOW},updated_by=$6 WHERE id=$7`, [uid, S(b.class_name), S(b.year), S(b.section), D(b.since), u.name, +b.id]);
      else await q(`INSERT INTO tutors(user_id,class_name,year,section,since,updated,updated_by) VALUES($1,$2,$3,$4,$5,${NOW},$6)`, [uid, S(b.class_name), S(b.year), S(b.section), D(b.since), u.name]);
      return send(res, 200, { ok: 1 });
    }
    if (a === 'tutors.del') {
      if (!ADM) return deny();
      await q("DELETE FROM notes WHERE ref='tutor' AND ref_id=$1", [+b.id]); await q('DELETE FROM tutors WHERE id=$1', [+b.id]);
      return send(res, 200, { ok: 1 });
    }

    if (a === 'tt.list') return send(res, 200, { tt: await q('SELECT t.*,u.name FROM tt t JOIN users u ON u.id=t.user_id ORDER BY t.day,t.t_from') });
    if (a === 'tt.save') {
      if (!ADM) return deny();
      const uid = +b.uid, day = +b.day, f = S(b.t_from), t = S(b.t_to), id = +b.id || 0, re = /^([01]\d|2[0-3]):[0-5]\d$/;
      if (!uid || !(day >= 0 && day <= 6) || !re.test(f) || !re.test(t) || t <= f || !S(b.subject)) return send(res, 400, { e: 'Teacher, day, valid from and to times, and subject are required.' });
      if ((await q('SELECT 1 FROM tt WHERE user_id=$1 AND day=$2 AND t_from<$4 AND t_to>$3 AND id<>$5', [uid, day, f, t, id])).length) return send(res, 400, { e: 'This teacher already has a class in that time slot.' });
      if (S(b.room) && (await q('SELECT 1 FROM tt WHERE lower(room)=lower($1) AND day=$2 AND t_from<$4 AND t_to>$3 AND id<>$5', [S(b.room), day, f, t, id])).length) return send(res, 400, { e: 'That room is already used in that time slot.' });
      const v = [uid, day, f, t, S(b.subject), S(b.class_name), S(b.room), u.name];
      if (id) await q(`UPDATE tt SET user_id=$1,day=$2,t_from=$3,t_to=$4,subject=$5,class_name=$6,room=$7,updated=${NOW},updated_by=$8 WHERE id=$9`, v.concat([id]));
      else await q(`INSERT INTO tt(user_id,day,t_from,t_to,subject,class_name,room,updated,updated_by) VALUES($1,$2,$3,$4,$5,$6,$7,${NOW},$8)`, v);
      return send(res, 200, { ok: 1 });
    }
    if (a === 'tt.del') { if (!ADM) return deny(); await q('DELETE FROM tt WHERE id=$1', [+b.id]); return send(res, 200, { ok: 1 }); }

    if (a === 'notes.list' || a === 'notes.add') {
      const ref = b.ref === 'tutor' ? 'tutor' : 'task', id = +b.id;
      const o = (await q(ref === 'task' ? 'SELECT user_id FROM assign WHERE id=$1' : 'SELECT user_id FROM tutors WHERE id=$1', [id]))[0];
      if (!o) return send(res, 404, { e: 'Record not found.' });
      if (!ADM && o.user_id !== u.id) return deny();
      if (a === 'notes.add') {
        if (!S(b.text)) return send(res, 400, { e: 'Write a note first.' });
        await q('INSERT INTO notes(ref,ref_id,user_id,body) VALUES($1,$2,$3,$4)', [ref, id, u.id, S(b.text)]);
        return send(res, 200, { ok: 1 });
      }
      return send(res, 200, { notes: await q('SELECT n.body,n.created,u.name FROM notes n JOIN users u ON u.id=n.user_id WHERE n.ref=$1 AND n.ref_id=$2 ORDER BY n.id', [ref, id]) });
    }
    if (a === 'audit.list') {
      if (!ADM) return deny();
      return send(res, 200, { audit: await q('SELECT at,name,action,detail FROM audit ORDER BY id DESC LIMIT 300') });
    }
    return send(res, 400, { e: 'Unknown action.' });
  } catch (e) {
    console.error(e);
    return send(res, 500, { e: 'Server error. Check the Vercel function logs.' });
  }
};
