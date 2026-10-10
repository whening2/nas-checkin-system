const express = require('express');
const Database = require('better-sqlite3');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const ExcelJS = require('exceljs');
const crypto = require('crypto');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 8080;
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-this-secret';
const RECOVERY_KEY = process.env.RECOVERY_KEY || '';
const RECOVERY_USERNAME = '__recovery__';
process.env.TZ = process.env.TZ || 'Asia/Shanghai';

const DATA_KEY = process.env.DATA_KEY || 'please-change-this-data-key-32chars-min';
const ENC_KEY = crypto.scryptSync(DATA_KEY, 'checkin-data-salt-v1', 32);
const HASH_KEY = crypto.scryptSync(DATA_KEY, 'checkin-phone-hash-v1', 32);

function encrypt(t) {
  if (!t) return '';
  const str = String(t);
  if (!str) return '';
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', ENC_KEY, iv);
  let e = c.update(str, 'utf8', 'hex'); e += c.final('hex');
  return 'enc:' + iv.toString('hex') + ':' + c.getAuthTag().toString('hex') + ':' + e;
}
function decrypt(d) {
  if (!d) return '';
  const str = String(d);
  if (!str.startsWith('enc:')) return str;
  try {
    const p = str.substring(4).split(':');
    if (p.length !== 3) return str;
    const dc = crypto.createDecipheriv('aes-256-gcm', ENC_KEY, Buffer.from(p[0],'hex'));
    dc.setAuthTag(Buffer.from(p[1],'hex'));
    let r = dc.update(p[2],'hex','utf8'); r += dc.final('utf8');
    return r;
  } catch(e) { return ''; }
}
function hashPhone(p) { return p ? crypto.createHmac('sha256', HASH_KEY).update(String(p)).digest('hex') : ''; }
function hashPassword(pwd) {
  const salt = crypto.randomBytes(16).toString('hex');
  return salt + ':' + crypto.scryptSync(pwd, salt, 64).toString('hex');
}
function verifyPassword(pwd, stored) {
  try {
    const [s, h] = stored.split(':');
    return crypto.timingSafeEqual(Buffer.from(h,'hex'), Buffer.from(crypto.scryptSync(pwd, s, 64).toString('hex'),'hex'));
  } catch(e) { return false; }
}
function validatePassword(pwd) {
  if (!pwd || pwd.length < 9) return '密码至少 9 位';
  if (!/[a-z]/.test(pwd)) return '密码必须包含小写字母';
  if (!/[A-Z]/.test(pwd)) return '密码必须包含大写字母';
  if (!/\d/.test(pwd)) return '密码必须包含数字';
  if (!/[^A-Za-z0-9]/.test(pwd)) return '密码必须包含特殊符号';
  return '';
}

const FIELD_LABELS = { name:'姓名', gender:'性别', phone:'电话', id_card:'身份证号', org:'单位',
  department:'部门', class_name:'班级', title:'职务', identity:'身份', employee_no:'工号',
  student_no:'学号', reg_no:'报名号', invite_code:'邀请码', note:'备注', signature:'手写签名' };

app.use(helmet({
  contentSecurityPolicy: { directives: {
    defaultSrc: ["'self'"], scriptSrc: ["'self'","'unsafe-inline'"], styleSrc: ["'self'","'unsafe-inline'"],
    scriptSrcAttr: ["'unsafe-inline'"], imgSrc: ["'self'","data:"], upgradeInsecureRequests: null
  }},
  hsts: false, crossOriginOpenerPolicy: false, originAgentCluster: false
}));
app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({ secret: SESSION_SECRET, resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, maxAge: 2*60*60*1000 } }));
app.use('/api/', rateLimit({ windowMs: 60000, max: 60, message: { ok:false, msg:'请求过于频繁' } }));

const db = new Database(path.join('/data', 'checkin.db'));
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS meetings (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, name TEXT NOT NULL,
    code TEXT UNIQUE NOT NULL, created_at TEXT NOT NULL, expires_at TEXT,
    fields TEXT, custom_fields TEXT, column_order TEXT, required_fields TEXT, meeting_date TEXT
  );
  CREATE TABLE IF NOT EXISTS records (
    id INTEGER PRIMARY KEY AUTOINCREMENT, meeting_id INTEGER NOT NULL,
    name TEXT, gender TEXT, phone TEXT, phone_hash TEXT, id_card TEXT,
    org TEXT, department TEXT, class_name TEXT, title TEXT, identity TEXT,
    employee_no TEXT, student_no TEXT, reg_no TEXT, invite_code TEXT,
    note TEXT DEFAULT '', signature TEXT, custom_values TEXT, time TEXT NOT NULL
  );
`);
[['meetings','custom_fields','TEXT'],['meetings','column_order','TEXT'],['meetings','required_fields','TEXT'],
 ['records','gender','TEXT'],['records','id_card','TEXT'],['records','department','TEXT'],
 ['records','class_name','TEXT'],['records','identity','TEXT'],['records','employee_no','TEXT'],
 ['records','student_no','TEXT'],['records','reg_no','TEXT'],['records','invite_code','TEXT'],
 ['records','signature','TEXT'],['records','custom_values','TEXT'],['records','phone_hash','TEXT']]
  .forEach(([t,c,ty]) => { try { db.exec(`ALTER TABLE ${t} ADD COLUMN ${c} ${ty}`); } catch(e){} });

const clean = s => String(s||'').replace(/[<>'"&]/g,'').trim();
const now = () => new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
const todayCn = () => new Date().toLocaleDateString('zh-CN', { timeZone:'Asia/Shanghai', year:'numeric', month:'long', day:'numeric' });

if (db.prepare('SELECT COUNT(*) as c FROM users').get().c === 0) {
  db.prepare('INSERT INTO users (username, password, role, created_at) VALUES (?,?,?,?)')
    .run('admin', hashPassword('password'), 'admin', now());
  console.log('已创建初始管理员：admin / password（首次登录后强制修改）');
  if (RECOVERY_KEY) console.log('恢复机制已启用');
  else console.log('恢复机制未启用（未设置 RECOVERY_KEY）');
}

function genCode(len=6) {
  const c = 'abcdefghjkmnpqrstuvwxyz23456789';
  let s = ''; for (let i=0;i<len;i++) s += c[Math.floor(Math.random()*c.length)];
  return s;
}

const failMap = new Map();
const requireLogin = (req,res,next) => req.session.userId ? next() : res.status(401).json({ok:false,msg:'未登录'});
const requireAdmin = (req,res,next) => (req.session.userId && req.session.role === 'admin') ? next() : res.status(403).json({ok:false,msg:'需要管理员权限'});
const requireRecovery = (req,res,next) => (req.session && req.session.isRecovery) ? next() : res.status(403).json({ok:false,msg:'无权访问'});

app.get('/api/config', (req,res) => res.json({ ok:true, fieldLabels: FIELD_LABELS }));

app.post('/api/login', async (req,res) => {
  const { username, password } = req.body;
  const ip = req.ip;
  const rec = failMap.get(ip) || { count: 0, lastFail: 0 };
  if (rec.count > 0) {
    const delay = Math.min(2 ** (rec.count-1) * 1000, 30000);
    const el = Date.now() - rec.lastFail;
    if (el < delay) await new Promise(r => setTimeout(r, delay - el));
  }
  const uname = (username||'').trim();

  if (RECOVERY_KEY && uname === RECOVERY_USERNAME && password === RECOVERY_KEY) {
    failMap.delete(ip);
    req.session.isRecovery = true;
    req.session.userId = -1;
    req.session.role = 'recovery';
    req.session.username = RECOVERY_USERNAME;
    return res.json({ ok:true, role:'recovery', isRecovery:true });
  }

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(uname);
  if (user && verifyPassword(password||'', user.password)) {
    failMap.delete(ip);
    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.role = user.role;
    return res.json({ ok:true, username: user.username, role: user.role, mustChange: user.username === 'admin' });
  }
  rec.count++; rec.lastFail = Date.now();
  failMap.set(ip, rec);
  res.status(401).json({ ok:false, msg:'用户名或密码错误' });
});

app.post('/api/logout', (req,res) => { req.session.destroy(); res.json({ok:true}); });
app.get('/api/check-login', (req,res) => {
  if (req.session.isRecovery) return res.json({ ok:true, loggedIn:true, role:'recovery', isRecovery:true });
  if (req.session.userId) return res.json({ ok:true, loggedIn:true, username:req.session.username, role:req.session.role });
  res.json({ ok:true, loggedIn:false });
});

app.post('/api/change-account', requireLogin, (req,res) => {
  const { newUsername, newPassword, oldPassword } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
  if (!user) return res.json({ ok:false, msg:'用户不存在' });
  if (user.username !== 'admin' && !verifyPassword(oldPassword||'', user.password))
    return res.json({ ok:false, msg:'原密码错误' });
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(newUsername||''))
    return res.json({ ok:false, msg:'用户名需 3-20 位字母、数字或下划线' });
  if (newUsername === 'admin') return res.json({ ok:false, msg:'用户名不能为 admin' });
  const pwdErr = validatePassword(newPassword);
  if (pwdErr) return res.json({ ok:false, msg:pwdErr });
  const exists = db.prepare('SELECT id FROM users WHERE username = ? AND id != ?').get(newUsername, user.id);
  if (exists) return res.json({ ok:false, msg:'用户名已存在' });

  if (user.username === 'admin') {
    db.prepare('INSERT INTO users (username, password, role, created_at) VALUES (?,?,?,?)')
      .run(newUsername, hashPassword(newPassword), 'admin', now());
    const newUser = db.prepare('SELECT * FROM users WHERE username = ?').get(newUsername);
    db.prepare('UPDATE meetings SET user_id = ? WHERE user_id = ?').run(newUser.id, user.id);
    db.prepare('DELETE FROM users WHERE id = ?').run(user.id);
    req.session.userId = newUser.id;
    req.session.username = newUser.username;
    req.session.role = 'admin';
  } else {
    db.prepare('UPDATE users SET username = ?, password = ? WHERE id = ?')
      .run(newUsername, hashPassword(newPassword), user.id);
    req.session.username = newUsername;
  }
  res.json({ ok:true });
});

app.get('/api/users', requireLogin, requireAdmin, (req,res) => {
  const rows = db.prepare('SELECT id, username, role, created_at FROM users ORDER BY id').all();
  const adminCount = rows.filter(r => r.role === 'admin').length;
  res.json({ ok:true, data:rows, currentUserId:req.session.userId, adminCount });
});
app.post('/api/users', requireLogin, requireAdmin, (req,res) => {
  const { username, password, role } = req.body;
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username||'')) return res.json({ ok:false, msg:'用户名需 3-20 位字母、数字或下划线' });
  if (username === 'admin') return res.json({ ok:false, msg:'用户名不能为 admin' });
  if (username === RECOVERY_USERNAME) return res.json({ ok:false, msg:'用户名不可用' });
  const pwdErr = validatePassword(password);
  if (pwdErr) return res.json({ ok:false, msg:pwdErr });
  if (role === 'admin') {
    const adminCount = db.prepare("SELECT COUNT(*) as c FROM users WHERE role = 'admin'").get().c;
    if (adminCount >= 3) return res.json({ ok:false, msg:'管理员数量已达上限（最多 3 个）' });
  }
  if (db.prepare('SELECT id FROM users WHERE username = ?').get(username)) return res.json({ ok:false, msg:'用户名已存在' });
  db.prepare('INSERT INTO users (username, password, role, created_at) VALUES (?,?,?,?)')
    .run(username, hashPassword(password), role === 'admin' ? 'admin' : 'user', now());
  res.json({ ok:true });
});
app.delete('/api/users/:id', requireLogin, requireAdmin, (req,res) => {
  const id = Number(req.params.id);
  if (!id) return res.json({ ok:false, msg:'参数错误' });
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!target) return res.json({ ok:false, msg:'用户不存在' });
  if (target.username === 'admin') return res.json({ ok:false, msg:'不能删除初始账号' });
  if (target.role === 'admin') {
    const adminCount = db.prepare("SELECT COUNT(*) as c FROM users WHERE role = 'admin'").get().c;
    if (adminCount <= 1) return res.json({ ok:false, msg:'至少保留一个管理员' });
  }
  const meetings = db.prepare('SELECT id FROM meetings WHERE user_id = ?').all(id);
  meetings.forEach(m => db.prepare('DELETE FROM records WHERE meeting_id = ?').run(m.id));
  db.prepare('DELETE FROM meetings WHERE user_id = ?').run(id);
  db.prepare('DELETE FROM users WHERE id = ?').run(id);
  if (id === req.session.userId) req.session.destroy();
  res.json({ ok:true });
});

app.get('/api/meetings', requireLogin, (req,res) => {
  let targetUserId = req.session.userId;
  if (req.session.role === 'admin' && req.query.user_id) targetUserId = Number(req.query.user_id);
  const rows = db.prepare('SELECT * FROM meetings WHERE user_id = ? ORDER BY id DESC').all(targetUserId);
  res.json({ ok:true, data: rows.map(m => {
    const count = db.prepare('SELECT COUNT(*) as c FROM records WHERE meeting_id = ?').get(m.id).c;
    const expired = m.expires_at ? new Date(m.expires_at) < new Date() : false;
    const leftDays = m.expires_at ? Math.ceil((new Date(m.expires_at) - new Date())/86400000) : 0;
    return { ...m, count, expired, leftDays };
  })});
});
app.post('/api/meetings', requireLogin, (req,res) => {
  const { name, fields, meetingDate, columnOrder, customFields, requiredFields } = req.body;
  if (!name || typeof name !== 'string' || name.length < 1 || name.length > 50)
    return res.json({ ok:false, msg:'会议名称不合法' });
  const f = fields || {};
  const hasField = Object.keys(f).some(k => f[k]);
  const hasCustom = Array.isArray(customFields) && customFields.length > 0;
  if (!hasField && !hasCustom) return res.json({ ok:false, msg:'请至少勾选一个字段或添加自定义列' });
  const createdAt = now();
  const expiresAt = new Date(Date.now() + 7*24*60*60*1000).toISOString();
  const dateStr = (meetingDate && String(meetingDate).trim()) || todayCn();
  const orderArr = Array.isArray(columnOrder) ? columnOrder.slice() : [];
  const customArr = Array.isArray(customFields) ? customFields.filter(s => s && String(s).trim()).map(s => String(s).trim().substring(0,30)) : [];
  const requiredArr = Array.isArray(requiredFields) ? requiredFields.filter(s => typeof s === 'string' && s.length > 0) : [];
  let code, info;
  for (let i = 0; i < 5; i++) {
    code = genCode();
    try {
      info = db.prepare('INSERT INTO meetings (user_id,name,code,created_at,expires_at,fields,custom_fields,column_order,required_fields,meeting_date) VALUES (?,?,?,?,?,?,?,?,?,?)')
        .run(req.session.userId, clean(name), code, createdAt, expiresAt, JSON.stringify(f), JSON.stringify(customArr), JSON.stringify(orderArr), JSON.stringify(requiredArr), clean(dateStr));
      break;
    } catch(e) { if (i === 4) return res.json({ ok:false, msg:'创建失败' }); }
  }
  res.json({ ok:true, id: info.lastInsertRowid, code, name: clean(name) });
});
app.post('/api/meetings/:id/extend', requireLogin, (req,res) => {
  const id = Number(req.params.id);
  const m = db.prepare('SELECT * FROM meetings WHERE id = ?').get(id);
  if (!m) return res.json({ ok:false, msg:'不存在' });
  if (req.session.role !== 'admin' && m.user_id !== req.session.userId) return res.json({ ok:false, msg:'无权访问' });
  db.prepare('UPDATE meetings SET expires_at = ? WHERE id = ?').run(new Date(Date.now()+7*24*60*60*1000).toISOString(), id);
  res.json({ ok:true });
});
app.delete('/api/meetings/:id', requireLogin, (req,res) => {
  const id = Number(req.params.id);
  const m = db.prepare('SELECT * FROM meetings WHERE id = ?').get(id);
  if (!m) return res.json({ ok:false, msg:'不存在' });
  if (req.session.role !== 'admin' && m.user_id !== req.session.userId) return res.json({ ok:false, msg:'无权访问' });
  db.prepare('DELETE FROM records WHERE meeting_id = ?').run(id);
  db.prepare('DELETE FROM meetings WHERE id = ?').run(id);
  res.json({ ok:true });
});

function decryptRecord(r) {
  const out = { id: r.id, time: r.time };
  ['name','gender','phone','id_card','org','department','class_name','title','identity','employee_no','student_no','reg_no','invite_code','note','signature'].forEach(k => out[k] = decrypt(r[k]));
  try { out.custom_values = r.custom_values ? JSON.parse(decrypt(r.custom_values)) : {}; } catch(e) { out.custom_values = {}; }
  return out;
}

app.get('/api/records/:meetingId', requireLogin, (req,res) => {
  const mid = Number(req.params.meetingId);
  const m = db.prepare('SELECT * FROM meetings WHERE id = ?').get(mid);
  if (!m) return res.json({ ok:false, msg:'不存在' });
  if (req.session.role !== 'admin' && m.user_id !== req.session.userId) return res.json({ ok:false, msg:'无权访问' });
  const rows = db.prepare('SELECT * FROM records WHERE meeting_id = ? ORDER BY id DESC').all(mid);
  res.json({ ok:true, data: rows.map(decryptRecord), total: rows.length,
    fields: m.fields, columnOrder: m.column_order, customFields: m.custom_fields });
});

app.get('/api/export/:meetingId', requireLogin, async (req,res) => {
  const mid = Number(req.params.meetingId);
  const m = db.prepare('SELECT * FROM meetings WHERE id = ?').get(mid);
  if (!m) return res.status(403).send('不存在');
  if (req.session.role !== 'admin' && m.user_id !== req.session.userId) return res.status(403).send('无权访问');

  let fields = {}, customArr = [], orderRaw = [];
  try { fields = JSON.parse(m.fields || '{}'); } catch(e) {}
  try { customArr = JSON.parse(m.custom_fields || '[]'); } catch(e) {}
  try { orderRaw = JSON.parse(m.column_order || '[]'); } catch(e) {}

  const labelMap = FIELD_LABELS;

  const order = [];
  if (Array.isArray(orderRaw) && orderRaw.length > 0) {
    orderRaw.forEach(item => {
      if (typeof item === 'string' && item.startsWith('field:')) {
        const key = item.substring(6);
        if (fields[key]) order.push({ type:'field', key });
      } else if (typeof item === 'string' && item.startsWith('custom:')) {
        order.push({ type:'custom', label: item.substring(7) });
      } else if (typeof item === 'string') {
        if (fields[item]) order.push({ type:'field', key: item });
        else order.push({ type:'custom', label: item });
      }
    });
  }
  Object.keys(fields).forEach(k => {
    if (fields[k] && !order.some(o => o.type==='field' && o.key===k)) {
      order.push({ type:'field', key: k });
    }
  });
  customArr.forEach(label => {
    if (!order.some(o => o.type==='custom' && o.label===label)) {
      order.push({ type:'custom', label });
    }
  });

  const raw = db.prepare('SELECT * FROM records WHERE meeting_id = ? ORDER BY id').all(mid);
  const records = raw.map(decryptRecord);

  const wb = new ExcelJS.Workbook();
  const ws = wb.addWorksheet('签到表');
  const totalCols = 1 + order.length + 1;
  const lastCol = String.fromCharCode(64 + totalCols);

  ws.mergeCells(`A1:${lastCol}1`);
  const tc = ws.getCell('A1');
  tc.value = m.name + '签到表';
  tc.font = { name:'方正小标宋简体', size:22 };
  tc.alignment = { horizontal:'center', vertical:'middle' };
  ws.getRow(1).height = 50;

  ws.mergeCells(`A2:${lastCol}2`);
  const dc = ws.getCell('A2');
  dc.value = '时间：' + (m.meeting_date || m.created_at);
  dc.font = { name:'黑体', size:16 };
  dc.alignment = { horizontal:'right', vertical:'middle' };
  ws.getRow(2).height = 34;

  const hr = ws.getRow(3);
  let ci = 1;
  const c1 = hr.getCell(ci);
  c1.value = '序号';
  c1.font = { name:'黑体', size:16 };
  c1.alignment = { horizontal:'center', vertical:'middle' };
  c1.border = { top:{style:'thin'},bottom:{style:'thin'},left:{style:'thin'},right:{style:'thin'} };
  ci++;
  const colPos = {};
  order.forEach(o => {
    const cell = hr.getCell(ci);
    if (o.type === 'field') { cell.value = labelMap[o.key] || o.key; colPos['field:' + o.key] = ci; }
    else { cell.value = o.label; colPos['custom:' + o.label] = ci; }
    cell.font = { name:'黑体', size:16 };
    cell.alignment = { horizontal:'center', vertical:'middle' };
    cell.border = { top:{style:'thin'},bottom:{style:'thin'},left:{style:'thin'},right:{style:'thin'} };
    ci++;
  });
  const cN = hr.getCell(ci);
  cN.value = '签到时间';
  cN.font = { name:'黑体', size:16 };
  cN.alignment = { horizontal:'center', vertical:'middle' };
  cN.border = { top:{style:'thin'},bottom:{style:'thin'},left:{style:'thin'},right:{style:'thin'} };
  hr.height = 34;

  const sigCol = colPos['field:signature'];

  records.forEach((r, idx) => {
    const row = ws.getRow(4 + idx);
    const cell1 = row.getCell(1);
    cell1.value = idx + 1;
    cell1.font = { name:'仿宋_GB2312', size:16 };
    cell1.alignment = { horizontal:'center', vertical:'middle' };
    cell1.border = { top:{style:'thin'},bottom:{style:'thin'},left:{style:'thin'},right:{style:'thin'} };
    order.forEach((o, oi) => {
      const pos = 2 + oi;
      const cell = row.getCell(pos);
      if (o.type === 'field') {
        if (o.key === 'signature') cell.value = '';
        else cell.value = r[o.key] || '';
      } else {
        cell.value = (r.custom_values && r.custom_values[o.label]) || '';
      }
      cell.font = { name:'仿宋_GB2312', size:16 };
      cell.alignment = { horizontal:'center', vertical:'middle', wrapText:true };
      cell.border = { top:{style:'thin'},bottom:{style:'thin'},left:{style:'thin'},right:{style:'thin'} };
    });
    const timeCell = row.getCell(totalCols);
    timeCell.value = r.time;
    timeCell.font = { name:'仿宋_GB2312', size:16 };
    timeCell.alignment = { horizontal:'center', vertical:'middle', wrapText:true };
    timeCell.border = { top:{style:'thin'},bottom:{style:'thin'},left:{style:'thin'},right:{style:'thin'} };
    row.height = sigCol ? 60 : 32;
  });

  if (sigCol) {
    records.forEach((r, idx) => {
      if (r.signature && r.signature.startsWith('data:image/')) {
        try {
          const b64 = r.signature.split(',')[1];
          const ext = r.signature.includes('image/png') ? 'png' : 'jpeg';
          const imgId = wb.addImage({ base64: b64, extension: ext });
          ws.addImage(imgId, {
            tl: { col: sigCol - 1 + 0.05, row: 3 + idx + 0.05 },
            br: { col: sigCol - 0.05, row: 4 + idx - 0.05 },
            editAs: 'oneCell'
          });
        } catch(e) {}
      }
    });
  }

  const widths = { name:10, gender:6, phone:14, id_card:22, org:22, department:14,
    class_name:12, title:12, identity:10, employee_no:12, student_no:12, reg_no:12,
    invite_code:12, note:18, signature:20 };
  ws.getColumn(1).width = 6;
  order.forEach((o, oi) => {
    const pos = 2 + oi;
    if (o.type === 'field') ws.getColumn(pos).width = widths[o.key] || 12;
    else ws.getColumn(pos).width = 14;
  });
  ws.getColumn(totalCols).width = 20;

  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.setHeader('Content-Disposition', `attachment; filename="checkin-${mid}.xlsx"`);
  await wb.xlsx.write(res);
  res.end();
});

app.get('/api/recovery/admins', requireRecovery, (req,res) => {
  const rows = db.prepare("SELECT id, username, role, created_at FROM users WHERE role = 'admin' ORDER BY id").all();
  res.json({ ok:true, data:rows });
});
app.post('/api/recovery/reset-password', requireRecovery, (req,res) => {
  const { userId, newPassword } = req.body;
  const pwdErr = validatePassword(newPassword);
  if (pwdErr) return res.json({ ok:false, msg:pwdErr });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  if (!user) return res.json({ ok:false, msg:'用户不存在' });
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hashPassword(newPassword), userId);
  res.json({ ok:true });
});
app.delete('/api/recovery/admins/:id', requireRecovery, (req,res) => {
  const id = Number(req.params.id);
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!target) return res.json({ ok:false, msg:'用户不存在' });
  if (target.username === 'admin') return res.json({ ok:false, msg:'不能删除初始账号' });
  if (target.role === 'admin') {
    const adminCount = db.prepare("SELECT COUNT(*) as c FROM users WHERE role = 'admin'").get().c;
    if (adminCount <= 1) return res.json({ ok:false, msg:'至少保留一个管理员' });
  }
  const meetings = db.prepare('SELECT id FROM meetings WHERE user_id = ?').all(id);
  meetings.forEach(m => db.prepare('DELETE FROM records WHERE meeting_id = ?').run(m.id));
  db.prepare('DELETE FROM meetings WHERE user_id = ?').run(id);
  db.prepare('DELETE FROM users WHERE id = ?').run(id);
  res.json({ ok:true });
});

app.get('/api/captcha', (req,res) => {
  const a = Math.floor(Math.random()*9)+1, b = Math.floor(Math.random()*9)+1;
  const op = Math.random() < 0.5 ? '+' : '-';
  let answer, question;
  if (op === '+') { answer = a+b; question = a+' + '+b; }
  else { const big = Math.max(a,b), small = Math.min(a,b); answer = big-small; question = big+' - '+small; }
  req.session.captchaAnswer = answer;
  req.session.captchaTime = Date.now();
  res.json({ ok:true, question: question + ' = ?' });
});

app.get('/api/meeting-info', (req,res) => {
  const code = req.query.code;
  if (!code) return res.json({ ok:false, msg:'缺少参数' });
  const m = db.prepare('SELECT * FROM meetings WHERE code = ?').get(code);
  if (!m) return res.json({ ok:false, msg:'会议不存在' });
  if (m.expires_at && new Date(m.expires_at) < new Date()) return res.json({ ok:false, msg:'签到已过期，请联系管理员' });
  let fields = {}, customFields = [], columnOrder = [], requiredFields = [];
  try { fields = JSON.parse(m.fields || '{}'); } catch(e) {}
  try { customFields = JSON.parse(m.custom_fields || '[]'); } catch(e) {}
  try { columnOrder = JSON.parse(m.column_order || '[]'); } catch(e) {}
  try { requiredFields = JSON.parse(m.required_fields || '[]'); } catch(e) {}
  fields._order = columnOrder;
  res.json({ ok:true, id:m.id, name:m.name, fields, customFields, requiredFields });
});

app.post('/api/checkin', (req,res) => {
  const body = req.body;
  const expected = req.session.captchaAnswer;
  const ct = req.session.captchaTime || 0;
  if (Date.now() - ct > 5*60*1000) return res.json({ ok:false, msg:'验证码已过期' });
  if (!expected || Number(body.captcha) !== expected) return res.json({ ok:false, msg:'验证码错误' });
  delete req.session.captchaAnswer; delete req.session.captchaTime;
  const mid = Number(body.meetingId);
  if (!mid) return res.json({ ok:false, msg:'缺少会议' });
  const m = db.prepare('SELECT * FROM meetings WHERE id = ?').get(mid);
  if (!m) return res.json({ ok:false, msg:'会议不存在' });
  if (m.expires_at && new Date(m.expires_at) < new Date()) return res.json({ ok:false, msg:'签到已过期' });
  let fields = {};
  try { fields = JSON.parse(m.fields || '{}'); } catch(e) {}
  let requiredArr = [];
  try { requiredArr = JSON.parse(m.required_fields || '[]'); } catch(e) {}

  // 必填校验
  for (const item of requiredArr) {
    if (item.startsWith('field:')) {
      const key = item.substring(6);
      if (key === 'signature') continue; // 签名单独处理
      const val = body[key];
      if (val === undefined || val === null || String(val).trim() === '') {
        return res.json({ ok:false, msg: `请填写${FIELD_LABELS[key] || key}` });
      }
    } else if (item.startsWith('custom:')) {
      const label = item.substring(7);
      const val = (body.custom_values || {})[label];
      if (val === undefined || val === null || String(val).trim() === '') {
        return res.json({ ok:false, msg: `请填写${label}` });
      }
    }
  }

  const phone = clean(body.phone || '');
  // 格式校验（填了就校验）
  if (fields.phone && phone && !/^1\d{10}$/.test(phone)) return res.json({ ok:false, msg:'手机号格式错误' });
  if (fields.id_card && body.id_card && !/^\d{15}(\d{2}[\dXx])?$/.test(body.id_card)) return res.json({ ok:false, msg:'身份证号格式错误' });
  // 签名为必填时必须有
  if (requiredArr.includes('field:signature') && !body.signature) return res.json({ ok:false, msg:'请手写签名' });

  if (fields.phone && phone) {
    const h = hashPhone(phone);
    const dup = db.prepare('SELECT time FROM records WHERE meeting_id = ? AND phone_hash = ?').get(mid, h);
    if (dup) return res.json({ ok:true, dup:true, time:dup.time });
  }
  let customValues = {};
  try { Object.keys(body.custom_values||{}).forEach(k => customValues[k] = clean(body.custom_values[k]).substring(0,200)); } catch(e) {}
  const time = now();
  db.prepare(`INSERT INTO records (meeting_id,name,gender,phone,phone_hash,id_card,org,department,
    class_name,title,identity,employee_no,student_no,reg_no,invite_code,note,signature,custom_values,time)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
    mid, encrypt(clean(body.name)), encrypt(clean(body.gender)), encrypt(phone),
    fields.phone && phone ? hashPhone(phone) : '', encrypt(clean(body.id_card)),
    encrypt(clean(body.org)), encrypt(clean(body.department)), encrypt(clean(body.class_name)),
    encrypt(clean(body.title)), encrypt(clean(body.identity)), encrypt(clean(body.employee_no)),
    encrypt(clean(body.student_no)), encrypt(clean(body.reg_no)), encrypt(clean(body.invite_code)),
    encrypt(clean(body.note)), encrypt(body.signature || ''), encrypt(JSON.stringify(customValues)), time
  );
  res.json({ ok:true, dup:false, time });
});

app.get('/admin', (req,res) => res.sendFile(path.join(__dirname,'public','admin.html')));
app.get('/', (req,res) => res.sendFile(path.join(__dirname,'public','index.html')));

app.listen(PORT, '::', () => console.log(`签到服务已启动，监听端口 ${PORT}`));