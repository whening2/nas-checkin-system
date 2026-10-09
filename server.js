const express = require('express');
const Database = require('better-sqlite3');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const ExcelJS = require('exceljs');

const app = express();
const PORT = process.env.PORT || 8080;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'change-me';
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-this-secret';
// 内置默认值，部署时无需再设置
const SITE_TITLE = process.env.SITE_TITLE || '会议签到';
const SUBTITLE = process.env.SUBTITLE || '请填写以下信息完成签到';
// 强制使用北京时间
process.env.TZ = process.env.TZ || 'Asia/Shanghai';

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      upgradeInsecureRequests: null
    }
  },
  hsts: false,
  crossOriginOpenerPolicy: false,
  originAgentCluster: false
}));

app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, maxAge: 2 * 60 * 60 * 1000 }
}));

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { ok: false, msg: '请求过于频繁，请稍后再试' }
});
app.use('/api/', limiter);

const db = new Database(path.join('/data', 'checkin.db'));
db.exec(`
  CREATE TABLE IF NOT EXISTS meetings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    code TEXT UNIQUE NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    fields TEXT,
    meeting_date TEXT,
    column_order TEXT
  );
  CREATE TABLE IF NOT EXISTS records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    meeting_id INTEGER NOT NULL,
    name TEXT,
    phone TEXT,
    org TEXT,
    title TEXT,
    note TEXT DEFAULT '',
    time TEXT NOT NULL,
    FOREIGN KEY (meeting_id) REFERENCES meetings(id)
  );
`);
[['meetings','expires_at','TEXT'],['meetings','fields','TEXT'],['meetings','meeting_date','TEXT'],['meetings','column_order','TEXT'],['records','title','TEXT']]
  .forEach(([t,c,ty]) => { try { db.exec(`ALTER TABLE ${t} ADD COLUMN ${c} ${ty}`); } catch(e){} });

const clean = s => String(s).replace(/[<>'"&]/g, '').trim();
const now = () => new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
const todayCn = () => new Date().toLocaleDateString('zh-CN', { timeZone: 'Asia/Shanghai', year: 'numeric', month: 'long', day: 'numeric' });

function generateCode(len = 6) {
  const chars = 'abcdefghjkmnpqrstuvwxyz23456789';
  let code = '';
  for (let i = 0; i < len; i++) code += chars[Math.floor(Math.random() * chars.length)];
  return code;
}

const failMap = new Map();
function requireLogin(req, res, next) {
  if (req.session && req.session.loggedIn) return next();
  res.status(401).json({ ok: false, msg: '未登录' });
}

// ========== 全局配置（供前端读取）==========
app.get('/api/config', (req, res) => {
  res.json({ ok: true, siteTitle: SITE_TITLE, subtitle: SUBTITLE });
});

// ========== 管理端 ==========
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const ip = req.ip;
  const rec = failMap.get(ip) || { count: 0, lastFail: 0 };
  if (rec.count > 0) {
    const delay = Math.min(2 ** (rec.count - 1) * 1000, 30000);
    const elapsed = Date.now() - rec.lastFail;
    if (elapsed < delay) await new Promise(r => setTimeout(r, delay - elapsed));
  }
  if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
    failMap.delete(ip);
    req.session.loggedIn = true;
    return res.json({ ok: true });
  }
  rec.count += 1; rec.lastFail = Date.now();
  failMap.set(ip, rec);
  res.status(401).json({ ok: false, msg: '用户名或密码错误' });
});

app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ ok: true }); });
app.get('/api/check-login', (req, res) => res.json({ ok: true, loggedIn: !!(req.session && req.session.loggedIn) }));

app.get('/api/meetings', requireLogin, (req, res) => {
  const rows = db.prepare('SELECT * FROM meetings ORDER BY id DESC').all();
  const result = rows.map(m => {
    const count = db.prepare('SELECT COUNT(*) as c FROM records WHERE meeting_id = ?').get(m.id).c;
    const expired = m.expires_at ? new Date(m.expires_at) < new Date() : false;
    const leftMs = m.expires_at ? new Date(m.expires_at) - new Date() : 0;
    const leftDays = Math.ceil(leftMs / (24 * 60 * 60 * 1000));
    return { ...m, count, expired, leftDays };
  });
  res.json({ ok: true, data: result });
});

app.post('/api/meetings', requireLogin, (req, res) => {
  const { name, fields, meetingDate, columnOrder } = req.body;
  if (!name || typeof name !== 'string' || name.length < 1 || name.length > 50) {
    return res.json({ ok: false, msg: '会议名称不合法' });
  }
  const f = fields || {};
  if (!f.name && !f.phone && !f.org && !f.title && !f.note) {
    return res.json({ ok: false, msg: '请至少勾选一个签到字段' });
  }
  const code = generateCode();
  const createdAt = now();
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
  const dateStr = (meetingDate && String(meetingDate).trim()) || todayCn();
  // columnOrder 现在是数组，如 ['org','name','title','phone','note']
  let orderArr = Array.isArray(columnOrder) ? columnOrder : [];
  // 过滤掉未勾选的字段
  orderArr = orderArr.filter(k => ['org','name','title','phone','note'].includes(k) && f[k]);
  // 补充遗漏的已勾选字段
  ['org','name','title','phone','note'].forEach(k => {
    if (f[k] && !orderArr.includes(k)) orderArr.push(k);
  });
  const orderStr = orderArr.join(',');
  const info = db.prepare('INSERT INTO meetings (name, code, created_at, expires_at, fields, meeting_date, column_order) VALUES (?,?,?,?,?,?,?)')
    .run(clean(name), code, createdAt, expiresAt, JSON.stringify(f), clean(dateStr), orderStr);
  res.json({ ok: true, id: info.lastInsertRowid, code, name: clean(name) });
});

app.post('/api/meetings/:id/extend', requireLogin, (req, res) => {
  const id = Number(req.params.id);
  const m = db.prepare('SELECT id FROM meetings WHERE id = ?').get(id);
  if (!m) return res.json({ ok: false, msg: '会议不存在' });
  const newExpires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
  db.prepare('UPDATE meetings SET expires_at = ? WHERE id = ?').run(newExpires, id);
  res.json({ ok: true });
});

app.delete('/api/meetings/:id', requireLogin, (req, res) => {
  const id = Number(req.params.id);
  if (!id) return res.json({ ok: false, msg: '参数错误' });
  db.prepare('DELETE FROM records WHERE meeting_id = ?').run(id);
  db.prepare('DELETE FROM meetings WHERE id = ?').run(id);
  res.json({ ok: true });
});

app.get('/api/records/:meetingId', requireLogin, (req, res) => {
  const mid = Number(req.params.meetingId);
  const meeting = db.prepare('SELECT * FROM meetings WHERE id = ?').get(mid);
  if (!meeting) return res.json({ ok: false, msg: '会议不存在' });
  const rows = db.prepare('SELECT * FROM records WHERE meeting_id = ? ORDER BY id DESC').all(mid);
  res.json({ ok: true, data: rows, total: rows.length, fields: meeting.fields, columnOrder: meeting.column_order });
});

app.get('/api/export/:meetingId', requireLogin, async (req, res) => {
  const mid = Number(req.params.meetingId);
  const meeting = db.prepare('SELECT * FROM meetings WHERE id = ?').get(mid);
  if (!meeting) return res.status(404).send('会议不存在');

  let fields = { name: true, phone: true, org: true, title: false, note: false };
  try { fields = Object.assign(fields, JSON.parse(meeting.fields || '{}')); } catch(e) {}

  const fieldMap = { '单位': 'org', '姓名': 'name', '职务': 'title', '电话': 'phone', '备注': 'note' };
  const headerMap = { id: '序号', org: '单位', name: '姓名', title: '职务', phone: '电话', note: '备注' };

  // column_order 存的是 key 数组，如 'org,name,title,phone,note'
  let orderKeys = (meeting.column_order || '').split(',').map(s => s.trim()).filter(s => s);
  let columns = ['id'];
  orderKeys.forEach(key => {
    if (fields[key] && !columns.includes(key)) columns.push(key);
  });
  ['org','name','title','phone','note'].forEach(key => {
    if (fields[key] && !columns.includes(key)) columns.push(key);
  });

  const records = db.prepare('SELECT * FROM records WHERE meeting_id = ? ORDER BY id').all(mid);

  const wb = new ExcelJS.Workbook();
  const ws = wb.addWorksheet('签到表');
  const colCount = columns.length;
  const lastColLetter = String.fromCharCode(64 + colCount);

  // 第 1 行：标题
  ws.mergeCells(`A1:${lastColLetter}1`);
  const titleCell = ws.getCell('A1');
  titleCell.value = meeting.name + '签到表';
  titleCell.font = { name: '方正小标宋简体', size: 22 };
  titleCell.alignment = { horizontal: 'center', vertical: 'middle' };
  ws.getRow(1).height = 50;

  // 第 2 行：日期（右对齐）
  ws.mergeCells(`A2:${lastColLetter}2`);
  const dateCell = ws.getCell('A2');
  dateCell.value = '时间：' + (meeting.meeting_date || meeting.created_at);
  dateCell.font = { name: '黑体', size: 16 };
  dateCell.alignment = { horizontal: 'right', vertical: 'middle' };
  ws.getRow(2).height = 34;

  // 第 3 行：表头
  const headerRow = ws.getRow(3);
  columns.forEach((col, i) => {
    const cell = headerRow.getCell(i + 1);
    cell.value = headerMap[col];
    cell.font = { name: '黑体', size: 16 };
    cell.alignment = { horizontal: 'center', vertical: 'middle' };
    cell.border = { top:{style:'thin'}, bottom:{style:'thin'}, left:{style:'thin'}, right:{style:'thin'} };
  });
  headerRow.height = 34;

  // 第 4 行起：数据，全部居中、带边框
  records.forEach((r, idx) => {
    const row = ws.getRow(4 + idx);
    columns.forEach((col, i) => {
      const cell = row.getCell(i + 1);
      cell.value = col === 'id' ? (idx + 1) : (r[col] || '');
      cell.font = { name: '仿宋_GB2312', size: 16 };
      cell.alignment = { horizontal: 'center', vertical: 'middle', wrapText: true };
      cell.border = { top:{style:'thin'}, bottom:{style:'thin'}, left:{style:'thin'}, right:{style:'thin'} };
    });
    row.height = 32;
  });

  const widths = { id: 8, org: 28, name: 12, title: 16, phone: 18, note: 20 };
  columns.forEach((col, i) => { ws.getColumn(i + 1).width = widths[col] || 15; });

  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.setHeader('Content-Disposition', `attachment; filename="checkin-${mid}.xlsx"`);
  await wb.xlsx.write(res);
  res.end();
});

// ========== 公开接口 ==========
app.get('/api/captcha', (req, res) => {
  const a = Math.floor(Math.random() * 9) + 1;
  const b = Math.floor(Math.random() * 9) + 1;
  const op = Math.random() < 0.5 ? '+' : '-';
  let answer, question;
  if (op === '+') { answer = a + b; question = a + ' + ' + b; }
  else { const big = Math.max(a, b), small = Math.min(a, b); answer = big - small; question = big + ' - ' + small; }
  req.session.captchaAnswer = answer;
  req.session.captchaTime = Date.now();
  res.json({ ok: true, question: question + ' = ?' });
});

app.get('/api/meeting-info', (req, res) => {
  const code = req.query.code;
  if (!code || typeof code !== 'string') return res.json({ ok: false, msg: '缺少会议参数' });
  const meeting = db.prepare('SELECT * FROM meetings WHERE code = ?').get(code);
  if (!meeting) return res.json({ ok: false, msg: '会议不存在或已被删除' });
  if (meeting.expires_at && new Date(meeting.expires_at) < new Date()) {
    return res.json({ ok: false, msg: '签到已过期，请联系管理员' });
  }
  let fields = { name: true, phone: true, org: true, title: false, note: false };
  try { fields = Object.assign(fields, JSON.parse(meeting.fields || '{}')); } catch(e) {}
  res.json({ ok: true, id: meeting.id, name: meeting.name, fields });
});

app.post('/api/checkin', (req, res) => {
  let { meetingId, name, phone, org, title, note, captcha } = req.body;

  const expected = req.session.captchaAnswer;
  const captchaTime = req.session.captchaTime || 0;
  if (Date.now() - captchaTime > 5 * 60 * 1000) return res.json({ ok: false, msg: '验证码已过期，请刷新页面' });
  if (!expected || Number(captcha) !== expected) return res.json({ ok: false, msg: '验证码错误' });
  delete req.session.captchaAnswer; delete req.session.captchaTime;

  if (!meetingId) return res.json({ ok: false, msg: '缺少会议信息' });
  const meeting = db.prepare('SELECT * FROM meetings WHERE id = ?').get(meetingId);
  if (!meeting) return res.json({ ok: false, msg: '会议不存在' });
  if (meeting.expires_at && new Date(meeting.expires_at) < new Date()) {
    return res.json({ ok: false, msg: '签到已过期' });
  }

  let fields = { name: true, phone: true, org: true, title: false, note: false };
  try { fields = Object.assign(fields, JSON.parse(meeting.fields || '{}')); } catch(e) {}

  if (fields.name && (typeof name !== 'string' || name.length < 1 || name.length > 50))
    return res.json({ ok: false, msg: '姓名格式错误' });
  if (fields.phone && (typeof phone !== 'string' || !/^1\d{10}$/.test(phone)))
    return res.json({ ok: false, msg: '手机号格式错误' });
  if (fields.org && (typeof org !== 'string' || org.length < 1 || org.length > 100))
    return res.json({ ok: false, msg: '单位格式错误' });
  if (fields.title && (typeof title !== 'string' || title.length < 1 || title.length > 50))
    return res.json({ ok: false, msg: '职务格式错误' });
  if (note && (typeof note !== 'string' || note.length > 200))
    return res.json({ ok: false, msg: '备注格式错误' });

  name = name ? clean(name) : '';
  phone = phone ? clean(phone) : '';
  org = org ? clean(org) : '';
  title = title ? clean(title) : '';
  note = note ? clean(note) : '';

  if (phone) {
    const dup = db.prepare('SELECT * FROM records WHERE meeting_id = ? AND phone = ?').get(meetingId, phone);
    if (dup) return res.json({ ok: true, dup: true, time: dup.time });
  }

  const time = now();
  db.prepare('INSERT INTO records (meeting_id, name, phone, org, title, note, time) VALUES (?,?,?,?,?,?,?)')
    .run(meetingId, name, phone, org, title, note, time);
  res.json({ ok: true, dup: false, time });
});

app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, '::', () => { console.log(`签到服务已启动，监听端口 ${PORT}`); });