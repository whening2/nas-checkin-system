const express = require('express');
const Database = require('better-sqlite3');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 8080;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'change-me';
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-this-secret';

// 安全响应头
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

// Session 配置
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, maxAge: 2 * 60 * 60 * 1000 }
}));

// 接口限流
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { ok: false, msg: '请求过于频繁，请稍后再试' }
});
app.use('/api/', limiter);

// 数据库
const db = new Database(path.join('/data', 'checkin.db'));
db.exec(`
  CREATE TABLE IF NOT EXISTS meetings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    code TEXT UNIQUE NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    meeting_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    phone TEXT NOT NULL,
    org TEXT NOT NULL,
    note TEXT DEFAULT '',
    time TEXT NOT NULL,
    FOREIGN KEY (meeting_id) REFERENCES meetings(id)
  );
`);

// 工具函数
const clean = s => String(s).replace(/[<>'"&]/g, '').trim();
const now = () => new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });

function generateCode(len = 6) {
  const chars = 'abcdefghjkmnpqrstuvwxyz23456789';
  let code = '';
  for (let i = 0; i < len; i++) code += chars[Math.floor(Math.random() * chars.length)];
  return code;
}

// 登录失败延迟记录
const failMap = new Map();

// 登录状态检查
function requireLogin(req, res, next) {
  if (req.session && req.session.loggedIn) return next();
  res.status(401).json({ ok: false, msg: '未登录' });
}

// ========== 管理端接口 ==========

// 登录（用户名 + 密码）
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const ip = req.ip;
  const rec = failMap.get(ip) || { count: 0, lastFail: 0 };
  const nowTime = Date.now();

  // 延迟递增：失败次数越多，等待越久
  if (rec.count > 0) {
    const delay = Math.min(2 ** (rec.count - 1) * 1000, 30000);
    const elapsed = nowTime - rec.lastFail;
    if (elapsed < delay) {
      await new Promise(r => setTimeout(r, delay - elapsed));
    }
  }

  if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
    failMap.delete(ip);
    req.session.loggedIn = true;
    return res.json({ ok: true });
  } else {
    rec.count += 1;
    rec.lastFail = Date.now();
    failMap.set(ip, rec);
    return res.status(401).json({ ok: false, msg: '用户名或密码错误' });
  }
});

// 登出
app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

// 检查登录状态
app.get('/api/check-login', (req, res) => {
  res.json({ ok: true, loggedIn: !!(req.session && req.session.loggedIn) });
});

// 会议列表
app.get('/api/meetings', requireLogin, (req, res) => {
  const rows = db.prepare('SELECT * FROM meetings ORDER BY id DESC').all();
  res.json({ ok: true, data: rows });
});

// 创建会议
app.post('/api/meetings', requireLogin, (req, res) => {
  const { name } = req.body;
  if (!name || typeof name !== 'string' || name.length < 1 || name.length > 50) {
    return res.json({ ok: false, msg: '会议名称不合法' });
  }
  const code = generateCode();
  const time = now();
  const info = db.prepare('INSERT INTO meetings (name, code, created_at) VALUES (?,?,?)').run(clean(name), code, time);
  res.json({ ok: true, id: info.lastInsertRowid, code, name: clean(name) });
});

// 删除会议
app.delete('/api/meetings/:id', requireLogin, (req, res) => {
  const id = Number(req.params.id);
  if (!id) return res.json({ ok: false, msg: '参数错误' });
  db.prepare('DELETE FROM records WHERE meeting_id = ?').run(id);
  db.prepare('DELETE FROM meetings WHERE id = ?').run(id);
  res.json({ ok: true });
});

// 获取某会议签到记录
app.get('/api/records/:meetingId', requireLogin, (req, res) => {
  const mid = Number(req.params.meetingId);
  if (!mid) return res.json({ ok: false, msg: '参数错误' });
  const meeting = db.prepare('SELECT id FROM meetings WHERE id = ?').get(mid);
  if (!meeting) return res.json({ ok: false, msg: '会议不存在' });
  const rows = db.prepare('SELECT * FROM records WHERE meeting_id = ? ORDER BY id DESC').all(mid);
  res.json({ ok: true, data: rows, total: rows.length });
});

// 导出 CSV
app.get('/api/export/:meetingId', requireLogin, (req, res) => {
  const mid = Number(req.params.meetingId);
  const meeting = db.prepare('SELECT name FROM meetings WHERE id = ?').get(mid);
  if (!meeting) return res.status(404).send('会议不存在');
  const rows = db.prepare('SELECT name, phone, org, note, time FROM records WHERE meeting_id = ? ORDER BY id').all(mid);
  let csv = '\uFEFF姓名,电话,单位,备注,签到时间\n';
  rows.forEach(r => { csv += `"${r.name}","${r.phone}","${r.org}","${r.note}","${r.time}"\n`; });
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename=checkin-meeting-${mid}.csv`);
  res.send(csv);
});

// ========== 公开接口 ==========

// 会议校验：根据 code 获取会议信息
app.get('/api/meeting-info', (req, res) => {
  const code = req.query.code;
  if (!code || typeof code !== 'string') return res.json({ ok: false, msg: '缺少会议参数' });
  const meeting = db.prepare('SELECT id, name FROM meetings WHERE code = ?').get(code);
  if (!meeting) return res.json({ ok: false, msg: '会议不存在或已被删除' });
  res.json({ ok: true, id: meeting.id, name: meeting.name });
});

// 签到（带会议校验）
app.post('/api/checkin', (req, res) => {
  let { meetingId, name, phone, org, note } = req.body;
  if (!meetingId) return res.json({ ok: false, msg: '缺少会议信息' });

  const meeting = db.prepare('SELECT id FROM meetings WHERE id = ?').get(meetingId);
  if (!meeting) return res.json({ ok: false, msg: '会议不存在' });

  if (typeof name !== 'string' || name.length < 1 || name.length > 50)
    return res.json({ ok: false, msg: '姓名格式错误' });
  if (typeof phone !== 'string' || !/^1\d{10}$/.test(phone))
    return res.json({ ok: false, msg: '手机号格式错误' });
  if (typeof org !== 'string' || org.length < 1 || org.length > 100)
    return res.json({ ok: false, msg: '单位格式错误' });
  if (note && (typeof note !== 'string' || note.length > 200))
    return res.json({ ok: false, msg: '备注格式错误' });

  name = clean(name); org = clean(org); note = note ? clean(note) : '';

  const dup = db.prepare('SELECT * FROM records WHERE meeting_id = ? AND phone = ?').get(meetingId, phone);
  if (dup) return res.json({ ok: true, dup: true, time: dup.time });

  const time = now();
  db.prepare('INSERT INTO records (meeting_id, name, phone, org, note, time) VALUES (?,?,?,?,?,?)')
    .run(meetingId, name, phone, org, note, time);
  res.json({ ok: true, dup: false, time });
});

// ========== 页面路由 ==========

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '::', () => {
  console.log(`签到服务已启动，监听端口 ${PORT}`);
});