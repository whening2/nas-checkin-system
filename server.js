const express = require('express');
const Database = require('better-sqlite3');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 8080;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'change-me';
const SITE_TITLE = process.env.SITE_TITLE || '会议签到';
const SUBTITLE = process.env.SUBTITLE || '请填写以下信息完成签到';

// 安全响应头
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrcAttr: ["'unsafe-inline'"],   // 关键：允许内联 onclick
      upgradeInsecureRequests: null          // 禁用强制 HTTPS 升级
    }
  },
  hsts: false,                 // 禁用 HSTS，防止浏览器强制 HTTPS
  crossOriginOpenerPolicy: false,
  originAgentCluster: false
}));

// 请求体大小限制
app.use(express.json({ limit: '10kb' }));

// 接口限流
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  message: { ok: false, msg: '请求过于频繁，请稍后再试' }
});
app.use('/api/', limiter);

// 初始化数据库
const db = new Database(path.join('/data', 'checkin.db'));
db.exec(`
  CREATE TABLE IF NOT EXISTS records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    phone TEXT NOT NULL,
    org TEXT NOT NULL,
    note TEXT DEFAULT '',
    time TEXT NOT NULL
  )
`);

app.use(express.static(path.join(__dirname, 'public')));

// 输入清洗函数
const clean = s => String(s).replace(/[<>'"&]/g, '').trim();

// 签到接口
app.post('/api/checkin', (req, res) => {
  let { name, phone, org, note } = req.body;

  // 类型和长度校验
  if (typeof name !== 'string' || name.length < 1 || name.length > 50)
    return res.json({ ok: false, msg: '姓名格式错误' });
  if (typeof phone !== 'string' || !/^1\d{10}$/.test(phone))
    return res.json({ ok: false, msg: '手机号格式错误' });
  if (typeof org !== 'string' || org.length < 1 || org.length > 100)
    return res.json({ ok: false, msg: '单位格式错误' });
  if (note && (typeof note !== 'string' || note.length > 200))
    return res.json({ ok: false, msg: '备注格式错误' });

  name = clean(name); org = clean(org); note = note ? clean(note) : '';

  const dup = db.prepare('SELECT * FROM records WHERE phone = ?').get(phone);
  if (dup) return res.json({ ok: true, dup: true, time: dup.time });

  const time = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
  db.prepare('INSERT INTO records (name, phone, org, note, time) VALUES (?,?,?,?,?)')
    .run(name, phone, org, note, time);
  res.json({ ok: true, dup: false, time });
});

// 管理密码失败次数限制
const failCount = {};
app.get('/admin/records', (req, res) => {
  const ip = req.ip;
  if (failCount[ip] >= 5) {
    return res.status(429).json({ ok: false, msg: '尝试次数过多，请15分钟后再试' });
  }
  if (req.query.pwd !== ADMIN_PASSWORD) {
    failCount[ip] = (failCount[ip] || 0) + 1;
    setTimeout(() => { delete failCount[ip]; }, 15 * 60 * 1000);
    return res.status(401).json({ ok: false, msg: '密码错误' });
  }
  delete failCount[ip];
  const rows = db.prepare('SELECT * FROM records ORDER BY id DESC').all();
  res.json({ ok: true, data: rows, total: rows.length });
});

// 导出 CSV
app.get('/admin/export', (req, res) => {
  if (req.query.pwd !== ADMIN_PASSWORD) return res.status(401).send('密码错误');
  const rows = db.prepare('SELECT name, phone, org, note, time FROM records ORDER BY id').all();
  let csv = '\uFEFF姓名,电话,单位,备注,签到时间\n';
  rows.forEach(r => { csv += `"${r.name}","${r.phone}","${r.org}","${r.note}","${r.time}"\n`; });
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename=checkin.csv');
  res.send(csv);
});

// 获取服务器信息（用于生成二维码）
app.get('/api/server-info', (req, res) => {
  const os = require('os');
  const nets = os.networkInterfaces();
  let ipv6 = '';
  for (const name of Object.keys(nets)) {
    for (const net of nets[name]) {
      if (net.family === 'IPv6' && !net.internal && !net.address.startsWith('fe80')) {
        ipv6 = net.address;
      }
    }
  }
  res.json({ ok: true, ipv6, port: PORT });
});

// 管理页面
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// 启动：监听 :: 同时接受 IPv6 和 IPv4
app.listen(PORT, '::', () => {
  console.log(`签到服务已启动，监听端口 ${PORT}`);
});