// CampusPass backend: Express + SQLite. Run: npm install && npm start
const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const QRCode = require('qrcode');
const crypto = require('crypto');

const SECRET = process.env.JWT_SECRET || 'change-me-in-production';
const db = new Database('campuspass.db');
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE, hash TEXT,
  role TEXT DEFAULT 'student', status TEXT DEFAULT 'active', created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, organizer_id INTEGER, title TEXT, category TEXT,
  description TEXT, venue TEXT, date TEXT, price INTEGER DEFAULT 0, capacity INTEGER,
  status TEXT DEFAULT 'pending');
CREATE TABLE IF NOT EXISTS bookings(id INTEGER PRIMARY KEY, event_id INTEGER, user_id INTEGER, qty INTEGER,
  code TEXT UNIQUE, status TEXT DEFAULT 'confirmed', checked_in INTEGER DEFAULT 0, created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, user_id INTEGER, action TEXT, at TEXT DEFAULT CURRENT_TIMESTAMP);
`);
const seed = (n, e, r) => db.prepare('INSERT OR IGNORE INTO users(name,email,hash,role) VALUES(?,?,?,?)')
  .run(n, e, bcrypt.hashSync('password123', 8), r);
seed('Admin', 'admin@campus.ac.ke', 'admin');
seed('CS Club', 'organizer@students.ac.ke', 'organizer');
seed('Amani Wanjiru', 'amani@students.ac.ke', 'student');
if (!db.prepare('SELECT 1 FROM events').get()) {
  const ins = db.prepare('INSERT INTO events(organizer_id,title,category,description,venue,date,price,capacity,status) VALUES(2,?,?,?,?,?,?,?,?)');
  ins.run('Nairobi Tech Hackathon 2026', 'Tech', '9-hour build sprint with mentors and prizes.', 'Innovation Lab, Block B', '2026-12-17T09:00', 500, 200, 'published');
  ins.run('Afrobeats Night Live', 'Music', 'Live music at the amphitheatre.', 'Main Amphitheatre', '2026-12-23T19:00', 800, 500, 'published');
  ins.run('Founders Talk', 'Talk', 'Building in Africa.', 'Auditorium 2', '2026-12-09T16:00', 0, 150, 'published');
}

const app = express();
app.use(express.json());
app.use(express.static('public'));
const log = (uid, action) => db.prepare('INSERT INTO audit(user_id,action) VALUES(?,?)').run(uid, action);
const sign = u => jwt.sign({ id: u.id, role: u.role, name: u.name }, SECRET, { expiresIn: '8h' });
const auth = (...roles) => (req, res, next) => {
  try {
    req.user = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), SECRET);
    if (roles.length && !roles.includes(req.user.role)) return res.status(403).json({ error: 'Forbidden' });
    next();
  } catch { res.status(401).json({ error: 'Please sign in' }); }
};
const sold = id => db.prepare("SELECT COALESCE(SUM(qty),0) n FROM bookings WHERE event_id=? AND status='confirmed'").get(id).n;

// ---- Auth ----
app.post('/api/register', (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password || password.length < 6) return res.status(400).json({ error: 'Name, email and 6+ char password required' });
  try {
    const r = db.prepare('INSERT INTO users(name,email,hash) VALUES(?,?,?)').run(name, email.toLowerCase(), bcrypt.hashSync(password, 8));
    const u = { id: r.lastInsertRowid, role: 'student', name };
    res.json({ token: sign(u), user: u });
  } catch { res.status(409).json({ error: 'Email already registered' }); }
});
app.post('/api/login', (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE email=?').get((req.body.email || '').toLowerCase());
  if (!u || !bcrypt.compareSync(req.body.password || '', u.hash)) return res.status(401).json({ error: 'Invalid credentials' });
  if (u.status !== 'active') return res.status(403).json({ error: 'Account suspended' });
  res.json({ token: sign(u), user: { id: u.id, role: u.role, name: u.name } });
});

// ---- Events (search & filter) ----
app.get('/api/events', (req, res) => {
  const { q = '', category = '', when = '' } = req.query;
  let rows = db.prepare("SELECT * FROM events WHERE status='published' AND title LIKE ? AND (?='' OR category=?) ORDER BY date")
    .all(`%${q}%`, category, category);
  const now = new Date(), end = { today: 1, week: 7, month: 30 }[when];
  if (end) rows = rows.filter(e => { const d = (new Date(e.date) - now) / 864e5; return d >= -1 && d <= end; });
  res.json(rows.map(e => ({ ...e, booked: sold(e.id) })));
});
app.get('/api/events/:id', (req, res) => {
  const e = db.prepare('SELECT * FROM events WHERE id=?').get(req.params.id);
  e ? res.json({ ...e, booked: sold(e.id) }) : res.status(404).json({ error: 'Not found' });
});
app.post('/api/events', auth('organizer', 'admin'), (req, res) => {
  const { title, category, description, venue, date, price, capacity } = req.body;
  if (!title || !venue || !date || !(capacity > 0)) return res.status(400).json({ error: 'Title, venue, date and capacity required' });
  const r = db.prepare('INSERT INTO events(organizer_id,title,category,description,venue,date,price,capacity) VALUES(?,?,?,?,?,?,?,?)')
    .run(req.user.id, title, category || 'Other', description || '', venue, date, price || 0, capacity);
  log(req.user.id, `created event ${r.lastInsertRowid}`);
  res.json({ id: r.lastInsertRowid, status: 'pending' });
});

// ---- Booking & QR ----
app.post('/api/bookings', auth('student', 'organizer'), (req, res) => {
  const qty = Math.min(Math.max(+req.body.qty || 1, 1), 2);
  const book = db.transaction(() => {
    const e = db.prepare("SELECT * FROM events WHERE id=? AND status='published'").get(req.body.event_id);
    if (!e) return { code: 404, error: 'Event not found' };
    if (sold(e.id) + qty > e.capacity) return { code: 409, error: 'Sold out' };
    if (db.prepare("SELECT 1 FROM bookings WHERE event_id=? AND user_id=? AND status='confirmed'").get(e.id, req.user.id))
      return { code: 409, error: 'You already booked this event' };
    const code = 'CP-' + crypto.randomBytes(4).toString('hex').toUpperCase();
    db.prepare('INSERT INTO bookings(event_id,user_id,qty,code) VALUES(?,?,?,?)').run(e.id, req.user.id, qty, code);
    return { code: 200, booking: { code, event: e.title } };
  });
  const r = book();
  r.error ? res.status(r.code).json({ error: r.error }) : res.json(r.booking);
});
app.get('/api/bookings/mine', auth(), async (req, res) => {
  const rows = db.prepare(`SELECT b.*, e.title, e.venue, e.date FROM bookings b JOIN events e ON e.id=b.event_id
    WHERE b.user_id=? ORDER BY b.created DESC`).all(req.user.id);
  for (const b of rows) b.qr = await QRCode.toDataURL(b.code, { margin: 1, width: 220 });
  res.json(rows);
});
app.delete('/api/bookings/:id', auth(), (req, res) => {
  const r = db.prepare("UPDATE bookings SET status='cancelled' WHERE id=? AND user_id=? AND checked_in=0").run(req.params.id, req.user.id);
  r.changes ? res.json({ ok: true }) : res.status(400).json({ error: 'Cannot cancel' });
});

// ---- Organizer: scan & dashboard ----
const owns = (u, eid) => u.role === 'admin' || db.prepare('SELECT 1 FROM events WHERE id=? AND organizer_id=?').get(eid, u.id);
app.post('/api/scan', auth('organizer', 'admin'), (req, res) => {
  const b = db.prepare(`SELECT b.*, e.title, u.name FROM bookings b JOIN events e ON e.id=b.event_id
    JOIN users u ON u.id=b.user_id WHERE b.code=?`).get((req.body.code || '').trim().toUpperCase());
  if (!b || !owns(req.user, b.event_id)) return res.json({ valid: false, reason: 'Ticket not found for your events' });
  if (b.status !== 'confirmed') return res.json({ valid: false, reason: 'Ticket cancelled' });
  if (b.checked_in) return res.json({ valid: false, reason: 'Already used' });
  db.prepare('UPDATE bookings SET checked_in=1 WHERE id=?').run(b.id);
  res.json({ valid: true, name: b.name, event: b.title, qty: b.qty });
});
app.get('/api/organizer/dashboard', auth('organizer', 'admin'), (req, res) => {
  const evs = db.prepare('SELECT * FROM events WHERE organizer_id=?').all(req.user.id);
  const out = evs.map(e => {
    const s = db.prepare("SELECT COALESCE(SUM(qty),0) booked, COALESCE(SUM(CASE WHEN checked_in=1 THEN qty END),0) checked FROM bookings WHERE event_id=? AND status='confirmed'").get(e.id);
    return { ...e, ...s, revenue: s.booked * e.price };
  });
  res.json({ events: out, totals: { bookings: out.reduce((a, e) => a + e.booked, 0),
    checkedIn: out.reduce((a, e) => a + e.checked, 0), revenue: out.reduce((a, e) => a + e.revenue, 0) } });
});

// ---- Admin ----
app.get('/api/admin/overview', auth('admin'), (req, res) => res.json({
  users: db.prepare('SELECT id,name,email,role,status,created FROM users').all(),
  pending: db.prepare("SELECT * FROM events WHERE status='pending'").all(),
  audit: db.prepare('SELECT * FROM audit ORDER BY id DESC LIMIT 15').all() }));
app.post('/api/admin/events/:id/:action', auth('admin'), (req, res) => {
  const st = { approve: 'published', reject: 'rejected' }[req.params.action];
  if (!st) return res.status(400).json({ error: 'Bad action' });
  db.prepare('UPDATE events SET status=? WHERE id=?').run(st, req.params.id);
  log(req.user.id, `${req.params.action} event ${req.params.id}`); res.json({ ok: true });
});
app.post('/api/admin/users/:id/status', auth('admin'), (req, res) => {
  db.prepare('UPDATE users SET status=? WHERE id=?').run(req.body.status === 'suspended' ? 'suspended' : 'active', req.params.id);
  log(req.user.id, `set user ${req.params.id} ${req.body.status}`); res.json({ ok: true });
});

app.listen(process.env.PORT || 3000, () => console.log('CampusPass running on http://localhost:3000'));
