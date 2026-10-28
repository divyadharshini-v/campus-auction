const express = require('express'), Database = require('better-sqlite3'), crypto = require('crypto');
const db = new Database(process.env.DB || 'auction.db'); db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT UNIQUE, token TEXT);
CREATE TABLE IF NOT EXISTS items(id INTEGER PRIMARY KEY, seller_id INT, title TEXT, category TEXT, description TEXT,
  condition TEXT, photos TEXT DEFAULT '[]', start_price INT, min_inc INT, closes_at INT, status TEXT DEFAULT 'active',
  winner_id INT, final_price INT, created_at INT);
CREATE TABLE IF NOT EXISTS bids(id INTEGER PRIMARY KEY, item_id INT, bidder_id INT, amount INT, created_at INT);
CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY, user_id INT, item_id INT, message TEXT, created_at INT, read INT DEFAULT 0);
`);
const app = express(); app.use(express.json({ limit: '12mb' })); app.use(express.static('public'));
const now = () => Date.now(), ok = (res, d = {}) => res.json(d), fail = (res, m, c = 400) => res.status(c).json({ error: m });
const notify = (uid, item_id, message) => uid && db.prepare('INSERT INTO notifications(user_id,item_id,message,created_at) VALUES(?,?,?,?)').run(uid, item_id, message, now());

// Closing: runs every second; the server decides when bidding stops.
function settle() {
  const due = db.prepare("SELECT * FROM items WHERE status='active' AND closes_at<=?").all(now());
  for (const it of due) {
    const top = db.prepare('SELECT * FROM bids WHERE item_id=? ORDER BY amount DESC, id ASC LIMIT 1').get(it.id);
    if (!top) { db.prepare("UPDATE items SET status='unsold' WHERE id=?").run(it.id); notify(it.seller_id, it.id, `"${it.title}" closed with no bids (unsold).`); }
    else {
      db.prepare("UPDATE items SET status='pending_approval',winner_id=?,final_price=? WHERE id=?").run(top.bidder_id, top.amount, it.id);
      notify(it.seller_id, it.id, `"${it.title}" closed at ₹${top.amount}. Approve or reject the price.`);
      notify(top.bidder_id, it.id, `You are the provisional winner of "${it.title}" at ₹${top.amount}. Awaiting seller approval.`);
    }
  }
}
setInterval(settle, 1000);

const SELECT = `SELECT i.*, s.name seller, w.name winner,
 (SELECT MAX(amount) FROM bids WHERE item_id=i.id) current,
 (SELECT COUNT(*) FROM bids WHERE item_id=i.id) bid_count,
 (SELECT u.name FROM bids b JOIN users u ON u.id=b.bidder_id WHERE b.item_id=i.id ORDER BY amount DESC LIMIT 1) leader
 FROM items i JOIN users s ON s.id=i.seller_id LEFT JOIN users w ON w.id=i.winner_id`;
const auth = (req, res, next) => {
  const u = db.prepare('SELECT * FROM users WHERE token=?').get(req.get('x-token') || '');
  if (!u) return fail(res, 'Please log in', 401); req.user = u; next();
};

for (const c of ['pw_hash TEXT', 'pw_salt TEXT']) { try { db.exec('ALTER TABLE users ADD COLUMN ' + c); } catch {} }
const hash = (pw, salt) => crypto.scryptSync(pw, salt, 64).toString('hex');
const session = u => ({ id: u.id, name: u.name, token: u.token });
app.post('/api/register', (req, res) => {
  const name = String(req.body.name || '').trim(), pw = String(req.body.password || '');
  if (!/^[\w .-]{3,30}$/.test(name)) return fail(res, 'Username: 3-30 letters, numbers, spaces, . _ -');
  if (pw.length < 6) return fail(res, 'Password must be at least 6 characters');
  if (db.prepare('SELECT 1 FROM users WHERE name=? COLLATE NOCASE').get(name)) return fail(res, 'That username is taken', 409);
  const salt = crypto.randomBytes(16).toString('hex'), token = crypto.randomBytes(24).toString('hex');
  const id = db.prepare('INSERT INTO users(name,token,pw_hash,pw_salt) VALUES(?,?,?,?)').run(name, token, hash(pw, salt), salt).lastInsertRowid;
  ok(res, { id, name, token });
});
app.post('/api/login', (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE name=? COLLATE NOCASE').get(String(req.body.name || '').trim());
  const bad = () => fail(res, 'Wrong username or password', 401);
  if (!u || !u.pw_hash) return bad();
  const a = Buffer.from(hash(String(req.body.password || ''), u.pw_salt), 'hex'), b = Buffer.from(u.pw_hash, 'hex');
  if (!crypto.timingSafeEqual(a, b)) return bad();
  const token = crypto.randomBytes(24).toString('hex'); db.prepare('UPDATE users SET token=? WHERE id=?').run(token, u.id);
  ok(res, session({ ...u, token }));
});
app.post('/api/relogin', (req, res) => {
  const u = db.prepare('SELECT id,name FROM users WHERE token=?').get(req.body.token || ''); u ? ok(res, u) : fail(res, 'bad token', 401);
});

app.get('/api/items', (req, res) => {
  settle(); const q = req.query, w = [], p = [];
  if (q.q) { w.push('(i.title LIKE ? OR i.description LIKE ?)'); p.push(`%${q.q}%`, `%${q.q}%`); }
  if (q.category) { w.push('i.category=?'); p.push(q.category); }
  if (q.condition) { w.push('i.condition=?'); p.push(q.condition); }
  if (q.status) { w.push('i.status=?'); p.push(q.status); } else if (!q.seller) w.push("i.status='active'");
  if (q.seller) { const u = db.prepare('SELECT id FROM users WHERE token=?').get(req.get('x-token') || ''); w.push('i.seller_id=?'); p.push(u ? u.id : -1); }
  if (q.closing) { w.push('i.closes_at<=?'); p.push(now() + 3600e3 * 24); }
  const price = 'COALESCE((SELECT MAX(amount) FROM bids WHERE item_id=i.id), i.start_price)';
  if (q.min) { w.push(price + '>=?'); p.push(+q.min); } if (q.max) { w.push(price + '<=?'); p.push(+q.max); }
  const rows = db.prepare(`${SELECT} ${w.length ? 'WHERE ' + w.join(' AND ') : ''} ORDER BY i.closes_at ASC`).all(...p);
  ok(res, { now: now(), items: rows.map(r => ({ ...r, photos: JSON.parse(r.photos).slice(0, 1) })) });
});
app.get('/api/items/:id', (req, res) => {
  settle(); const it = db.prepare(SELECT + ' WHERE i.id=?').get(req.params.id); if (!it) return fail(res, 'Not found', 404);
  it.photos = JSON.parse(it.photos);
  const bids = db.prepare('SELECT b.amount,b.created_at,u.name bidder FROM bids b JOIN users u ON u.id=b.bidder_id WHERE item_id=? ORDER BY b.id DESC').all(it.id);
  ok(res, { now: now(), item: it, bids });
});

function validate(b) {
  const f = { title: String(b.title || '').trim(), category: String(b.category || '').trim(), description: String(b.description || '').trim(),
    condition: String(b.condition || '').trim(), start_price: Math.floor(+b.start_price), min_inc: Math.floor(+b.min_inc), closes_at: +b.closes_at,
    photos: JSON.stringify((b.photos || []).slice(0, 4)) };
  if (!f.title || !f.category || !f.condition) return 'Title, category and condition are required';
  if (!(f.start_price > 0) || !(f.min_inc > 0)) return 'Starting price and increment must be positive';
  if (!(f.closes_at > now())) return 'Closing time must be in the future'; return f;
}
app.post('/api/items', auth, (req, res) => {
  const f = validate(req.body); if (typeof f === 'string') return fail(res, f);
  const id = db.prepare(`INSERT INTO items(seller_id,title,category,description,condition,photos,start_price,min_inc,closes_at,created_at)
    VALUES(?,?,?,?,?,?,?,?,?,?)`).run(req.user.id, f.title, f.category, f.description, f.condition, f.photos, f.start_price, f.min_inc, f.closes_at, now()).lastInsertRowid;
  ok(res, { id });
});
const mine = (req, res) => {
  const it = db.prepare('SELECT * FROM items WHERE id=?').get(req.params.id);
  if (!it) return fail(res, 'Not found', 404); if (it.seller_id !== req.user.id) return fail(res, 'Not your listing', 403); return it;
};
app.put('/api/items/:id', auth, (req, res) => { // editable only while active and before the first bid
  settle(); const it = mine(req, res); if (!it.id) return;
  if (it.status !== 'active') return fail(res, 'Only active listings can be edited');
  if (db.prepare('SELECT 1 FROM bids WHERE item_id=?').get(it.id)) return fail(res, 'Cannot edit after bidding has started; cancel instead');
  const f = validate(req.body); if (typeof f === 'string') return fail(res, f);
  db.prepare('UPDATE items SET title=?,category=?,description=?,condition=?,photos=?,start_price=?,min_inc=?,closes_at=? WHERE id=?')
    .run(f.title, f.category, f.description, f.condition, f.photos, f.start_price, f.min_inc, f.closes_at, it.id); ok(res);
});
app.post('/api/items/:id/cancel', auth, (req, res) => {
  settle(); const it = mine(req, res); if (!it.id) return;
  if (!['active', 'pending_approval', 'approved'].includes(it.status)) return fail(res, 'Cannot cancel now');
  db.prepare("UPDATE items SET status='cancelled' WHERE id=?").run(it.id);
  const ids = new Set(db.prepare('SELECT DISTINCT bidder_id FROM bids WHERE item_id=?').all(it.id).map(r => r.bidder_id));
  ids.forEach(u => notify(u, it.id, `"${it.title}" was cancelled by the seller.`)); ok(res);
});
app.post('/api/items/:id/bid', auth, (req, res) => {
  db.transaction(() => { // synchronous txn = no race between two bidders
    const it = db.prepare('SELECT * FROM items WHERE id=?').get(req.params.id); if (!it) return fail(res, 'Not found', 404);
    if (it.status !== 'active' || it.closes_at <= now()) return fail(res, 'Bidding is closed');
    if (it.seller_id === req.user.id) return fail(res, 'You cannot bid on your own item');
    const amount = Math.floor(+req.body.amount), top = db.prepare('SELECT * FROM bids WHERE item_id=? ORDER BY amount DESC LIMIT 1').get(it.id);
    const min = top ? top.amount + it.min_inc : it.start_price;
    if (!(amount >= min)) return fail(res, `Minimum bid is ₹${min}`);
    db.prepare('INSERT INTO bids(item_id,bidder_id,amount,created_at) VALUES(?,?,?,?)').run(it.id, req.user.id, amount, now());
    if (top && top.bidder_id !== req.user.id) notify(top.bidder_id, it.id, `You were outbid on "${it.title}" (now ₹${amount}).`);
    notify(it.seller_id, it.id, `New bid of ₹${amount} on "${it.title}".`); ok(res, { amount });
  })();
});
app.post('/api/items/:id/decision', auth, (req, res) => {
  settle(); const it = mine(req, res); if (!it.id) return; if (it.status !== 'pending_approval') return fail(res, 'Nothing to approve');
  const a = !!req.body.approve; db.prepare('UPDATE items SET status=? WHERE id=?').run(a ? 'approved' : 'rejected', it.id);
  notify(it.winner_id, it.id, a ? `Seller approved ₹${it.final_price} for "${it.title}". Arrange campus handover.` : `Seller rejected the winning price for "${it.title}".`); ok(res);
});
app.post('/api/items/:id/handover', auth, (req, res) => {
  const it = mine(req, res); if (!it.id) return; if (it.status !== 'approved') return fail(res, 'Item is not awaiting handover');
  const s = req.body.success; db.prepare('UPDATE items SET status=? WHERE id=?').run(s ? 'sold' : 'failed_pickup', it.id);
  notify(it.winner_id, it.id, s ? `Handover of "${it.title}" confirmed. Sale complete.` : `Pickup of "${it.title}" was recorded as failed.`); ok(res);
});
app.get('/api/notifications', auth, (req, res) => {
  ok(res, db.prepare('SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 50').all(req.user.id));
});
app.post('/api/notifications/read', auth, (req, res) => { db.prepare('UPDATE notifications SET read=1 WHERE user_id=?').run(req.user.id); ok(res); });
app.listen(process.env.PORT || 3000, () => console.log('http://localhost:3000'));
