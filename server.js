const express = require('express'), Database = require('better-sqlite3'), crypto = require('crypto');
const db = new Database(process.env.DB || 'auction.db'); db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, token TEXT, pw_hash TEXT, pw_salt TEXT);
CREATE UNIQUE INDEX IF NOT EXISTS u_name ON users(name COLLATE NOCASE);
CREATE TABLE IF NOT EXISTS items(id INTEGER PRIMARY KEY, seller_id INT, title TEXT, category TEXT, description TEXT, condition TEXT,
  photos TEXT DEFAULT '[]', start_price INT, min_inc INT, closes_at INT, status TEXT DEFAULT 'active', winner_id INT, final_price INT, created_at INT);
CREATE TABLE IF NOT EXISTS bids(id INTEGER PRIMARY KEY, item_id INT, bidder_id INT, amount INT, auto INT DEFAULT 0, created_at INT);
CREATE TABLE IF NOT EXISTS autobids(item_id INT, user_id INT, max_amount INT, created_at INT, PRIMARY KEY(item_id,user_id));
CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY, user_id INT, item_id INT, message TEXT, created_at INT, read INT DEFAULT 0);
`);
const app = express(); app.use(express.json({ limit: '12mb' })); app.use(express.static('public'));
const now = () => Date.now(), ok = (res, d = {}) => res.json(d), fail = (res, m, c = 400) => res.status(c).json({ error: m });
const notify = (uid, item_id, message) => uid && db.prepare('INSERT INTO notifications(user_id,item_id,message,created_at) VALUES(?,?,?,?)').run(uid, item_id, message, now());
const hash = (pw, salt) => crypto.scryptSync(pw, salt, 64).toString('hex');
const auth = (req, res, next) => { const u = db.prepare('SELECT * FROM users WHERE token=?').get(req.get('x-token') || '-'); if (!u) return fail(res, 'Please log in', 401); req.user = u; next(); };

app.post('/api/register', (req, res) => {
  const name = String(req.body.name || '').trim(), pw = String(req.body.password || '');
  if (!/^[\w .-]{3,30}$/.test(name)) return fail(res, 'Username: 3-30 letters, numbers, spaces, . _ -');
  if (pw.length < 6) return fail(res, 'Password must be at least 6 characters');
  if (db.prepare('SELECT 1 FROM users WHERE name=? COLLATE NOCASE').get(name)) return fail(res, 'That username is taken', 409);
  const salt = crypto.randomBytes(16).toString('hex'), token = crypto.randomBytes(24).toString('hex');
  const id = db.prepare('INSERT INTO users(name,token,pw_hash,pw_salt) VALUES(?,?,?,?)').run(name, token, hash(pw, salt), salt).lastInsertRowid; ok(res, { id, name, token });
});
app.post('/api/login', (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE name=? COLLATE NOCASE').get(String(req.body.name || '').trim());
  if (!u || !crypto.timingSafeEqual(Buffer.from(hash(String(req.body.password || ''), u.pw_salt), 'hex'), Buffer.from(u.pw_hash, 'hex'))) return fail(res, 'Wrong username or password', 401);
  const token = crypto.randomBytes(24).toString('hex'); db.prepare('UPDATE users SET token=? WHERE id=?').run(token, u.id); ok(res, { id: u.id, name: u.name, token });
});
app.post('/api/relogin', (req, res) => { const u = db.prepare('SELECT id,name FROM users WHERE token=?').get(String(req.body.token || '-')); u ? ok(res, u) : fail(res, 'bad token', 401); });

function settle() { // the server is the only clock
  for (const it of db.prepare("SELECT * FROM items WHERE status='active' AND closes_at<=?").all(now())) {
    const top = topBid(it.id);
    if (!top) { db.prepare("UPDATE items SET status='unsold' WHERE id=?").run(it.id); notify(it.seller_id, it.id, `"${it.title}" closed with no bids (unsold).`); }
    else {
      db.prepare("UPDATE items SET status='pending_approval',winner_id=?,final_price=? WHERE id=?").run(top.bidder_id, top.amount, it.id);
      notify(it.seller_id, it.id, `"${it.title}" closed at ₹${top.amount}. Approve or reject the price.`);
      notify(top.bidder_id, it.id, `You are the provisional winner of "${it.title}" at ₹${top.amount}. Awaiting seller approval.`);
    }
  }
}
setInterval(settle, 1000);

// ---- bidding core: every bid (manual or automatic) goes through insertBid ----
const topBid = id => db.prepare('SELECT * FROM bids WHERE item_id=? ORDER BY amount DESC, id ASC LIMIT 1').get(id);
const minNext = (it, top) => top ? top.amount + it.min_inc : it.start_price;
function insertBid(it, userId, amount, auto) {
  const t = now(), prev = topBid(it.id);
  db.prepare('INSERT INTO bids(item_id,bidder_id,amount,auto,created_at) VALUES(?,?,?,?,?)').run(it.id, userId, amount, auto ? 1 : 0, t);
  if (prev && prev.bidder_id !== userId) notify(prev.bidder_id, it.id, `You were outbid on "${it.title}" (now ₹${amount}).`);
  if (it.closes_at - t <= 30000) { // last-minute extension: close 60s after this bid
    it.closes_at = t + 60000; db.prepare('UPDATE items SET closes_at=? WHERE id=?').run(it.closes_at, it.id);
    const ids = new Set(db.prepare('SELECT DISTINCT bidder_id FROM bids WHERE item_id=?').all(it.id).map(r => r.bidder_id)); ids.add(it.seller_id);
    ids.forEach(u => u !== userId && notify(u, it.id, `Last-minute bid on "${it.title}": closing extended by up to 60s.`));
  }
}
function resolveAutobids(it) { // bid the minimum needed for the highest other maximum to take or keep the lead
  for (let n = 0; n < 500; n++) {
    const top = topBid(it.id), need = minNext(it, top);
    const c = db.prepare('SELECT * FROM autobids WHERE item_id=? AND user_id!=? AND max_amount>=? ORDER BY max_amount DESC, created_at ASC LIMIT 1').get(it.id, top ? top.bidder_id : -1, need);
    if (!c) return; insertBid(it, c.user_id, need, true);
  }
}
const openItem = (id, userId) => {
  const it = db.prepare('SELECT * FROM items WHERE id=?').get(id);
  if (!it) return [null, 'Not found']; if (it.status !== 'active' || it.closes_at <= now()) return [null, 'Bidding is closed'];
  if (it.seller_id === userId) return [null, 'You cannot bid on your own item']; return [it];
};
app.post('/api/items/:id/bid', auth, (req, res) => db.transaction(() => {
  const [it, e] = openItem(req.params.id, req.user.id); if (!it) return fail(res, e);
  const amount = Math.floor(+req.body.amount), min = minNext(it, topBid(it.id));
  if (!(amount >= min)) return fail(res, `Minimum bid is ₹${min}`);
  insertBid(it, req.user.id, amount, false); resolveAutobids(it); ok(res, { amount });
})());
app.post('/api/items/:id/autobid', auth, (req, res) => db.transaction(() => {
  const [it, e] = openItem(req.params.id, req.user.id); if (!it) return fail(res, e);
  const max = Math.floor(+req.body.max), old = db.prepare('SELECT * FROM autobids WHERE item_id=? AND user_id=?').get(it.id, req.user.id);
  const min = minNext(it, topBid(it.id)), top = topBid(it.id);
  if (!(max >= min) && !(top && top.bidder_id === req.user.id && max > top.amount)) return fail(res, `Your maximum must be at least ₹${min}`);
  if (old && max <= old.max_amount) return fail(res, `You can only raise your maximum (currently ₹${old.max_amount})`);
  db.prepare('INSERT INTO autobids(item_id,user_id,max_amount,created_at) VALUES(?,?,?,?) ON CONFLICT(item_id,user_id) DO UPDATE SET max_amount=excluded.max_amount').run(it.id, req.user.id, max, now());
  resolveAutobids(it); ok(res, { max });
})());

// ---- listings ----
const SELECT = `SELECT i.*, s.name seller, w.name winner,
 (SELECT MAX(amount) FROM bids WHERE item_id=i.id) current, (SELECT COUNT(*) FROM bids WHERE item_id=i.id) bid_count,
 (SELECT u.name FROM bids b JOIN users u ON u.id=b.bidder_id WHERE b.item_id=i.id ORDER BY amount DESC, b.id ASC LIMIT 1) leader
 FROM items i JOIN users s ON s.id=i.seller_id LEFT JOIN users w ON w.id=i.winner_id`;
app.get('/api/items', (req, res) => {
  settle(); const q = req.query, w = [], p = [];
  if (q.q) { w.push('(i.title LIKE ? OR i.description LIKE ?)'); p.push(`%${q.q}%`, `%${q.q}%`); }
  if (q.category) { w.push('i.category=?'); p.push(q.category); } if (q.condition) { w.push('i.condition=?'); p.push(q.condition); }
  if (q.seller) { const u = db.prepare('SELECT id FROM users WHERE token=?').get(req.get('x-token') || '-'); w.push('i.seller_id=?'); p.push(u ? u.id : -1); } else w.push("i.status='active'");
  if (q.closing) { w.push('i.closes_at<=?'); p.push(now() + 864e5); }
  const price = 'COALESCE((SELECT MAX(amount) FROM bids WHERE item_id=i.id), i.start_price)';
  if (q.min) { w.push(price + '>=?'); p.push(+q.min); } if (q.max) { w.push(price + '<=?'); p.push(+q.max); }
  const rows = db.prepare(`${SELECT} ${w.length ? 'WHERE ' + w.join(' AND ') : ''} ORDER BY i.closes_at ASC`).all(...p);
  ok(res, { now: now(), items: rows.map(r => ({ ...r, photos: JSON.parse(r.photos).slice(0, 1) })) });
});
app.get('/api/items/:id', (req, res) => {
  settle(); const it = db.prepare(SELECT + ' WHERE i.id=?').get(req.params.id); if (!it) return fail(res, 'Not found', 404);
  it.photos = JSON.parse(it.photos);
  const bids = db.prepare('SELECT b.amount,b.auto,b.created_at,u.name bidder FROM bids b JOIN users u ON u.id=b.bidder_id WHERE item_id=? ORDER BY b.id DESC').all(it.id);
  const maxes = db.prepare('SELECT a.max_amount,u.name bidder,a.user_id FROM autobids a JOIN users u ON u.id=a.user_id WHERE item_id=? ORDER BY max_amount DESC').all(it.id); // public by design
  ok(res, { now: now(), item: it, bids, maxes });
});
function validate(b) {
  const f = { title: String(b.title || '').trim(), category: String(b.category || ''), description: String(b.description || '').trim(), condition: String(b.condition || ''),
    start_price: Math.floor(+b.start_price), min_inc: Math.floor(+b.min_inc), closes_at: +b.closes_at, photos: JSON.stringify((b.photos || []).slice(0, 4)) };
  if (!f.title || !f.category || !f.condition) return 'Title, category and condition are required';
  if (!(f.start_price > 0) || !(f.min_inc > 0)) return 'Starting price and increment must be positive';
  if (!(f.closes_at > now())) return 'Closing time must be in the future'; return f;
}
app.post('/api/items', auth, (req, res) => {
  const f = validate(req.body); if (typeof f === 'string') return fail(res, f);
  ok(res, { id: db.prepare('INSERT INTO items(seller_id,title,category,description,condition,photos,start_price,min_inc,closes_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)')
    .run(req.user.id, f.title, f.category, f.description, f.condition, f.photos, f.start_price, f.min_inc, f.closes_at, now()).lastInsertRowid });
});
const mine = (req, res, statuses) => {
  const it = db.prepare('SELECT * FROM items WHERE id=?').get(req.params.id);
  if (!it) return fail(res, 'Not found', 404) && null; if (it.seller_id !== req.user.id) return fail(res, 'Not your listing', 403) && null;
  if (!statuses.includes(it.status)) return fail(res, 'Not allowed in the current state') && null; return it;
};
app.put('/api/items/:id', auth, (req, res) => {
  settle(); const it = mine(req, res, ['active']); if (!it) return;
  if (db.prepare('SELECT 1 FROM bids WHERE item_id=?').get(it.id)) return fail(res, 'Cannot edit after bidding has started; cancel instead');
  const f = validate(req.body); if (typeof f === 'string') return fail(res, f);
  db.prepare('UPDATE items SET title=?,category=?,description=?,condition=?,photos=?,start_price=?,min_inc=?,closes_at=? WHERE id=?').run(f.title, f.category, f.description, f.condition, f.photos, f.start_price, f.min_inc, f.closes_at, it.id); ok(res);
});
app.post('/api/items/:id/cancel', auth, (req, res) => {
  settle(); const it = mine(req, res, ['active', 'pending_approval', 'approved']); if (!it) return;
  db.prepare("UPDATE items SET status='cancelled' WHERE id=?").run(it.id);
  db.prepare('SELECT DISTINCT bidder_id FROM bids WHERE item_id=?').all(it.id).forEach(r => notify(r.bidder_id, it.id, `"${it.title}" was cancelled by the seller.`)); ok(res);
});
app.post('/api/items/:id/decision', auth, (req, res) => {
  settle(); const it = mine(req, res, ['pending_approval']); if (!it) return; const a = !!req.body.approve;
  db.prepare('UPDATE items SET status=? WHERE id=?').run(a ? 'approved' : 'rejected', it.id);
  notify(it.winner_id, it.id, a ? `Seller approved ₹${it.final_price} for "${it.title}". Arrange campus handover.` : `Seller rejected the winning price for "${it.title}".`); ok(res);
});
app.post('/api/items/:id/handover', auth, (req, res) => {
  const it = mine(req, res, ['approved']); if (!it) return; const s = !!req.body.success;
  db.prepare('UPDATE items SET status=? WHERE id=?').run(s ? 'sold' : 'failed_pickup', it.id);
  notify(it.winner_id, it.id, s ? `Handover of "${it.title}" confirmed. Sale complete.` : `Pickup of "${it.title}" was recorded as failed.`); ok(res);
});
app.get('/api/notifications', auth, (req, res) => ok(res, db.prepare('SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 50').all(req.user.id)));
app.post('/api/notifications/read', auth, (req, res) => { db.prepare('UPDATE notifications SET read=1 WHERE user_id=?').run(req.user.id); ok(res); });
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`http://localhost:${PORT}`));