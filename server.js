const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');

const app = express();
const db = new sqlite3.Database('./applications.db');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
  secret: 'mc-apply-secret-key-1234',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

// Initialize Database
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS admin (
    id INTEGER PRIMARY KEY,
    password TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_code TEXT UNIQUE,
    ign TEXT,
    discord TEXT,
    role TEXT,
    experience TEXT,
    reason TEXT,
    status TEXT DEFAULT 'PENDING',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS thread_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_code TEXT,
    sender TEXT,
    message TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Default Owner Password: admin123
  db.get(`SELECT * FROM admin WHERE id = 1`, (err, row) => {
    if (!row) {
      const hashed = bcrypt.hashSync('admin123', 10);
      db.run(`INSERT INTO admin (id, password) VALUES (1, ?)`, [hashed]);
    }
  });
});

// Middleware: Owner Only
function requireOwner(req, res, next) {
  if (!req.session.isOwner) {
    return res.status(403).json({ error: 'Access denied: Owner only' });
  }
  next();
}

// --- APPLICANT API ---

// 1. Submit Application
app.post('/api/apply', (req, res) => {
  const { ign, discord, role, experience, reason } = req.body;
  if (!ign || !discord || !role || !experience || !reason) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  const ticketCode = 'APP-' + crypto.randomBytes(3).toString('hex').toUpperCase();

  db.run(
    `INSERT INTO applications (ticket_code, ign, discord, role, experience, reason) VALUES (?, ?, ?, ?, ?, ?)`,
    [ticketCode, ign, discord, role, experience, reason],
    function(err) {
      if (err) return res.status(500).json({ error: 'Database write error' });
      res.json({ success: true, ticketCode });
    }
  );
});

// 2. View Single Ticket (Applicant or Owner)
app.get('/api/ticket/:code', (req, res) => {
  const code = req.params.code.toUpperCase();
  db.get(`SELECT * FROM applications WHERE ticket_code = ?`, [code], (err, appData) => {
    if (err || !appData) return res.status(404).json({ error: 'Ticket not found' });

    db.all(`SELECT * FROM thread_messages WHERE ticket_code = ? ORDER BY id ASC`, [code], (err, messages) => {
      res.json({ application: appData, messages: messages || [] });
    });
  });
});

// 3. Post Message in Follow-Up Thread
app.post('/api/ticket/:code/message', (req, res) => {
  const code = req.params.code.toUpperCase();
  const { message, sender } = req.body;

  if (!message || !message.trim()) return res.status(400).json({ error: 'Message empty' });

  // Validate sender
  let verifiedSender = 'APPLICANT';
  if (req.session.isOwner) {
    verifiedSender = 'OWNER';
  } else if (sender !== 'APPLICANT') {
    return res.status(403).json({ error: 'Invalid sender' });
  }

  db.get(`SELECT status FROM applications WHERE ticket_code = ?`, [code], (err, appData) => {
    if (!appData) return res.status(404).json({ error: 'Ticket not found' });
    if (appData.status === 'CLOSED' || appData.status === 'DENIED') {
      return res.status(400).json({ error: 'This ticket thread is closed' });
    }

    db.run(
      `INSERT INTO thread_messages (ticket_code, sender, message) VALUES (?, ?, ?)`,
      [code, verifiedSender, message.trim()],
      (err) => {
        if (err) return res.status(500).json({ error: 'Failed to send' });
        res.json({ success: true });
      }
    );
  });
});

// --- OWNER AUTH & API ---

app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  db.get(`SELECT password FROM admin WHERE id = 1`, (err, row) => {
    if (row && bcrypt.compareSync(password, row.password)) {
      req.session.isOwner = true;
      res.json({ success: true });
    } else {
      res.status(401).json({ error: 'Invalid password' });
    }
  });
});

app.post('/api/admin/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/api/admin/session', (req, res) => {
  res.json({ isOwner: !!req.session.isOwner });
});

app.post('/api/admin/change-password', requireOwner, (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 5) {
    return res.status(400).json({ error: 'Minimum 5 characters' });
  }
  const hashed = bcrypt.hashSync(newPassword, 10);
  db.run(`UPDATE admin SET password = ? WHERE id = 1`, [hashed], (err) => {
    if (err) return res.status(500).json({ error: 'Failed to update' });
    res.json({ success: true });
  });
});

app.get('/api/admin/applications', requireOwner, (req, res) => {
  db.all(`SELECT * FROM applications ORDER BY id DESC`, (err, rows) => {
    res.json(rows || []);
  });
});

app.post('/api/admin/set-status', requireOwner, (req, res) => {
  const { ticket_code, status } = req.body;
  db.run(`UPDATE applications SET status = ? WHERE ticket_code = ?`, [status, ticket_code], (err) => {
    if (err) return res.status(500).json({ error: 'Failed update' });
    res.json({ success: true });
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Application portal listening on port ${PORT}`));
