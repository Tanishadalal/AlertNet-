require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const cors = require('cors');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] }
});

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const JWT_SECRET = process.env.JWT_SECRET || 'emergency_alert_secret_2024';
const PORT = process.env.PORT || 3000;

// ─── In-Memory Data Store ───────────────────────────────────────────────────
const db = {
  users: [],
  alerts: [],
  acknowledgments: [],
  pendingVerifications: {},
  onlineUsers: new Map()
};

// Seed admin user
(async () => {
  const adminHash = await bcrypt.hash('Admin@123', 10);
  db.users.push({
    id: uuidv4(),
    name: 'System Administrator',
    email: 'admin@rbunagpur.in',
    password: adminHash,
    role: 'admin',
    verified: true,
    createdAt: new Date().toISOString(),
    avatar: 'A'
  });
  console.log('✅ Admin seeded: admin@rbunagpur.in / Admin@123');
})();

// ─── Email Transport ────────────────────────────────────────────────────────
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.ethereal.email',
  port: parseInt(process.env.SMTP_PORT || '587'),
  secure: false,
  auth: {
    user: process.env.SMTP_USER || '',
    pass: process.env.SMTP_PASS || ''
  }
});

async function sendVerificationEmail(email, name, token) {
  const verifyUrl = `http://localhost:${PORT}/verify-email?token=${token}`;
  try {
    const info = await transporter.sendMail({
      from: '"AlertSystem" <no-reply@campus.edu>',
      to: email,
      subject: '🔐 Verify your Emergency Alert Account',
      html: `
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;background:#0a0a0f;color:#e0e0e0;padding:40px;border-radius:12px">
          <h1 style="color:#ff6b35;margin-bottom:8px">Emergency Alert System</h1>
          <p style="color:#888;margin-bottom:32px">Campus Security Platform</p>
          <h2 style="color:#fff">Hi ${name},</h2>
          <p>Please verify your email address to activate your account.</p>
          <a href="${verifyUrl}" style="display:inline-block;background:linear-gradient(135deg,#ff6b35,#ff3b3b);color:#fff;padding:14px 32px;border-radius:8px;text-decoration:none;font-weight:bold;margin:20px 0">
            Verify Email Address
          </a>
          <p style="color:#666;font-size:13px;margin-top:24px">Link expires in 24 hours. If you didn't register, ignore this email.</p>
          <p style="color:#666;font-size:12px;margin-top:16px">Or copy: ${verifyUrl}</p>
        </div>
      `
    });
    console.log('📧 Email preview:', nodemailer.getTestMessageUrl(info));
    return { success: true, previewUrl: nodemailer.getTestMessageUrl(info) };
  } catch (err) {
    console.log('📧 Email error (using dev mode):', err.message);
    console.log(`📧 DEV MODE - Verify link: ${verifyUrl}`);
    return { success: false, devUrl: verifyUrl };
  }
}

// ─── Auth Middleware ────────────────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

function adminMiddleware(req, res, next) {
  authMiddleware(req, res, () => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    next();
  });
}

const ALLOWED_ADMIN_EMAILS = ['admin@rbunagpur.in', '24dalalt@rbunagpur.in'];

function isAllowedAdminEmail(email) {
  return typeof email === 'string' && ALLOWED_ADMIN_EMAILS.includes(email.toLowerCase());
}

// ─── Auth Routes ────────────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });
    if (db.users.find(u => u.email === email)) return res.status(409).json({ error: 'Email already registered' });

    const userRole = role === 'admin' ? 'admin' : 'user';
    // For admin registration, require allowed email and valid key
    if (userRole === 'admin') {
      if (!isAllowedAdminEmail(email)) {
        return res.status(403).json({ error: 'Admin signup only allowed for specified @rbunagpur.in accounts' });
      }
      if (req.body.adminKey !== 'CAMPUS2024') {
        return res.status(403).json({ error: 'Invalid admin registration key' });
      }
    }

    const hash = await bcrypt.hash(password, 10);
    const verToken = uuidv4();
    const user = {
      id: uuidv4(),
      name,
      email,
      password: hash,
      role: userRole,
      verified: false,
      createdAt: new Date().toISOString(),
      avatar: name.charAt(0).toUpperCase()
    };
    db.users.push(user);
    db.pendingVerifications[verToken] = { userId: user.id, expires: Date.now() + 86400000 };

    const emailResult = await sendVerificationEmail(email, name, verToken);
    res.json({
      message: 'Registration successful! Check your email.',
      devVerifyUrl: emailResult.devUrl || null,
      previewUrl: emailResult.previewUrl || null
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = db.users.find(u => u.email === email);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    if (user.role === 'admin' && !isAllowedAdminEmail(user.email)) {
      return res.status(403).json({ error: 'Admin login only allowed for specified @rbunagpur.in accounts' });
    }
    if (!user.verified) return res.status(403).json({ error: 'Please verify your email first' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '24h' });
    res.json({
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/verify-email', (req, res) => {
  const { token } = req.query;
  const record = db.pendingVerifications[token];
  if (!record || record.expires < Date.now()) {
    return res.send(`<!DOCTYPE html><html><body style="background:#0a0a0f;color:#ff4444;font-family:Arial;text-align:center;padding:60px">
      <h1>❌ Invalid or expired verification link</h1>
      <a href="/" style="color:#ff6b35">← Back to Login</a></body></html>`);
  }
  const user = db.users.find(u => u.id === record.userId);
  if (user) {
    user.verified = true;
    delete db.pendingVerifications[token];
  }
  res.send(`<!DOCTYPE html><html><body style="background:#0a0a0f;color:#22c55e;font-family:Arial;text-align:center;padding:60px">
    <h1>✅ Email Verified Successfully!</h1>
    <p style="color:#888">Your account is now active.</p>
    <a href="/" style="display:inline-block;background:#ff6b35;color:#fff;padding:12px 28px;border-radius:8px;text-decoration:none;margin-top:20px">Go to Login →</a>
    </body></html>`);
});

// ─── Alert Routes ───────────────────────────────────────────────────────────
app.post('/api/alerts', adminMiddleware, (req, res) => {
  const { type, title, message, severity, affectedZones } = req.body;
  const alert = {
    id: uuidv4(),
    type,
    title,
    message,
    severity: severity || 'high',
    affectedZones: affectedZones || ['All Zones'],
    status: 'active',
    createdBy: req.user.name,
    createdAt: new Date().toISOString(),
    resolvedAt: null,
    acknowledgments: []
  };
  db.alerts.unshift(alert);
  io.emit('new_alert', alert);
  io.emit('alert_stats', getStats());
  res.json(alert);
});

app.patch('/api/alerts/:id/resolve', adminMiddleware, (req, res) => {
  const alert = db.alerts.find(a => a.id === req.params.id);
  if (!alert) return res.status(404).json({ error: 'Alert not found' });
  alert.status = 'resolved';
  alert.resolvedAt = new Date().toISOString();
  io.emit('alert_resolved', alert);
  io.emit('alert_stats', getStats());
  res.json(alert);
});

app.post('/api/alerts/:id/acknowledge', authMiddleware, (req, res) => {
  const alert = db.alerts.find(a => a.id === req.params.id);
  if (!alert) return res.status(404).json({ error: 'Alert not found' });
  const alreadyAck = alert.acknowledgments.find(a => a.userId === req.user.id);
  if (alreadyAck) return res.json({ message: 'Already acknowledged' });

  const ack = {
    userId: req.user.id,
    userName: req.user.name,
    userEmail: req.user.email,
    timestamp: new Date().toISOString(),
    location: req.body.location || 'Unknown'
  };
  alert.acknowledgments.push(ack);
  io.emit('acknowledgment', { alertId: alert.id, acknowledgment: ack, total: alert.acknowledgments.length });
  io.emit('alert_stats', getStats());
  res.json({ message: 'Acknowledged', ack });
});

app.get('/api/alerts', authMiddleware, (req, res) => {
  res.json(db.alerts);
});

app.get('/api/stats', authMiddleware, (req, res) => {
  res.json(getStats());
});

app.get('/api/users', adminMiddleware, (req, res) => {
  res.json(db.users.map(u => ({ id: u.id, name: u.name, email: u.email, role: u.role, verified: u.verified, createdAt: u.createdAt })));
});

function getStats() {
  const active = db.alerts.filter(a => a.status === 'active');
  return {
    totalAlerts: db.alerts.length,
    activeAlerts: active.length,
    resolvedAlerts: db.alerts.filter(a => a.status === 'resolved').length,
    onlineUsers: db.onlineUsers.size,
    totalUsers: db.users.filter(u => u.role === 'user').length,
    byType: {
      fire: db.alerts.filter(a => a.type === 'fire').length,
      medical: db.alerts.filter(a => a.type === 'medical').length,
      lockdown: db.alerts.filter(a => a.type === 'lockdown').length,
      evacuation: db.alerts.filter(a => a.type === 'evacuation').length,
      weather: db.alerts.filter(a => a.type === 'weather').length,
      custom: db.alerts.filter(a => a.type === 'custom').length
    },
    recentAcknowledgments: db.alerts.flatMap(a => a.acknowledgments).sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)).slice(0, 10)
  };
}

// ─── Socket.io ──────────────────────────────────────────────────────────────
io.on('connection', (socket) => {
  console.log('🔌 Connected:', socket.id);

  socket.on('join', (userData) => {
    socket.userData = userData;
    db.onlineUsers.set(socket.id, userData);
    io.emit('user_count', db.onlineUsers.size);
    io.emit('online_users', Array.from(db.onlineUsers.values()));
    // Send current active alerts on join
    socket.emit('init_alerts', db.alerts);
    socket.emit('alert_stats', getStats());
  });

  socket.on('disconnect', () => {
    db.onlineUsers.delete(socket.id);
    io.emit('user_count', db.onlineUsers.size);
    io.emit('online_users', Array.from(db.onlineUsers.values()));
  });
});

// Serve SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

server.listen(PORT, () => {
  console.log(`\n🚨 Emergency Alert System running at http://localhost:${PORT}`);
  console.log(`📊 Admin: admin@campus.edu / Admin@123\n`);
});
