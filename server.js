require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
app.set('trust proxy', 1);
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, limit: 40, standardHeaders: true, legacyHeaders: false }));

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 60 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true }
}, { timestamps: true });
const User = mongoose.model('User', userSchema);

const taskSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  title: { type: String, required: true, trim: true, maxlength: 160 },
  notes: { type: String, default: '', maxlength: 1000 },
  category: { type: String, default: 'Personal', maxlength: 40 },
  priority: { type: String, enum: ['Low', 'Medium', 'High'], default: 'Medium' },
  kind: { type: String, enum: ['once', 'routine'], default: 'once' },
  dueDate: { type: String, default: '' }, // YYYY-MM-DD, user's local date
  dueTime: { type: String, default: '' }, // HH:mm
  reminder: { type: Boolean, default: false },
  routineDays: { type: [Number], default: [0,1,2,3,4,5,6] }, // JS day numbers; all days by default
  completed: { type: Boolean, default: false }, // for one-off tasks
  completedAt: { type: Date, default: null },
  completionDates: { type: [String], default: [] }, // local YYYY-MM-DD dates for routines
  createdAt: { type: Date, default: Date.now }
}, { timestamps: true });
taskSchema.index({ userId: 1, dueDate: 1 });
const Task = mongoose.model('Task', taskSchema);

function setAuthCookie(res, userId) {
  const token = jwt.sign({ sub: String(userId) }, JWT_SECRET, { expiresIn: '14d' });
  res.cookie('tf_session', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', maxAge: 14 * 24 * 60 * 60 * 1000, path: '/' });
}
async function auth(req, res, next) {
  try {
    const token = req.cookies.tf_session;
    if (!token) return res.status(401).json({ error: 'Please sign in to continue.' });
    const payload = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(payload.sub).select('_id name email');
    if (!user) return res.status(401).json({ error: 'Session expired. Please sign in again.' });
    req.user = user; next();
  } catch { return res.status(401).json({ error: 'Session expired. Please sign in again.' }); }
}
function safeTask(task) { return task.toObject ? task.toObject() : task; }

app.get('/api/health', (_req, res) => res.json({ ok: true, database: mongoose.connection.readyState === 1 ? 'connected' : 'connecting' }));
app.post('/api/auth/register', async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    if (name.length < 2) return res.status(400).json({ error: 'Name must be at least 2 characters.' });
    if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
    if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    if (await User.exists({ email })) return res.status(409).json({ error: 'An account with this email already exists.' });
    const user = await User.create({ name, email, passwordHash: await bcrypt.hash(password, 12) });
    setAuthCookie(res, user._id);
    res.status(201).json({ user: { id: user._id, name: user.name, email: user.email } });
  } catch (e) { res.status(500).json({ error: 'Could not create account. Check your server and database settings.' }); }
});
app.post('/api/auth/login', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(String(req.body.password || ''), user.passwordHash))) return res.status(401).json({ error: 'Email or password is incorrect.' });
    setAuthCookie(res, user._id);
    res.json({ user: { id: user._id, name: user.name, email: user.email } });
  } catch { res.status(500).json({ error: 'Unable to sign in right now.' }); }
});
app.post('/api/auth/logout', (_req, res) => { res.clearCookie('tf_session', { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', path: '/' }); res.json({ ok: true }); });
app.get('/api/auth/me', auth, (req, res) => res.json({ user: req.user }));

app.get('/api/tasks', auth, async (req, res) => {
  const tasks = await Task.find({ userId: req.user._id }).sort({ createdAt: -1 }).lean();
  res.json({ tasks });
});
app.post('/api/tasks', auth, async (req, res) => {
  try {
    const b = req.body || {};
    const title = String(b.title || '').trim();
    if (!title) return res.status(400).json({ error: 'Task title is required.' });
    if (title.length > 160) return res.status(400).json({ error: 'Task title must be 160 characters or fewer.' });
    const kind = b.kind === 'routine' ? 'routine' : 'once';
    const days = Array.isArray(b.routineDays) ? b.routineDays.map(Number).filter(n => Number.isInteger(n) && n >= 0 && n <= 6) : [0,1,2,3,4,5,6];
    const task = await Task.create({ userId: req.user._id, title, notes: String(b.notes || '').slice(0,1000), category: String(b.category || 'Personal').slice(0,40), priority: ['Low','Medium','High'].includes(b.priority) ? b.priority : 'Medium', kind, dueDate: kind === 'once' ? String(b.dueDate || '') : '', dueTime: String(b.dueTime || ''), reminder: Boolean(b.reminder), routineDays: kind === 'routine' ? (days.length ? days : [0,1,2,3,4,5,6]) : [], completed: false, completionDates: [] });
    res.status(201).json({ task: safeTask(task) });
  } catch { res.status(400).json({ error: 'Could not save this task. Please check the fields.' }); }
});
app.patch('/api/tasks/:id', auth, async (req, res) => {
  try {
    const task = await Task.findOne({ _id: req.params.id, userId: req.user._id });
    if (!task) return res.status(404).json({ error: 'Task not found.' });
    const b = req.body || {};
    for (const key of ['title','notes','category','priority','dueDate','dueTime','reminder','kind','routineDays']) {
      if (Object.prototype.hasOwnProperty.call(b, key)) {
        if (key === 'title') task.title = String(b.title).trim().slice(0,160);
        else if (key === 'notes') task.notes = String(b.notes || '').slice(0,1000);
        else if (key === 'category') task.category = String(b.category || 'Personal').slice(0,40);
        else if (key === 'priority' && ['Low','Medium','High'].includes(b.priority)) task.priority = b.priority;
        else if (key === 'dueDate') task.dueDate = String(b.dueDate || '');
        else if (key === 'dueTime') task.dueTime = String(b.dueTime || '');
        else if (key === 'reminder') task.reminder = Boolean(b.reminder);
        else if (key === 'kind' && ['once','routine'].includes(b.kind)) task.kind = b.kind;
        else if (key === 'routineDays' && Array.isArray(b.routineDays)) task.routineDays = b.routineDays.map(Number).filter(n => Number.isInteger(n) && n >= 0 && n <= 6);
      }
    }
    await task.save(); res.json({ task: safeTask(task) });
  } catch { res.status(400).json({ error: 'Could not update task.' }); }
});
app.post('/api/tasks/:id/toggle', auth, async (req, res) => {
  try {
    const task = await Task.findOne({ _id: req.params.id, userId: req.user._id });
    if (!task) return res.status(404).json({ error: 'Task not found.' });
    const date = String(req.body.date || new Date().toISOString().slice(0,10));
    if (task.kind === 'routine') {
      task.completionDates = task.completionDates || [];
      task.completionDates = task.completionDates.includes(date) ? task.completionDates.filter(d => d !== date) : [...task.completionDates, date];
    } else {
      task.completed = !task.completed; task.completedAt = task.completed ? new Date() : null;
    }
    await task.save(); res.json({ task: safeTask(task) });
  } catch { res.status(400).json({ error: 'Could not update completion status.' }); }
});
app.delete('/api/tasks/:id', auth, async (req, res) => {
  const result = await Task.deleteOne({ _id: req.params.id, userId: req.user._id });
  if (!result.deletedCount) return res.status(404).json({ error: 'Task not found.' });
  res.json({ ok: true });
});

app.get('/{*path}', (req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
app.use((err, _req, res, _next) => { console.error(err); res.status(500).json({ error: 'Unexpected server error.' }); });

if (!JWT_SECRET) { console.error('Missing JWT_SECRET. Copy .env.example to .env and set JWT_SECRET.'); process.exit(1); }
if (!process.env.MONGODB_URI) { console.error('Missing MONGODB_URI. Set your MongoDB Atlas connection string in .env.'); process.exit(1); }
mongoose.connect(process.env.MONGODB_URI).then(() => {
  console.log('MongoDB connected');
  app.listen(PORT, () => console.log(`TaskFlow Cloud running on http://localhost:${PORT}`));
}).catch(err => { console.error('MongoDB connection failed:', err.message); process.exit(1); });
