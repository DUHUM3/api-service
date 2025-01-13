const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;

// مفتاح سري لتشفير JWT
const JWT_SECRET = 'your_secret_key';

// الاتصال بقاعدة البيانات
mongoose.connect('mongodb://127.0.0.1:27017/authDB', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const studentSchema = new mongoose.Schema({
  name: { type: String, required: true },
  age: { type: Number, required: true },
  grade: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);
const Student = mongoose.model('Student', studentSchema);

// Middleware لتحليل بيانات JSON
app.use(bodyParser.json());

// Middleware للتحقق من التوثيق (JWT)
function authenticateToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).json({ message: 'Access denied' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
}

// تسجيل مستخدم جديد
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' });
  }

  const existingUser = await User.findOne({ username });
  if (existingUser) {
    return res.status(409).json({ message: 'Username already exists' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ username, password: hashedPassword });
  await user.save();

  res.status(201).json({ message: 'User registered successfully' });
});

// تسجيل الدخول
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' });
  }

  const user = await User.findOne({ username });
  if (!user) {
    return res.status(401).json({ message: 'Invalid username or password' });
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(401).json({ message: 'Invalid username or password' });
  }

  const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET, {
    expiresIn: '1h',
  });

  res.status(200).json({ message: 'Login successful', token });
});

// إضافة طالب جديد
app.post('/api/students', authenticateToken, async (req, res) => {
  const { name, age, grade } = req.body;

  if (!name || !age || !grade) {
    return res.status(400).json({ message: 'Name, age, and grade are required' });
  }

  const student = new Student({ name, age, grade });
  await student.save();

  res.status(201).json({ message: 'Student added successfully', student });
});

// جلب قائمة الطلاب
app.get('/api/students', authenticateToken, async (req, res) => {
  const students = await Student.find();
  res.status(200).json(students);
});

// تعديل بيانات طالب
app.put('/api/students/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { name, age, grade } = req.body;

  const student = await Student.findByIdAndUpdate(
    id,
    { name, age, grade },
    { new: true }
  );

  if (!student) {
    return res.status(404).json({ message: 'Student not found' });
  }

  res.status(200).json({ message: 'Student updated successfully', student });
});

// حذف طالب
app.delete('/api/students/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  const student = await Student.findByIdAndDelete(id);
  if (!student) {
    return res.status(404).json({ message: 'Student not found' });
  }

  res.status(200).json({ message: 'Student deleted successfully' });
});

// بدء الخادم
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
