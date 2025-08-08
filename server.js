require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { body, validationResult } = require('express-validator');
const Razorpay = require('razorpay');
const nodemailer = require('nodemailer');

const app = express();

// CORS setup - restrict to your frontend URL
app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials: true
}));

app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// MAILER SETUP
const mailer = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS
  }
});

// MySQL pool
const db = mysql.createPool({
  host               : process.env.DB_HOST,
  port               : process.env.DB_PORT,
  user               : process.env.DB_USER,
  password           : process.env.DB_PASS,
  database           : process.env.DB_NAME,
  waitForConnections : true,
  connectionLimit    : 10,
  connectTimeout     : 10000
});

db.getConnection((err, connection) => {
  if (err) {
    console.error('DB connection error:', err);
  } else {
    console.log('Connected to MySQL');
    connection.release();
  }
});

const JWT_SECRET = process.env.JWT_SECRET || 'yourSecretKey';
const SALT_ROUNDS = parseInt(process.env.SALT_ROUNDS, 10) || 10;

// Ensure tables and seed default admin
(async () => {
  try {
    await db.execute(
      `CREATE TABLE IF NOT EXISTS admin (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(100) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )`
    );
    const [admins] = await db.execute('SELECT id FROM admin');
    if (!admins.length) {
      const defaultName = process.env.ADMIN_NAME || 'SuperAdmin';
      const defaultEmail = process.env.ADMIN_EMAIL || 'admin@example.com';
      const defaultPassword = process.env.ADMIN_PASSWORD || 'changeMe123';
      const hash = await bcrypt.hash(defaultPassword, SALT_ROUNDS);
      await db.execute(
        'INSERT INTO admin (name, email, password) VALUES (?, ?, ?)',
        [defaultName, defaultEmail, hash]
      );
      console.log(`Default admin created: ${defaultEmail}`);
    }

    await db.execute(
      `CREATE TABLE IF NOT EXISTS login_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(100) NOT NULL,
        role ENUM('user','admin') NOT NULL DEFAULT 'user',
        logged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )`
    );

    console.log('Database tables are ready');
  } catch (err) {
    console.error('Table migration error:', err);
  }
})();

// Razorpay setup
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

// Force HTTPS in production
if (process.env.NODE_ENV === 'production') {
  app.enable('trust proxy');
  app.use((req, res, next) => {
    if (req.secure) return next();
    res.redirect(`https://${req.headers.host}${req.url}`);
  });
}

// Multer setup for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage });

// Auth middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

app.get('/', (req, res) => {
  res.send('API is running');
});


// --- SIGNUP (users only) ---
app.post('/api/signup', upload.single('photo'), [
    body('fullName').trim().notEmpty(),
    body('fatherName').trim().notEmpty(),
    body('email').isEmail().normalizeEmail(),
    body('phone').isMobilePhone('any'),
    body('password').isLength({ min: 6 }),
    body('address').trim().notEmpty(),
    body('govId').trim().notEmpty()
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { fullName, fatherName, email, phone, password, address, govId } = req.body;
    const photo = req.file ? req.file.filename : null;
    try {
      const [existing] = await db.execute('SELECT id FROM signup WHERE email = ?', [email]);
      if (existing.length) return res.status(409).json({ error: 'Email already registered.' });

      const hashed = await bcrypt.hash(password, SALT_ROUNDS);
      const insertSql = `INSERT INTO signup
        (name, father_name, mob_number, email, password, photo, address, gov_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;
      const [result] = await db.execute(insertSql, [
        fullName, fatherName, phone, email, hashed, photo, address, govId
      ]);

      res.status(201).json({ message: 'Signed up!', id: result.insertId });
    } catch (err) {
      console.error('Signup error:', err);
      res.status(500).json({ error: 'Server error.' });
    }
  }
);

// --- LOGIN (users & admins) ---
app.post('/api/login', [
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty(),
    body('role').isIn(['user', 'admin'])
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { email, password, role } = req.body;
    const table = role === 'admin' ? 'admin' : 'signup';
    try {
      const [rows] = await db.execute(`SELECT * FROM \`${table}\` WHERE email = ?`, [email]);
      if (!rows.length) return res.status(401).json({ error: 'Invalid credentials.' });
      const user = rows[0];
      const match = await bcrypt.compare(password, user.password);
      if (!match) return res.status(401).json({ error: 'Invalid credentials.' });

      const token = jwt.sign({ id: user.id, email: user.email, role }, JWT_SECRET, { expiresIn: '2h' });
      await db.execute('INSERT INTO login_logs (email, role) VALUES (?, ?)', [email, role]);

      res.json({ message: 'Login successful', token, email: user.email, role });
    } catch (err) {
      console.error('Login error:', err);
      res.status(500).json({ error: 'Server error.' });
    }
  }
);

app.delete('/api/admin/user/:id', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Unauthorized' });

  const userId = req.params.id;
  try {
    await db.execute('DELETE FROM bookings WHERE user_id = ?', [userId]);
    const [result] = await db.execute('DELETE FROM signup WHERE id = ?', [userId]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ message: 'User deleted successfully' });
  } catch (err) {
    console.error('Delete error:', err);
    res.status(500).json({ error: 'Server error during delete' });
  }
});

// --- UPDATE USER SIGNUP RECORD ---
app.put('/api/signup/:id', authenticateToken, async (req, res) => {
  const userId = req.params.id;
  const {
    name, father_name, mob_number, email, address, gov_id,
    seat_number, time_slot
  } = req.body;

  try {
    const fields = [];
    const params = [];

    if (name)         { fields.push('name = ?');         params.push(name); }
    if (father_name)  { fields.push('father_name = ?');  params.push(father_name); }
    if (mob_number)   { fields.push('mob_number = ?');   params.push(mob_number); }
    if (email)        { fields.push('email = ?');        params.push(email); }
    if (address)      { fields.push('address = ?');      params.push(address); }
    if (gov_id)       { fields.push('gov_id = ?');       params.push(gov_id); }

    if (fields.length) {
      await db.execute(
        `UPDATE signup SET ${fields.join(', ')} WHERE id = ?`,
        [...params, userId]
      );
    }

    if (seat_number || time_slot) {
      const bookingFields = [];
      const bookingParams = [];

      if (seat_number) bookingFields.push('seat_number = ?'), bookingParams.push(seat_number);
      if (time_slot)   bookingFields.push('time_slot   = ?'), bookingParams.push(time_slot);

      await db.execute(
        `UPDATE bookings SET ${bookingFields.join(', ')} WHERE user_id = ?`,
        [...bookingParams, userId]
      );

      await db.execute(
        `UPDATE signup SET seat_number = ?, time_slot = ? WHERE id = ?`,
        [seat_number || null, time_slot || null, userId]
      );
    }

    const [rows] = await db.execute('SELECT * FROM signup WHERE id = ?', [userId]);
    const updated = rows[0];
    updated.photo = updated.photo
      ? `${req.protocol}://${req.get('host')}/uploads/${updated.photo}`
      : null;

    res.json(updated);
  } catch (err) {
    console.error('Update signup error:', err);
    res.status(500).json({ error: 'Server error during update.' });
  }
});

// --- ADMIN: FETCH ALL BOOKINGS ---
app.get('/api/admin/book', authenticateToken, async (req, res) => {
  try {
    const [rows] = await db.execute(`
      SELECT 
        b.id, b.seat_number, b.time_slot, b.created_at, b.paid,
        u.name AS user_name, u.email AS user_email
      FROM bookings b
      JOIN signup u ON b.user_id = u.id
      ORDER BY b.created_at DESC
    `);
    res.json(rows);
  } catch (err) {
    console.error('Admin fetch bookings error:', err);
    res.status(500).json({ error: 'Server error fetching bookings.' });
  }
});

// --- FETCH ALL SIGNUP RECORDS ---
app.get('/api/signup', async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM signup');
    const data = rows.map(r => ({
      ...r,
      photo: r.photo ? `${req.protocol}://${req.get('host')}/uploads/${r.photo}` : null
    }));
    res.json(data);
  } catch (err) {
    console.error('Fetch signup error:', err);
    res.status(500).json({ error: 'Server error fetching signup records.' });
  }
});

// --- FETCH USER PROFILE (with cleanup) ---
app.get('/api/user/:email', authenticateToken, async (req, res) => {
  if (req.user.email !== req.params.email) return res.sendStatus(403);
  try {
    const [rows] = await db.execute('SELECT * FROM signup WHERE email = ?', [req.params.email]);
    if (!rows.length) return res.status(404).json({ error: 'User not found.' });
    const user = rows[0];
    user.photo = user.photo
      ? `${req.protocol}://${req.get('host')}/uploads/${user.photo}`
      : null;

    const [[booking]] = await db.execute(`
      SELECT id, seat_number, time_slot, created_at, COALESCE(paid,0) AS paid
      FROM bookings
      WHERE user_id = ?
      ORDER BY id DESC
      LIMIT 1
    `, [user.id]);

    if (booking) {
      const created = new Date(booking.created_at).getTime();
      const expiry  = created + 30*24*60*60*1000;
      if (Date.now() >= expiry) {
        await db.execute('DELETE FROM bookings WHERE id = ?', [booking.id]);
        await db.execute('UPDATE signup SET seat_number = NULL, time_slot = NULL WHERE id = ?', [user.id]);
        user.seat_number = null;
        user.time_slot   = null;
        user.paid        = 0;
      } else {
        user.seat_number = booking.seat_number;
        user.time_slot   = booking.time_slot;
        user.paid        = booking.paid;
      }
    }

    delete user.password;
    res.json(user);
  } catch (err) {
    console.error('Profile fetch error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// --- UPDATE USER PROFILE ---
app.put(
  '/api/user/:email',
  authenticateToken,
  upload.single('photo'),
  [
    body('name').optional().trim().notEmpty().withMessage('Name cannot be empty.'),
    body('mob_number').optional().isMobilePhone('any').withMessage('Invalid phone.'),
    body('address').optional().trim().notEmpty().withMessage('Address cannot be empty.'),
    body('seat_number').optional().trim(),
    body('currentPassword').optional().isLength({ min: 6 }).withMessage('Current password too short.'),
    body('newPassword').optional().isLength({ min: 6 }).withMessage('New password too short.')
  ],
  async (req, res) => {
    if (req.user.email !== req.params.email) return res.sendStatus(403);
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { name, mob_number, address, seat_number, currentPassword, newPassword } = req.body;
    const photoFilename = req.file?.filename;

    try {
      if (newPassword) {
        const [rows] = await db.execute('SELECT password FROM signup WHERE email = ?', [req.params.email]);
        const match = await bcrypt.compare(currentPassword, rows[0].password);
        if (!match) return res.status(400).json({ error: 'Current password incorrect.' });
      }

      const fields = [], paramsArr = [];
      if (name !== undefined)       { fields.push('name = ?'); paramsArr.push(name); }
      if (mob_number !== undefined) { fields.push('mob_number = ?'); paramsArr.push(mob_number); }
      if (address !== undefined)    { fields.push('address = ?'); paramsArr.push(address); }
      if (photoFilename)            { fields.push('photo = ?'); paramsArr.push(photoFilename); }
      if (newPassword) {
        const hashed = await bcrypt.hash(newPassword, SALT_ROUNDS);
        fields.push('password = ?'); paramsArr.push(hashed);
      }
      if (seat_number !== undefined){ fields.push('seat_number = ?'); paramsArr.push(seat_number); }
      if (req.body.time_slot)       { fields.push('time_slot = ?'); paramsArr.push(req.body.time_slot); }

      if (!fields.length) return res.status(400).json({ error: 'No fields to update.' });

      fields.push('updated_at = CURRENT_TIMESTAMP');
      const sql = `UPDATE signup SET ${fields.join(', ')} WHERE email = ?`;
      paramsArr.push(req.params.email);
      await db.execute(sql, paramsArr);

      const [rows2] = await db.execute('SELECT * FROM signup WHERE email = ?', [req.params.email]);
      const updated = rows2[0];
      updated.photo = updated.photo
        ? `${req.protocol}://${req.get('host')}/uploads/${updated.photo}`
        : null;
      delete updated.password;
      res.json(updated);
    } catch (err) {
      console.error('Profile update error:', err);
      res.status(500).json({ error: 'Server error during profile update.' });
    }
  }
);

// --- FETCH SEATS FOR A TIMESLOT ---
app.get('/api/seats', authenticateToken, async (req, res) => {
  const { timeSlot } = req.query;
  try {
    const [rows] = await db.execute(
      'SELECT seat_number, time_slot FROM bookings WHERE time_slot = ?',
      [timeSlot]
    );
    const seats = rows.map(r => ({ seat_number: r.seat_number, status: r.time_slot === '7am-10pm' ? 'all-shifts' : 'limited' }));
    res.json(seats);
  } catch (err) {
    console.error('Seats fetch error:', err);
    res.status(500).json({ error: 'Server error fetching seats.' });
  }
});

// --- BOOK A SEAT ---
app.post('/api/bookings', authenticateToken, async (req, res) => {
  const { seat_number, time_slot } = req.body;
  try {
    const [dup] = await db.execute(
      'SELECT 1 FROM bookings WHERE seat_number = ? AND time_slot = ?',
      [seat_number, time_slot]
    );
    if (dup.length) return res.status(409).json({ error: 'Seat already booked.' });

    if (time_slot === '7am-10pm') {
      const [limited] = await db.execute(
        'SELECT 1 FROM bookings WHERE seat_number = ? AND time_slot != ?',
        [seat_number, '7am-10pm']
      );
      if (limited.length) return res.status(409).json({ error: 'Cannot book all-shifts: already limited.' });
    }

    const [userHas] = await db.execute('SELECT 1 FROM bookings WHERE user_id = ?', [req.user.id]);
    if (userHas.length) return res.status(409).json({ error: 'You already have an active booking.' });

    await db.execute(
      'INSERT INTO bookings (user_id, seat_number, time_slot, paid) VALUES (?, ?, ?, 0)',
      [req.user.id, seat_number, time_slot]
    );
    await db.execute(
      'UPDATE signup SET seat_number = ?, time_slot = ? WHERE id = ?',
      [seat_number, time_slot, req.user.id]
    );

    res.status(201).json({ message: 'Booked (awaiting payment).' });
  } catch (err) {
    console.error('Booking error:', err);
    res.status(500).json({ error: 'Server error during booking.' });
  }
});

// --- CREATE RAZORPAY ORDER ---
app.post('/api/create-order', authenticateToken, async (req, res) => {
  try {
    const { amount, receipt } = req.body;
    const order = await razorpay.orders.create({ amount, currency: 'INR', receipt, payment_capture: 1 });
    res.json(order);
  } catch (err) {
    console.error('Order creation error:', err);
    res.status(500).json({ error: 'Could not create order' });
  }
});

// --- VERIFY PAYMENT ---
app.post('/api/verify-payment', authenticateToken, async (req, res) => {
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature, seat_number, time_slot } = req.body;
  const bodyStr = razorpay_order_id + '|' + razorpay_payment_id;
  const expectedSignature = crypto
    .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
    .update(bodyStr)
    .digest('hex');

  if (expectedSignature === razorpay_signature) {
    await db.execute(
      'UPDATE bookings SET paid = 1 WHERE user_id = ? AND seat_number = ? AND time_slot = ?',
      [req.user.id, seat_number, time_slot]
    );
    return res.json({ status: 'ok' });
  }
  res.status(400).json({ error: 'Invalid signature' });
});

// --- FORGOT PASSWORD ---
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {
    const [[user]] = await db.execute('SELECT id FROM signup WHERE email = ?', [email]);
    if (!user) return res.status(404).json({ error: 'Email not registered' });

    const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '15m' });
    const link = `${process.env.FRONTEND_URL}/reset-password/${token}`;

    await mailer.sendMail({
      to: email,
      from: process.env.GMAIL_USER,
      subject: '🔑 Reset Your Password',
      html: `<p>Click <a href=\"${link}\">here</a> to reset your password. This link expires in 15 minutes.</p>`
    });

    res.json({ message: 'Reset link sent.' });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// --- RESET PASSWORD ---
app.post('/api/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  try {
    const { email } = jwt.verify(token, JWT_SECRET);
    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    await db.execute('UPDATE signup SET password = ? WHERE email = ?', [hash, email]);
    res.json({ message: 'Password updated successfully.' });
  } catch (err) {
    console.error('Reset-password error:', err);
    res.status(400).json({ error: 'Invalid or expired link.' });
  }
});

// Example in Express.js
app.get('/test-db', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT 1'); // use your DB client here
    res.send('Database connection successful');
  } catch (err) {
    console.error(err);
    res.status(500).send('Database connection failed');
  }
});

// Start server
const PORT = process.env.PORT || 8080;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});
