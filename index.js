const express = require('express');
const path = require('path');
require('dotenv').config();
const cors = require('cors');
const bodyParser = require('body-parser');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const https = require('https');
const fs = require('fs');
const uploadsDir = path.join(__dirname, 'uploads');
const pageBannerDir = path.join(uploadsDir, 'pagebanner');

// Paths to your SSL certificate files
const privateKey = fs.readFileSync(path.resolve('/etc/nginx/ssl/cloudflare/privkey.pem'), 'utf8');
const certificate = fs.readFileSync(path.resolve('/etc/nginx/ssl/cloudflare/certificate.pem'), 'utf8');
// // Set up SSL credentials
const credentials = { key: privateKey, cert: certificate };

const app = express();
const port = 3001;

// Determine environment
const isProduction = process.env.NODE_ENV === 'production';

// CORS options based on environment
// const corsOptions = {
//   origin: isProduction ? ['https://dermalicious.id', 'http://103.177.56.115'] : 'http://localhost:3000',
//   methods: ['GET', 'POST', 'PUT', 'DELETE'], 
//   allowedHeaders: ['Content-Type', 'Authorization'], 
//   credentials: true // if using cookies
// };

const corsOptions = {
    origin: ['https://dermalicious.id', 'https://www.dermalicious.id', 'http://103.177.56.115'], // Allowed origins
    methods: ['GET', 'POST', 'PUT', 'DELETE'], 
    allowedHeaders: ['Content-Type', 'Authorization'], 
    credentials: true // if using cookies
  };

// Middleware
app.use(cors(corsOptions));
app.use(bodyParser.json());
app.use('/uploads', express.static(uploadsDir));

if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir);
}
if (!fs.existsSync(pageBannerDir)) {
  fs.mkdirSync(pageBannerDir);
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
      cb(null, uploadsDir); // Save to uploads directory
  },
  filename: (req, file, cb) => {
      cb(null, Date.now() + path.extname(file.originalname)); // Unique filename
  }
});

const upload = multer({ storage });

app.post('/upload', upload.single('image'), (req, res) => {
  res.json({ message: 'Image uploaded successfully!', filename: req.file.filename });
});

// MySQL connection pool based on environment
const db = mysql.createPool({
  host: 'localhost',
  user: isProduction ? process.env.PROD_DB_USER : process.env.DB_USER,
  password: isProduction ? process.env.PROD_DB_PASSWORD : process.env.DB_PASSWORD,
  database: isProduction ? process.env.PROD_DB_NAME : process.env.DB_NAME,
});

db.getConnection()
  .then(connection => {
      console.log('Connected to MySQL Database');
      connection.release(); // Release connection back to pool
  })
  .catch(err => {
      console.error('Database connection failed:', err);
  });

// Middleware to verify token
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.sendStatus(401); // Unauthorized

  jwt.verify(token, 'your_jwt_secret', (err, user) => {
      if (err) return res.sendStatus(403); // Forbidden
      req.user = user; // Save user info to request object
      next();
  });
};

// Login route
app.post('/api/login', async (req, res) => {
  const { email_user, password } = req.body;

  try {
      const [results] = await db.query('SELECT * FROM users WHERE email_user = ?', [email_user]);
      if (results.length === 0) return res.status(401).send('Invalid email or password');

      const user = results[0];
      const match = await bcrypt.compare(password, user.password);
      if (!match) return res.status(401).send('Invalid email or password');

      const token = jwt.sign({ id_user: user.id_user }, 'your_jwt_secret', { expiresIn: '1h' });
      res.json({ token });
  } catch (err) {
      return res.status(500).send('Server error');
  }
});


// Fetch roles route
app.get('/api/roles', async (req, res) => {
  try {
      const [results] = await db.query('SELECT * FROM ms_role');
      res.status(200).json(results);
  } catch (err) {
      return res.status(500).json({ error: 'Database error' });
  }
});


// Registration route
app.post('/api/register', async (req, res) => {
  const { name_user, email_user, password, id_role } = req.body;

  if (!name_user || !email_user || !password || !id_role) {
      return res.status(400).json({ error: 'All fields are required' });
  }

  try {
      const [results] = await db.query('SELECT * FROM users WHERE email_user = ?', [email_user]);
      if (results.length > 0) {
          return res.status(400).json({ error: 'Email already exists' });
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const [insertResult] = await db.query('INSERT INTO users (name_user, email_user, password, created_at, updated_at) VALUES (?, ?, ?, NOW(), NOW())', 
      [name_user, email_user, hashedPassword]);

      const userId = insertResult.insertId;
      await db.query('INSERT INTO tbl_role_user (id_role, id_user) VALUES (?, ?)', [id_role, userId]);
      res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
      return res.status(500).json({ error: 'Database error' });
  }
});

// Update user route
app.put('/api/users/:id_user', async (req, res) => {
  const { id_user } = req.params;
  const { name_user, email_user, password } = req.body;

  if (!name_user || !email_user) {
      return res.status(400).json({ error: 'Name and email are required' });
  }

  try {
      const updates = [name_user, email_user];
      if (password) {
          const hashedPassword = await bcrypt.hash(password, 10);
          updates.push(hashedPassword);
          await db.query('UPDATE users SET name_user = ?, email_user = ?, password = ?, updated_at = NOW() WHERE id_user = ?',
              [...updates, id_user]);
      } else {
          await db.query('UPDATE users SET name_user = ?, email_user = ?, updated_at = NOW() WHERE id_user = ?',
              [...updates, id_user]);
      }
      res.json({ message: 'User updated successfully' });
  } catch (err) {
      return res.status(500).json({ error: 'Database error' });
  }
});

// Fetch users
app.get('/api/users', async (req, res) => {
  const query = `
      SELECT 
          u.id_user, 
          u.name_user, 
          u.email_user, 
          u.created_at, 
          u.updated_at, 
          r.nama_role 
      FROM users u
      LEFT JOIN tbl_role_user ru ON u.id_user = ru.id_user
      LEFT JOIN ms_role r ON ru.id_role = r.id_role
  `;
  
  try {
      const [results] = await db.query(query);
      res.json(results);
  } catch (err) {
      return res.status(500).json({ error: 'Database query failed' });
  }
});

// Fetch a single user
app.get('/api/users/:id_user', async (req, res) => {
  const { id_user } = req.params;
  const query = `
      SELECT 
          u.id_user, 
          u.name_user, 
          u.email_user, 
          u.created_at, 
          u.updated_at, 
          r.nama_role 
      FROM users u
      LEFT JOIN tbl_role_user ru ON u.id_user = ru.id_user
      LEFT JOIN ms_role r ON ru.id_role = r.id_role
      WHERE u.id_user = ?`;

  try {
    const [results] = await db.query(query, [id_user]);
    if (results.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(results[0]);
  } catch (err) {
    res.status(500).json({ error: 'Database query failed' });
  }
});

// Get current user details
app.get('/api/current-user', authenticateToken, async (req, res) => {
  const userId = req.user.id_user;
  const query = `
    SELECT users.id_user, users.name_user, users.email_user, ms_role.nama_role
    FROM users
    JOIN tbl_role_user ON users.id_user = tbl_role_user.id_user
    JOIN ms_role ON tbl_role_user.id_role = ms_role.id_role
    WHERE users.id_user = ?`;

  try {
    const [results] = await db.query(query, [userId]);
    if (results.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(results[0]);
  } catch (err) {
    res.status(500).json({ error: 'Database query failed' });
  }
});

// DELETE user route
app.delete('/api/users/:id', async (req, res) => {
  const userId = req.params.id;

  let connection; // Declare the connection variable

  try {
      if (isNaN(userId)) {
          return res.status(400).json({ error: 'Invalid user ID' });
      }

      // Get a connection from the pool
      connection = await db.getConnection();
      await connection.beginTransaction();

      // Check if user exists
      const [userCheck] = await connection.query('SELECT id_user FROM users WHERE id_user = ?', [userId]);
      if (userCheck.length === 0) {
          return res.status(404).json({ error: 'User not found' });
      }

      // Delete related records and the user
      await connection.query('DELETE FROM tbl_role_user WHERE id_user = ?', [userId]);
      await connection.query('DELETE FROM users WHERE id_user = ?', [userId]);

      await connection.commit(); // Commit transaction
      res.status(200).json({ message: 'User deleted successfully' });
  } catch (error) {
      if (connection) await connection.rollback(); // Rollback transaction on error
      console.error('Database error:', error);
      res.status(500).json({ error: 'Database error', details: error.message });
  } finally {
      if (connection) connection.release(); // Release the connection
  }
});

// Fetch program catering (only where status_delete is 0)
app.get('/api/program-catering', async (req, res) => {
  try {
    const [results] = await db.query('SELECT id, title, calories, image, description FROM program_catering WHERE status_delete = 0');
    res.json(results);
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).json({ error: 'Database query failed' });
  }
});

// Create program catering (set status_delete to 0 by default)
app.post('/api/program-catering', upload.single('image'), async (req, res) => {
  const { title, calories, description } = req.body;
  const imagePath = req.file ? req.file.path : null;
  const imageUrl = `http://api.dermalicious.id/uploads/${path.basename(imagePath)}`;

  try {
    const [result] = await db.query('INSERT INTO program_catering (title, calories, image, description, status_delete) VALUES (?, ?, ?, ?, 0)', 
    [title, calories, imageUrl, description]);
    res.status(201).json({ id: result.insertId, title, calories, image: imageUrl, description });
  } catch (err) {
    res.status(500).json({ error: 'Database error', details: err });
  }
});

// Update program catering
app.put('/api/program-catering/:id', upload.single('image'), async (req, res) => {
  const { id } = req.params;
  const { title, calories, description } = req.body;
  const updates = [];
  const params = [];

  if (title) {
    updates.push('title = ?');
    params.push(title);
  }
  if (calories) {
    updates.push('calories = ?');
    params.push(calories);
  }
  if (description) {
    updates.push('description = ?');
    params.push(description);
  }

  if (req.file) {
    const imageUrl = `http://api.dermalicious.id/uploads/${path.basename(req.file.path)}`;
    updates.push('image = ?');
    params.push(imageUrl);
  }

  if (updates.length === 0) {
    return res.status(400).json({ error: 'No fields to update' });
  }

  const updateString = updates.join(', ');
  params.push(id);

  try {
    const [result] = await db.query(`UPDATE program_catering SET ${updateString}, updated_at = NOW() WHERE id = ?`, params);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Program not found' });
    }
    res.json({ message: 'Program updated successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Database error', details: err });
  }
});

// Delete program catering (set status_delete to 1)
app.delete('/api/program-catering/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const [result] = await db.query('UPDATE program_catering SET status_delete = 1 WHERE id = ?', [id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Program not found' });
    }
    res.json({ message: 'Program deleted (soft delete) successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Database error', details: err });
  }
});

// Fetch all testimonials (only where status_delete is 0)
app.get('/api/testimonials', async (req, res) => {
  try {
    const [results] = await db.query('SELECT * FROM testimonials WHERE status_delete = 0');
    res.json(results);
  } catch (err) {
    return res.status(500).json({ error: 'Database query failed' });
  }
});

// Create a new testimonial (set status_delete to 0 by default)
app.post('/api/testimonials', upload.single('image'), async (req, res) => {
  const { name, role, rating, text } = req.body;
  const imagePath = req.file ? req.file.path : null;
  const imageUrl = imagePath ? `https://api.dermalicious.id/uploads/${path.basename(imagePath)}` : null;

  try {
    const [result] = await db.query('INSERT INTO testimonials (name, role, image, rating, text, status_delete) VALUES (?, ?, ?, ?, ?, 0)', 
    [name, role, imageUrl, rating, text]);
    res.status(201).json({ id: result.insertId, name, role, image: imageUrl, rating, text });
  } catch (err) {
    res.status(500).json({ error: 'Database error', details: err });
  }
});

// Update a testimonial (only if status_delete is 0)
app.put('/api/testimonials/:id', upload.single('image'), async (req, res) => {
  const { id } = req.params;
  const { name, role, rating, text } = req.body;
  const updates = [];
  const params = [];

  if (name) {
    updates.push('name = ?');
    params.push(name);
  }
  if (role) {
    updates.push('role = ?');
    params.push(role);
  }
  if (rating) {
    updates.push('rating = ?');
    params.push(rating);
  }
  if (text) {
    updates.push('text = ?');
    params.push(text);
  }

  if (req.file) {
    const imageUrl = `https://api.dermalicious.id/uploads/${path.basename(req.file.path)}`;
    updates.push('image = ?');
    params.push(imageUrl);
  }

  if (updates.length === 0) {
    return res.status(400).json({ error: 'No fields to update' });
  }

  const updateString = updates.join(', ');
  params.push(id);

  try {
    const [result] = await db.query(`UPDATE testimonials SET ${updateString}, updated_at = NOW() WHERE id = ?`, params);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Testimonial not found' });
    }
    res.json({ message: 'Testimonial updated successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Database error', details: err });
  }
});

// Soft delete a testimonial (set status_delete to 1)
app.delete('/api/testimonials/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const result = await db.query('UPDATE testimonials SET status_delete = 1 WHERE id = ?', [id]);
    if (result[0].affectedRows === 0) {
      return res.status(404).json({ error: 'Testimonial not found' });
    }
    res.json({ message: 'Testimonial deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Database error', details: err });
  }
});

// Fetch all partnerships (only where status_delete is 0)
app.get('/api/partnerships', async (req, res) => {
  try {
    const [results] = await db.query('SELECT * FROM partnerships WHERE status_delete = 0');
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: 'Database query failed' });
  }
});

// Create a new partnership (set status_delete to 0 by default)
app.post('/api/partnerships', upload.single('image'), async (req, res) => {
  const { title } = req.body;
  const imagePath = req.file ? req.file.path : null;
  const imageUrl = imagePath ? `https://api.dermalicious.id/uploads/${path.basename(imagePath)}` : null;

  try {
    const [result] = await db.query('INSERT INTO partnerships (title, image, created_at, updated_at, status_delete) VALUES (?, ?, NOW(), NOW(), 0)', 
    [title, imageUrl]);
    res.status(201).json({ id: result.insertId, title, image: imageUrl });
  } catch (err) {
    res.status(500).json({ error: 'Database error', details: err });
  }
});

// Update a partnership (only if status_delete is 0)
app.put('/api/partnerships/:id', upload.single('image'), async (req, res) => {
  const { id } = req.params;
  const { title } = req.body;
  const updates = [];
  const params = [];

  if (title) updates.push(`title = ?`, params.push(title));
  
  if (req.file) {
    const imageUrl = `https://api.dermalicious.id/uploads/${path.basename(req.file.path)}`;
    updates.push(`image = ?`, params.push(imageUrl));
  }

  if (updates.length === 0) {
    return res.status(400).json({ error: 'No fields to update' });
  }

  const updateString = updates.join(', ');

  try {
    const [result] = await db.query(`UPDATE partnerships SET ${updateString}, updated_at = NOW() WHERE id = ? AND status_delete = 0`, [...params, id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Partnership not found or has been deleted' });
    }
    res.json({ message: 'Partnership updated successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Database error', details: err });
  }
});

// Soft delete a partnership (set status_delete to 1)
app.delete('/api/partnerships/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const [result] = await db.query('UPDATE partnerships SET status_delete = 1 WHERE id = ?', [id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Partnership not found' });
    }
    res.json({ message: 'Partnership deleted (soft delete) successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Database error', details: err });
  }
});


// Create links
app.post('/api/links', async (req, res) => {
  const { facebook, instagram, youtube, tiktok, whatsapp, email } = req.body;
  const query = 'INSERT INTO links (facebook, instagram, youtube, tiktok, whatsapp, email) VALUES (?, ?, ?, ?, ?, ?)';
  
  try {
    const [results] = await db.query(query, [facebook, instagram, youtube, tiktok, whatsapp, email]);
    res.status(201).json({ id: results.insertId, facebook, instagram, youtube, tiktok, whatsapp, email });
  } catch (err) {
    res.status(500).json({ error: 'Database error', details: err });
  }
});

// Read links
app.get('/api/links', async (req, res) => {
  try {
    const [results] = await db.query('SELECT * FROM links');
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: 'Database query failed' });
  }
});

// Update links
app.put('/api/links/:id', async (req, res) => {
  const { id } = req.params;
  const { facebook, instagram, youtube, tiktok, whatsapp, email } = req.body;
  const query = 'UPDATE links SET facebook = ?, instagram = ?, youtube = ?, tiktok = ?, whatsapp = ?, email = ? WHERE id = ?';
  
  try {
    const [results] = await db.query(query, [facebook, instagram, youtube, tiktok, whatsapp, email, id]);
    res.json({ id, facebook, instagram, youtube, tiktok, whatsapp, email });
  } catch (err) {
    res.status(500).json({ error: 'Database error', details: err });
  }
});

// Delete links
app.delete('/api/links/:id', async (req, res) => {
  const { id } = req.params;
  
  try {
    await db.query('DELETE FROM links WHERE id = ?', [id]);
    res.status(204).send();
  } catch (err) {
    res.status(500).json({ error: 'Database error', details: err });
  }
});

// Fetch All Eazy Meals (only where status_delete is 0)
app.get('/api/eazy_meals', async (req, res) => {
  try {
    const [results] = await db.query('SELECT * FROM eazy_meals WHERE status_delete = 0');
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: 'Database query failed' });
  }
});

// Fetch Single Eazy Meal (only if status_delete is 0)
app.get('/api/eazy_meals/:id', async (req, res) => {
  const { id } = req.params;
  
  try {
    const [results] = await db.query('SELECT * FROM eazy_meals WHERE id = ? AND status_delete = 0', [id]);
    if (results.length === 0) return res.status(404).json({ error: 'Meal not found or has been deleted' });
    res.json(results[0]);
  } catch (err) {
    res.status(500).json({ error: 'Database query failed' });
  }
});

// Updated POST route to handle image uploads (set status_delete to 0 by default)
app.post('/api/eazy_meals', upload.single('image'), async (req, res) => {
  const { name, url } = req.body;
  const imagePath = req.file ? req.file.path : null;
  const imageUrl = imagePath ? `https://api.dermalicious.id/uploads/${path.basename(imagePath)}` : null;

  try {
    const [result] = await db.query('INSERT INTO eazy_meals (name, image, url, created_at, updated_at, status_delete) VALUES (?, ?, ?, NOW(), NOW(), 0)', 
    [name, imageUrl, url]);
    res.status(201).json({ id: result.insertId, name, image: imageUrl, url });
  } catch (err) {
    res.status(500).json({ error: 'Database error', details: err });
  }
});

// Updated PUT route to handle image updates
app.put('/api/eazy_meals/:id', upload.single('image'), async (req, res) => {
  const { id } = req.params;
  const { name, url } = req.body;
  const updates = [];
  const params = [];

  if (name) updates.push(`name = ?`, params.push(name));
  if (url) updates.push(`url = ?`, params.push(url));
  if (req.file) {
    const imageUrl = `https://api.dermalicious.id/uploads/${path.basename(req.file.path)}`;
    updates.push(`image = ?`, params.push(imageUrl));
  }

  if (updates.length === 0) {
    return res.status(400).json({ error: 'No fields to update' });
  }

  const updateString = updates.join(', ');

  try {
    const [result] = await db.query(`UPDATE eazy_meals SET ${updateString}, updated_at = NOW() WHERE id = ? AND status_delete = 0`, [...params, id]);
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Meal not found or has been deleted' });
    res.json({ message: 'Meal updated successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Database error', details: err });
  }
});

// Soft delete Eazy Meal (set status_delete to 1)
app.delete('/api/eazy_meals/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const [result] = await db.query('UPDATE eazy_meals SET status_delete = 1 WHERE id = ?', [id]);
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Meal not found' });
    res.json({ message: 'Meal deleted (soft delete) successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Database error', details: err });
  }
});

// Fetch All Page Banner
app.get('/api/page_banner', async (req, res) => {
  try {
    const [results] = await db.query('SELECT * FROM page_banner');
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: 'Database query failed' });
  }
});

// Fetch Single Page Banner
app.get('/api/page_banner/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const [results] = await db.query('SELECT * FROM page_banner WHERE id = ?', [id]);
    if (results.length === 0) return res.status(404).json({ error: 'Page Banner not found' });
    res.json(results[0]);
  } catch (err) {
    res.status(500).json({ error: 'Database query failed' });
  }
});

// Insert New Page Banner
app.post('/api/page_banner', upload.single('image'), async (req, res) => {
  const { name } = req.body;
  const imagePath = req.file ? req.file.path : null;
  const imageUrl = imagePath ? `https://api.dermalicious.id/uploads/pagebanner/${path.basename(imagePath)}` : null;

  try {
    const [result] = await db.query('INSERT INTO page_banner (name, image, created_at, updated_at) VALUES (?, ?, NOW(), NOW())', 
    [name, imageUrl]);
    res.status(201).json({ id: result.insertId, name, image: imageUrl });
  } catch (err) {
    res.status(500).json({ error: 'Database error', details: err });
  }
});

// Update Page Banner
app.put('/api/page_banner/:id', upload.single('image'), async (req, res) => {
  const { id } = req.params;
  const { name } = req.body;

  try {
    let imageUrl = null;
    if (req.file) {
      imageUrl = `https://api.dermalicious.id/uploads/pagebanner/${req.file.filename}`;
      
      // Fetch the old image path from the database
      const [oldResults] = await db.query('SELECT image FROM page_banner WHERE id = ?', [id]);
      const oldImage = oldResults[0]?.image;

      // Update the page banner
      await db.query('UPDATE page_banner SET name = ?, image = ?, updated_at = NOW() WHERE id = ?', [name, imageUrl, id]);

      // Delete the old image file if it exists
      if (oldImage) {
        const oldImagePath = path.join(__dirname, 'uploads', 'pagebanner', path.basename(oldImage));
        fs.unlink(oldImagePath, (err) => {
          if (err) console.error('Failed to delete old image:', err);
        });
      }

      return res.json({ message: 'Banner updated successfully', image: imageUrl });
    } else {
      // Update without changing the image
      await db.query('UPDATE page_banner SET name = ?, updated_at = NOW() WHERE id = ?', [name, id]);
      return res.json({ message: 'Banner updated successfully' });
    }
  } catch (err) {
    res.status(500).json({ error: 'Database error', details: err });
  }
});

// Delete banner
app.delete('/api/pagebanner/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const [results] = await db.query('SELECT image FROM page_banner WHERE id = ?', [id]);
    const image = results[0]?.image;

    // Delete the page banner record from the database
    await db.query('DELETE FROM page_banner WHERE id = ?', [id]);

    // Delete the image file if it exists
    if (image) {
      const imagePath = path.join(__dirname, 'uploads', 'pagebanner', path.basename(image));
      fs.unlink(imagePath, (err) => {
        if (err) console.error('Failed to delete image:', err);
      });
    }

    res.json({ message: 'Banner deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Database error', details: err });
  }
});

// Serve static files from the React app
// app.use(express.static(path.join(__dirname, '../dermalicousweb_dev/build')));
app.use(express.static(path.join(__dirname, '../home/web/programmer/upload/dermalicious_web/frontend/build')));

// Catch-all route to serve the React app
app.get('*', (req, res) => {
    // res.sendFile(path.join(__dirname, '../dermalicousweb_dev/build', 'index.html'));
    res.sendFile(path.join(__dirname, '../home/web/programmer/upload/dermalicious_web/frontend/build', 'index.html'));
});

// Handle preflight requests
app.options('*', cors(corsOptions));

// Create an HTTPS server with your credentials
const httpsServer = https.createServer(credentials, app);

// Start the HTTPS server
// httpsServer.listen(port, () => {
//   console.log(`Server is running on https:api.dermalicious.id`);
// });
httpsServer.listen(port, () => {
    console.log(`HTTPS Server is running on https://api.dermalicious.id:${port}`);
  });
// // Start the server
// app.listen(port, () => {
//     console.log(`Server is running on http://103.177.56.115:${port}`);
// });