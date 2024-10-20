const express = require('express');
const path = require('path');
const cors = require('cors');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');

const uploadsDir = path.join(__dirname, 'uploads');
const pageBannerDir = path.join(uploadsDir, 'pagebanner');

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

const app = express();
const port = 5000;
// Middleware
app.use(cors());
app.use(bodyParser.json());

app.use('/uploads', express.static(uploadsDir));

app.post('/upload', upload.single('image'), (req, res) => {
  res.json({ message: 'Image uploaded successfully!', filename: req.file.filename });
});


// Database MySQL connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'dermalicious_web_staging',
});

db.connect((err) => {
    if (err) throw err;
    console.log('Connected to MySQL Database');
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
  const { email, password } = req.body; // Change 'username' to 'email'

  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => { // Change 'username' to 'email'
      if (err) return res.status(500).send('Server error');

      if (results.length === 0) return res.status(401).send('Invalid email or password');

      const user = results[0];
      const match = await bcrypt.compare(password, user.password);

      if (!match) return res.status(401).send('Invalid email or password');

      // Create a token
      const token = jwt.sign({ id: user.id }, 'your_jwt_secret', { expiresIn: '1h' });

      res.json({ token });
  });
});

// Registration route
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body; // Change 'username' to 'email'

  // Validate input
  if (!name || !email || !password) { // Change 'username' to 'email'
      return res.status(400).json({ error: 'All fields are required' });
  }

  // Check if email already exists
  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => { // Change 'username' to 'email'
      if (err) {
          return res.status(500).json({ error: 'Database error' });
      }
      if (results.length > 0) {
          return res.status(400).json({ error: 'Email already exists' });
      }

      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Insert new user into the database
      db.query('INSERT INTO users (name, email, password, created_at, updated_at) VALUES (?, ?, ?, NOW(), NOW())', 
      [name, email, hashedPassword], (err) => {
          if (err) {
              return res.status(500).json({ error: 'Database error' });
          }
          res.status(201).json({ message: 'User registered successfully' });
      });
  });
});

// Update user route
app.put('/api/users/:id', async (req, res) => {
  const { id } = req.params;
  const { name, email, password } = req.body;

  // Validate input
  if (!name || !email) { // Change 'username' to 'email'
      return res.status(400).json({ error: 'Name and email are required' });
  }

  const updates = [name, email]; // Change 'username' to 'email'

  if (password) {
      // Hash the password if it's being updated
      const hashedPassword = await bcrypt.hash(password, 10);
      updates.push(hashedPassword);
      db.query('UPDATE users SET name = ?, email = ?, password = ?, updated_at = NOW() WHERE id = ?',
          [...updates, id], (err) => {
              if (err) {
                  return res.status(500).json({ error: 'Database error' });
              }
              res.json({ message: 'User updated successfully' });
          });
  } else {
      // If password is not updated, skip it in the update query
      db.query('UPDATE users SET name = ?, email = ?, updated_at = NOW() WHERE id = ?',
          [...updates, id], (err) => {
              if (err) {
                  return res.status(500).json({ error: 'Database error' });
              }
              res.json({ message: 'User updated successfully' });
          });
  }
});

// Fetch users
app.get('/api/users', (req, res) => {
    db.query('SELECT id, name, email, created_at, updated_at FROM users', (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Database query failed' });
        }
        res.json(results);
    });
});

// Fetch a single user
app.get('/api/users/:id', (req, res) => {
  const { id } = req.params;
  db.query('SELECT id, name, email FROM users WHERE id = ?', [id], (err, results) => {
      if (err) {
          return res.status(500).json({ error: 'Database query failed' });
      }
      if (results.length === 0) {
          return res.status(404).json({ error: 'User not found' });
      }
      res.json(results[0]); // Send back the user data
  });
});

// Get current user details
app.get('/api/current-user', authenticateToken, (req, res) => {
  const userId = req.user.id;

  db.query('SELECT id, name, email FROM users WHERE id = ?', [userId], (err, results) => {
      if (err) {
          return res.status(500).json({ error: 'Database query failed' });
      }
      if (results.length === 0) {
          return res.status(404).json({ error: 'User not found' });
      }
      res.json(results[0]);
  });
});

// Delete user route
app.delete('/api/users/:id', (req, res) => {
  const { id } = req.params;

  db.query('DELETE FROM users WHERE id = ?', [id], (err, results) => {
      if (err) {
          return res.status(500).json({ error: 'Database error' });
      }
      if (results.affectedRows === 0) {
          return res.status(404).json({ error: 'User not found' });
      }
      res.json({ message: 'User deleted successfully' });
  });
});

// Fetch program catering (only where status_delete is 0)
app.get('/api/program-catering', (req, res) => {
  db.query('SELECT id, title, calories, image, description FROM program_catering WHERE status_delete = 0', (err, results) => {
      if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ error: 'Database query failed' });
      }
      res.json(results);
  });
});

// Create program catering (set status_delete to 0 by default)
app.post('/api/program-catering', upload.single('image'), (req, res) => {
  const { title, calories, description } = req.body;
  const imagePath = req.file ? req.file.path : null;
  const imageUrl = `http://localhost:5000/uploads/${path.basename(imagePath)}`;

  db.query('INSERT INTO program_catering (title, calories, image, description, status_delete) VALUES (?, ?, ?, ?, 0)', 
  [title, calories, imageUrl, description], (err, result) => {
      if (err) {
          return res.status(500).json({ error: 'Database error', details: err });
      }
      res.status(201).json({ id: result.insertId, title, calories, image: imageUrl, description });
  });
});

// Update program catering
app.put('/api/program-catering/:id', upload.single('image'), (req, res) => {
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
      const imageUrl = `http://localhost:5000/uploads/${path.basename(req.file.path)}`;
      updates.push('image = ?');
      params.push(imageUrl);
  }

  if (updates.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
  }

  const updateString = updates.join(', ');
  params.push(id); // Add id to params for the query

  db.query(`UPDATE program_catering SET ${updateString}, updated_at = NOW() WHERE id = ?`, params, (err, result) => {
      if (err) {
          return res.status(500).json({ error: 'Database error', details: err });
      }
      if (result.affectedRows === 0) {
          return res.status(404).json({ error: 'Program not found' });
      }
      res.json({ message: 'Program updated successfully' });
  });
});

// Delete program catering (set status_delete to 1)
app.delete('/api/program-catering/:id', (req, res) => {
  const { id } = req.params;

  db.query('UPDATE program_catering SET status_delete = 1 WHERE id = ?', [id], (err, result) => {
      if (err) {
          return res.status(500).json({ error: 'Database error', details: err });
      }
      if (result.affectedRows === 0) {
          return res.status(404).json({ error: 'Program not found' });
      }
      res.json({ message: 'Program deleted (soft delete) successfully' });
  });
});


// Fetch all testimonials (only where status_delete is 0)
app.get('/api/testimonials', (req, res) => {
  db.query('SELECT * FROM testimonials WHERE status_delete = 0', (err, results) => {
      if (err) {
          return res.status(500).json({ error: 'Database query failed' });
      }
      res.json(results);
  });
});

// Create a new testimonial (set status_delete to 0 by default)
app.post('/api/testimonials', upload.single('image'), (req, res) => {
  const { name, role, rating, text } = req.body;
  const imagePath = req.file ? req.file.path : null;
  const imageUrl = imagePath ? `http://localhost:5000/uploads/${path.basename(imagePath)}` : null;

  db.query('INSERT INTO testimonials (name, role, image, rating, text, created_at, updated_at, status_delete) VALUES (?, ?, ?, ?, ?, NOW(), NOW(), 0)', 
  [name, role, imageUrl, rating, text], (err, result) => {
      if (err) {
          return res.status(500).json({ error: 'Database error', details: err });
      }
      res.status(201).json({ id: result.insertId, name, role, image: imageUrl, rating, text });
  });
});

// Update a testimonial (only if status_delete is 0)
app.put('/api/testimonials/:id', upload.single('image'), (req, res) => {
  const { id } = req.params;
  const { name, role, rating, text } = req.body;
  const updates = [];

  if (name) updates.push(`name = '${name}'`);
  if (role) updates.push(`role = '${role}'`);
  if (rating) updates.push(`rating = '${rating}'`);
  if (text) updates.push(`text = '${text}'`);
  
  let imageUrl = null;
  if (req.file) {
      imageUrl = `http://localhost:5000/uploads/${path.basename(req.file.path)}`;
      updates.push(`image = '${imageUrl}'`);
  }

  if (updates.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
  }

  const updateString = updates.join(', ');
  db.query(`UPDATE testimonials SET ${updateString}, updated_at = NOW() WHERE id = ? AND status_delete = 0`, [id], (err, result) => {
      if (err) {
          return res.status(500).json({ error: 'Database error', details: err });
      }
      if (result.affectedRows === 0) {
          return res.status(404).json({ error: 'Testimonial not found or has been deleted' });
      }
      res.json({ message: 'Testimonial updated successfully' });
  });
});

// Soft delete a testimonial (set status_delete to 1)
app.delete('/api/testimonials/:id', (req, res) => {
  const { id } = req.params;

  db.query('UPDATE testimonials SET status_delete = 1 WHERE id = ?', [id], (err, result) => {
      if (err) {
          return res.status(500).json({ error: 'Database error', details: err });
      }
      if (result.affectedRows === 0) {
          return res.status(404).json({ error: 'Testimonial not found' });
      }
      res.json({ message: 'Testimonial deleted (soft delete) successfully' });
  });
});


// Fetch all partnerships (only where status_delete is 0)
app.get('/api/partnerships', (req, res) => {
  db.query('SELECT * FROM partnerships WHERE status_delete = 0', (err, results) => {
      if (err) {
          return res.status(500).json({ error: 'Database query failed' });
      }
      res.json(results);
  });
});

// Create a new partnership (set status_delete to 0 by default)
app.post('/api/partnerships', upload.single('image'), (req, res) => {
  const { title } = req.body;
  const imagePath = req.file ? req.file.path : null;
  const imageUrl = imagePath ? `http://localhost:5000/uploads/${path.basename(imagePath)}` : null;

  db.query('INSERT INTO partnerships (title, image, created_at, updated_at, status_delete) VALUES (?, ?, NOW(), NOW(), 0)', 
  [title, imageUrl], (err, result) => {
      if (err) {
          return res.status(500).json({ error: 'Database error', details: err });
      }
      res.status(201).json({ id: result.insertId, title, image: imageUrl });
  });
});

// Update a partnership (only if status_delete is 0)
app.put('/api/partnerships/:id', upload.single('image'), (req, res) => {
  const { id } = req.params;
  const { title } = req.body;
  const updates = [];

  if (title) updates.push(`title = '${title}'`);
  
  let imageUrl = null;
  if (req.file) {
      imageUrl = `http://localhost:5000/uploads/${path.basename(req.file.path)}`;
      updates.push(`image = '${imageUrl}'`);
  }

  if (updates.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
  }

  const updateString = updates.join(', ');
  db.query(`UPDATE partnerships SET ${updateString}, updated_at = NOW() WHERE id = ? AND status_delete = 0`, [id], (err, result) => {
      if (err) {
          return res.status(500).json({ error: 'Database error', details: err });
      }
      if (result.affectedRows === 0) {
          return res.status(404).json({ error: 'Partnership not found or has been deleted' });
      }
      res.json({ message: 'Partnership updated successfully' });
  });
});

// Soft delete a partnership (set status_delete to 1)
app.delete('/api/partnerships/:id', (req, res) => {
  const { id } = req.params;

  db.query('UPDATE partnerships SET status_delete = 1 WHERE id = ?', [id], (err, result) => {
      if (err) {
          return res.status(500).json({ error: 'Database error', details: err });
      }
      if (result.affectedRows === 0) {
          return res.status(404).json({ error: 'Partnership not found' });
      }
      res.json({ message: 'Partnership deleted (soft delete) successfully' });
  });
});


// Create links
app.post('/api/links', (req, res) => {
  const { facebook, instagram, youtube, tiktok, whatsapp, email } = req.body;
  const query = 'INSERT INTO links (facebook, instagram, youtube, tiktok, whatsapp, email) VALUES (?, ?, ?, ?, ?, ?)';
  db.query(query, [facebook, instagram, youtube, tiktok, whatsapp, email], (err, results) => {
      if (err) return res.status(500).json(err);
      res.status(201).json({ id: results.insertId, facebook, instagram, youtube, tiktok, whatsapp, email });
  });
});

// Read links
app.get('/api/links', (req, res) => {
  db.query('SELECT * FROM links', (err, results) => {
      if (err) return res.status(500).json(err);
      res.json(results);
  });
});

// Update links
app.put('/api/links/:id', (req, res) => {
  const { id } = req.params;
  const { facebook, instagram, youtube, tiktok, whatsapp, email } = req.body;
  const query = 'UPDATE links SET facebook = ?, instagram = ?, youtube = ?, tiktok = ?, whatsapp = ?, email = ? WHERE id = ?';
  db.query(query, [facebook, instagram, youtube, tiktok, whatsapp, email, id], (err, results) => {
      if (err) return res.status(500).json(err);
      res.json({ id, facebook, instagram, youtube, tiktok, whatsapp, email });
  });
});

// Delete links
app.delete('/api/links/:id', (req, res) => {
  const { id } = req.params;
  db.query('DELETE FROM links WHERE id = ?', [id], (err, results) => {
      if (err) return res.status(500).json(err);
      res.status(204).send();
  });
});

// Fetch All Eazy Meals (only where status_delete is 0)
app.get('/api/eazy_meals', (req, res) => {
  db.query('SELECT * FROM eazy_meals WHERE status_delete = 0', (err, results) => {
      if (err) return res.status(500).json({ error: 'Database query failed' });
      res.json(results);
  });
});

// Fetch Single Eazy Meal (only if status_delete is 0)
app.get('/api/eazy_meals/:id', (req, res) => {
  const { id } = req.params;
  db.query('SELECT * FROM eazy_meals WHERE id = ? AND status_delete = 0', [id], (err, results) => {
      if (err) return res.status(500).json({ error: 'Database query failed' });
      if (results.length === 0) return res.status(404).json({ error: 'Meal not found or has been deleted' });
      res.json(results[0]);
  });
});

// Updated POST route to handle image uploads (set status_delete to 0 by default)
app.post('/api/eazy_meals', upload.single('image'), (req, res) => {
  const { name, url } = req.body;
  const imagePath = req.file ? req.file.path : null;
  const imageUrl = imagePath ? `http://localhost:5000/uploads/${path.basename(imagePath)}` : null;

  db.query('INSERT INTO eazy_meals (name, image, url, created_at, updated_at, status_delete) VALUES (?, ?, ?, NOW(), NOW(), 0)', 
  [name, imageUrl, url], (err, result) => {
      if (err) return res.status(500).json({ error: 'Database error', details: err });
      res.status(201).json({ id: result.insertId, name, image: imageUrl, url });
  });
});

// Updated PUT route to handle image updates
app.put('/api/eazy_meals/:id', upload.single('image'), (req, res) => {
  const { id } = req.params;
  const { name, url } = req.body;
  let updates = [];
  const imageUrl = req.file ? `http://localhost:5000/uploads/${path.basename(req.file.path)}` : null;

  if (name) updates.push(`name = '${name}'`);
  if (url) updates.push(`url = '${url}'`);
  if (imageUrl) updates.push(`image = '${imageUrl}'`);

  if (updates.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
  }

  const updateString = updates.join(', ');
  db.query(`UPDATE eazy_meals SET ${updateString}, updated_at = NOW() WHERE id = ? AND status_delete = 0`, [id], (err, result) => {
      if (err) return res.status(500).json({ error: 'Database error', details: err });
      if (result.affectedRows === 0) return res.status(404).json({ error: 'Meal not found or has been deleted' });
      res.json({ message: 'Meal updated successfully' });
  });
});

// Soft delete Eazy Meal (set status_delete to 1)
app.delete('/api/eazy_meals/:id', (req, res) => {
  const { id } = req.params;
  db.query('UPDATE eazy_meals SET status_delete = 1 WHERE id = ?', [id], (err, result) => {
      if (err) return res.status(500).json({ error: 'Database error', details: err });
      if (result.affectedRows === 0) return res.status(404).json({ error: 'Meal not found' });
      res.json({ message: 'Meal deleted (soft delete) successfully' });
  });
});


// Fetch All Page Banner
app.get('/api/page_banner', (req, res) => {
  db.query('SELECT * FROM page_banner', (err, results) => {
      if (err) return res.status(500).json({ error: 'Database query failed' });
      res.json(results);
  });
});

// Fetch Single Page Banner
app.get('/api/page_banner/:id', (req, res) => {
  const { id } = req.params;
  db.query('SELECT * FROM page_banner WHERE id = ?', [id], (err, results) => {
      if (err) return res.status(500).json({ error: 'Database query failed' });
      if (results.length === 0) return res.status(404).json({ error: 'Page Banner not found' });
      res.json(results[0]);
  });
});

// Insert New Page Banner
app.post('/api/page_banner', upload.single('image'), (req, res) => {
  const { name } = req.body;
  const imagePath = req.file ? req.file.path : null;
  const imageUrl = imagePath ? `http://localhost:5000/uploads/pagebanner/${path.basename(imagePath)}` : null;

  db.query('INSERT INTO page_banner (name, image, created_at, updated_at) VALUES (?, ?, NOW(), NOW())', 
  [name, imageUrl], (err, result) => {
      if (err) return res.status(500).json({ error: 'Database error', details: err });
      res.status(201).json({ id: result.insertId, name, image: imageUrl });
  });
});

// Update Page Banner
app.put('/api/page_banner/:id', upload.single('image'), (req, res) => {
  const { id } = req.params;
  const { name } = req.body;
  
  // Check if an image was uploaded
  if (req.file) {
      const imagePath = `http://localhost:5000/uploads/pagebanner/${req.file.filename}`;
      
      // Fetch the old image path from the database
      db.query('SELECT image FROM page_banner WHERE id = ?', [id], (err, results) => {
          if (err) {
              return res.status(500).json({ error: 'Database error', details: err });
          }

          const oldImage = results[0]?.image;

          // Update the page banner
          db.query('UPDATE page_banner SET name = ?, image = ?, updated_at = NOW() WHERE id = ?', [name, imagePath, id], (err) => {
              if (err) {
                  return res.status(500).json({ error: 'Database error', details: err });
              }

              // Delete the old image file if it exists
              if (oldImage) {
                  const oldImagePath = path.join(__dirname, 'uploads', 'pagebanner', path.basename(oldImage));
                  fs.unlink(oldImagePath, (err) => {
                      if (err) {
                          console.error('Failed to delete old image:', err);
                      }
                  });
              }

              res.json({ message: 'Banner updated successfully', image: imagePath });
          });
      });
  } else {
      // Update without changing the image
      db.query('UPDATE page_banner SET name = ?, updated_at = NOW() WHERE id = ?', [name, id], (err) => {
          if (err) {
              return res.status(500).json({ error: 'Database error', details: err });
          }
          res.json({ message: 'Banner updated successfully' });
      });
  }
});


// Delete banner
app.delete('/api/pagebanner/:id', (req, res) => {
  const { id } = req.params;

  // Fetch the image path from the database
  db.query('SELECT image FROM page_banner WHERE id = ?', [id], (err, results) => {
      if (err) {
          return res.status(500).json({ error: 'Database error', details: err });
      }

      const image = results[0]?.image;

      // Delete the page banner record from the database
      db.query('DELETE FROM page_banner WHERE id = ?', [id], (err) => {
          if (err) {
              return res.status(500).json({ error: 'Database error', details: err });
          }

          // Delete the image file if it exists
          if (image) {
              const imagePath = path.join(__dirname, 'uploads', 'pagebanner', path.basename(image));
              fs.unlink(imagePath, (err) => {
                  if (err) {
                      console.error('Failed to delete image:', err);
                  }
              });
          }

          res.json({ message: 'Banner deleted successfully' });
      });
  });
});

// Serve static files from the React app
app.use(express.static(path.join(__dirname, '../dermalicousweb_dev/build')));

// Catch-all route to serve the React app
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../dermalicousweb_dev/build', 'index.html'));
});

// Start the server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
