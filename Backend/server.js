const express = require('express');
const app = express();
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
require('dotenv').config();


app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(__dirname + '/../Frontend'));


// app.use('/uploads', express.static('uploads'));
app.set('view engine', 'ejs');

// Connect to MongoDB
// mongoose.connect(process.env.DB_URL)
//   .then(() => console.log('Connected to MongoDB'))
//   .catch(err => console.error('MongoDB connection error:', err));

// Models
const Admin = mongoose.model('Admin', new mongoose.Schema({
  username: String,
  password: String
}));

// const Category = mongoose.model('Category', new mongoose.Schema({
//   name: String
// }));

// const Case = mongoose.model('Case', new mongoose.Schema({
//   date: String,
//   category: String,
//   content: String,
//   image: String
// }));

// File upload config
// const storage = multer.diskStorage({
//   destination: 'uploads/',
//   filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
// });
// const upload = multer({ storage });

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../Frontend/views/admin/register.html'));
});
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, '../Frontend/views/admin/login.html'));
});
app.get('/case-viewer', (req, res) => {
  res.sendFile(path.join(__dirname, '../Frontend/views/admin/case-viewer.html'));
});


// app.get('/select-category', (req, res) => res.sendFile(__dirname + '/views/select-category.html'));
// app.get('/add-case', async (req, res) => {
//   const categories = await Category.find();
//   res.send(`
//     <html><head><link rel="stylesheet" href="/css/style.css"></head><body>
//     <header><h1>Add Case</h1></header>
//     <div class="container">
//     <form action="/add-case" method="POST" enctype="multipart/form-data">
//     <input type="datetime-local" name="date" required>
//     <select name="category" required>
//       ${categories.map(c => `<option value="${c.name}">${c.name}</option>`).join('')}
//     </select>
//     <textarea name="content" rows="5" placeholder="Case details..." required></textarea>
//     <input type="file" name="image" accept="image/*">
//     <button type="submit">Post Case</button>
//     </form></div></body></html>
//   `);
// });

app.post('/admin-register', async (req, res) => {
  const { username, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  await new Admin({ username, password: hash }).save();
  console.log("Admin details saved")
  return res.status(200).json({ message: "Admin Details saved"})
});

app.post('/admin-login', async (req, res) => {
  const { username, password } = req.body;
  const admin = await Admin.findOne({ username });
  console.log(admin)
  if (!admin || !(await bcrypt.compare(password, admin.password))) {
    return res.status(400).json({message: "Invalid Credentials"})
  }
  res.status(200).json({message: "Login Successful"})
});

// app.post('/category', async (req, res) => {
//   const { category } = req.body;
//   await new Category({ name: category }).save();
//   res.redirect('/select-category');
// });

//  

app.listen(3000, () => console.log('🚀 Server running on http://localhost:3000'));
