const express = require('express');
const multer = require('multer');
const Case = require('../models/Case');
const path = require('path');
const router = express.Router();

// Set up storage
const storage = multer.diskStorage({
  destination: './uploads/',
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({ storage: storage });

// Route to add a case
router.post('/', upload.single('image'), async (req, res) => {
  const { date, time, category, content } = req.body;
  const imagePath = req.file ? req.file.filename : null;

  const newCase = new Case({
    date,
    time,
    category,
    content,
    imagePath
  });

  await newCase.save();
  res.json({ message: 'Case added successfully!' });
});

module.exports = router;
