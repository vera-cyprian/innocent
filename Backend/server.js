const express = require("express");
const app = express();
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const Joi = require("joi");
const path = require("path");
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const nodemailer = require('nodemailer');

const Admin = require('./models/Admin');

require("dotenv").config();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(__dirname + "/../Frontend"));

// Connect to MongoDB
mongoose
  .connect(process.env.DB_URL)
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("MongoDB connection error:", err));

// Authentication
const authenticateAdmin = async (req, res, next) => {
  const token = req.cookies.token
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.admin = await Admin.findById(decoded.adminId);
    next();
  } catch (error) {
    res.status(401).json({ message: "Please authenticate" });
  }
};

// Send verification email
const transporter = nodemailer.createTransport({
  service: "Gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
});

// Routes
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "../Frontend/views/admin/register.html"));
});
app.get("/admin-dashboard", authenticateAdmin, (req, res) => {
  // Only authenticated admins can access this route
  res.sendFile(path.join(__dirname, "../Frontend/views/admin/register.html"));
});
app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "../Frontend/views/admin/login.html"));
});
app.get('/get-admin-email', async (req, res) => {
  try {
    const verificationToken = req.cookies.verificationToken;
    const decodedToken = jwt.verify(verificationToken, process.env.JWT_SECRET);
    if (decodedToken.purpose !== 'resend-verification') {
      return res.status(401).json({ message: 'Invalid token' });
    }
    res.json({ email: decodedToken.email });
  } catch (error) {
    console.log(error);
    res.status(401).json({ message: 'Invalid token' });
  }
});
app.get("/resend-verification", (req, res) => {
  res.sendFile(path.join(__dirname, "../Frontend/views/admin/resend-verification.html"));
});
app.get('/verify-email/:token', (req, res) => {
  res.sendFile(path.join(__dirname, "../Frontend/views/admin/verify-email.html"));
});
app.get('/forgot-password', (req, res) => {
  res.sendFile(path.join(__dirname, "../Frontend/views/admin/forgot-password.html"));
});
app.get('/reset-password/:token', (req, res) => {
  res.sendFile(path.join(__dirname, "../Frontend/views/admin/reset-password.html"));
});
app.get("/case-viewer", authenticateAdmin, (req, res) => {
  res.sendFile(
    path.join(__dirname, "../Frontend/views/admin/case-viewer.html")
  );
});

// Rate limiting
const limiter = rateLimit({
  windowMs: 2 * 60 * 1000, // 2 minutes
  max: 8, // Limit each IP to 5 requests per windowMs
  handler: (request, response, next) => {
    response.status(429).json({
      message: 'Too many requests, please try again later.',
    });
  },
});

// Validation Schemas
const registerSchema = Joi.object({
  username: Joi.string().required().trim().min(3).messages({
    'string.empty': 'Username is required',
    'string.min': 'Username must contain at least 3 characters',
    'any.required': 'Username is required',
  }),
  email: Joi.string().email().required().trim().messages({
    'string.empty': 'Email is required',
    'string.email': 'Invalid email format',
    'any.required': 'Email is required',
  }),
  password: Joi.string().required().trim().min(4).max(8).messages({
    'string.empty': 'Password is required',
    'string.min': 'Password must contain at least 4 characters',
    'string.max': 'Password must not exceed 8 characters',
    'any.required': 'Password is required',
  }),
  terms: Joi.boolean().required().valid(true).messages({
    'boolean.base': 'You must agree to the terms and conditions',
    'any.required': 'You must agree to the terms and conditions',
    'any.valid': 'You must agree to the terms and conditions',
  }),
});

const loginSchema = Joi.object({
  email: Joi.string().email().required().trim().messages({
    'string.empty': 'Email is required',
    'string.email': 'Invalid email format',
    'any.required': 'Email is required',
  }),
  password: Joi.string().required().trim().messages({
    'string.empty': 'Password is required',
    'any.required': 'Password is required',
  }),
});

const forgotPasswordSchema = Joi.object({
  email: Joi.string().email().required().trim().messages({
    'string.empty': 'Email is required',
    'string.email': 'Invalid email format',
    'any.required': 'Email is required',
  }),
});

const resetPasswordSchema = Joi.object({
  password: Joi.string().required().trim().min(4).max(8).messages({
    'string.empty': 'Password is required',
    'string.min': 'Password must contain at least 4 characters',
    'string.max': 'Password must not exceed 8 characters',
    'any.required': 'Password is required',
  }),
});


// Not done - CAPTCHA
// Admin Register End point - Tested
app.post("/admin-register", limiter, async (req, res) => {
  // Validation check
  try {
    await registerSchema.validateAsync(req.body);
  } catch (error) {
    return res.status(400).json({
        // message: "Invalid request data",
        message: error.details[0].message,
      });
  }

  const { username, email, password, terms } = req.body;

  // Check terms and conditions
  if (!terms) {
    return res.status(400).json({
      message: "You must agree to the terms and conditions",
    });
  }

  // Username uniqueness check
  const existingUsername = await Admin.findOne({ username });
  if (existingUsername) {
    return res.status(400).json({
      message: "Username already taken",
    });
  }

  // Email uniqueness check
  const existingEmail = await Admin.findOne({ email });
  if (existingEmail) {
    return res.status(400).json({
      message: "Email already in use",
    });
  }

  // Password hashing
  const hash = await bcrypt.hash(password, 10);

  // Save admin info to database
  const admin = new Admin({
    username,
    email,
    password: hash,
    verified: false,
  });

  try {
    await admin.save();

    const verificationToken = jwt.sign(
      { adminId: admin._id },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: admin.email,
      subject: "Verify your email",
      text: `Verify your email by clicking this link: http://localhost:3000/verify-email/${verificationToken}`,
    };

    transporter.sendMail(mailOptions, async (error, info) => {
      if (error) {
        console.log(error);
        admin.verificationFailed = true;
        await admin.save();
        res.status(500).json({ message: "Error sending verification email. Please try again later." });
      } else {
        console.log("Email sent: " + info.response);
        res.status(200).json({ 
          message: "Registration successful, please verify your email", 
          redirect: `/resend-verification/${admin._id}` 
        });    
      }
    });  
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: "Error saving admin details" });
  }
});

// Admin Login End point
app.post("/admin-login", limiter, async (req, res) => {
  try {
    await loginSchema.validateAsync(req.body);
  } catch (error) {
    return res.status(400).json({
      message: error.details[0].message,
    });
  }

  const { email, password } = req.body;
  const admin = await Admin.findOne({ email });
  if (!admin) {
    return res.status(400).json({ message: "Invalid Credentials" });
  }

  const isValidPassword = await bcrypt.compare(password, admin.password);
  if (!isValidPassword) {
    return res.status(400).json({ message: "Invalid Credentials" });
  }

  if (!admin.verified) {
    const verificationToken = jwt.sign({ 
      adminId: admin._id, 
      email: admin.email, 
      purpose: 'resend-verification' }, 
      process.env.JWT_SECRET
    );
    res.cookie('verificationToken', verificationToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      expires: new Date(Date.now() + 3600000) // 1 hour
    });
    return res.status(400).json({ message: "Email not verified" });
  }
  
  const token = jwt.sign({ adminId: admin._id }, process.env.JWT_SECRET, {
    expiresIn: "1h",
  });

  res.cookie('token', token, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    expires: new Date(Date.now() + 3600000) // 1 hour
  });
  
  res.status(200).json({ message: "Login Successful" });
});

// Verify Email End point - Tested
app.get('/api/verify-email/:token', async (req, res) => {
  try {
    const token = req.params.token;
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const admin = await Admin.findById(decoded.adminId);
    if (!admin) {
      return res.status(404).json({ message: 'Admin not found' });
    }
    admin.verified = true;
    await admin.save();
    res.status(200).json({ message: 'Email verified successfully' });
  } catch (error) {
    console.log(error);
    res.status(400).json({ message: 'Invalid or expired token' });
  }
});

// Forgot Password Endpoint - Tested
app.post('/forgot-password', async (req, res) => {
  try {
    await forgotPasswordSchema.validateAsync(req.body);
  } catch (error) {
    return res.status(400).json({
      message: 'Invalid request data',
      error: error.details[0].message,
    });
  }
  
  try {
    const { email } = req.body;
    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(400).json({ message: 'Admin not found' });
    }

    const resetToken = jwt.sign({ adminId: admin._id }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    admin.resetToken = resetToken;
    admin.resetTokenExpiration = Date.now() + 3600000; // 1 hour
    await admin.save();

    const transporter = nodemailer.createTransport({
      service: "Gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD,
      },
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: admin.email,
      subject: 'Password Reset',
      text: `Reset your password by clicking this link: http://localhost:3000/reset-password/${resetToken}`,
    };
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.log(error);
        res.status(500).json({ message: 'Error sending email' });
      } else {
        res.status(200).json({ message: 'Password reset email sent' });
      }
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: 'Error processing request' });
  }
});

// Reset Password Endpoint - Tested
app.post('/reset-password/:token', async (req, res) => {
  try {
    await resetPasswordSchema.validateAsync(req.body);
  } catch (error) {
    return res.status(400).json({
      message: 'Invalid request data',
      error: error.details[0].message,
    });
  }
    
  try {
    const token = req.params.token;
    const { password } = req.body;

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const admin = await Admin.findById(decoded.adminId);
    if (!admin) {
      return res.status(400).json({ message: 'Invalid token' });
    }

    if (admin.resetTokenExpiration < Date.now()) {
      return res.status(400).json({ message: 'Token expired' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    admin.password = hashedPassword;
    admin.resetToken = undefined;
    admin.resetTokenExpiration = undefined;
    await admin.save();

    res.status(200).json({ message: 'Password reset successful' });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: 'Error resetting password' });
  }
});

// Resend Verification Endpoint - Tested
app.post('/resend-verification', async (req, res) => {
  try {
    const verificationToken = req.cookies.verificationToken;
    let decodedToken;
    try {
      decodedToken = jwt.verify(verificationToken, process.env.JWT_SECRET);
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return res.status(401).json({ message: 'Token has expired' });
      } else if (error.name === 'JsonWebTokenError') {
        return res.status(401).json({ message: 'Invalid token' });
      } else {
        throw error;
      }
    }

    if (decodedToken.purpose !== 'resend-verification') {
      return res.status(401).json({ message: 'Invalid token' });
    }

    if (!mongoose.Types.ObjectId.isValid(decodedToken.adminId)) {
      return res.status(400).json({ message: 'Invalid admin ID' });
    }

    const admin = await Admin.findById(decodedToken.adminId);
    if (!admin) {
      return res.status(404).json({ message: 'Admin not found' });
    }
    
    if (admin.verified) {
      return res.status(400).json({ message: 'Email already verified' });
    }

    const verifyToken = jwt.sign({ adminId: admin._id }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: admin.email,
      subject: 'Verify your email',
      text: `Verify your email by clicking this link: http://localhost:3000/verify-email/${verifyToken}`,
    };

    try {
      const info = await transporter.sendMail(mailOptions);
      console.log('Email sent: ' + info.response);
      res.status(200).json({ message: 'Email Verification sent' });
    } catch (error) {
      console.log(error);
      res.status(500).json({ message: 'Error sending verification email' });
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: 'Error processing request' });
  }
});

// Delete All Admins from Database End point - Tested
app.delete('/admins', async (req, res) => {
  try {
    await Admin.deleteMany({});
    res.status(200).json({ message: 'All admins deleted successfully' });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: 'Error deleting admins' });
  }
});

// Get All Admins from Database End point - Tested
app.get('/admins', async (req, res) => {
  try {
    const admins = await Admin.find().select('-password');
    res.status(200).json(admins);
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: 'Error fetching admins' });
  }
});

app.listen(3000, () =>
  console.log("Server running on http://localhost:3000")
);



// In your /resend-verification endpoint, you're verifying the token purpose and admin existence. You might want to consider adding more validation or error handling to ensure the request is legitimate.

// One more thing, you have created a middleware authenticateAdmin but haven't used it in the /resend-verification endpoint. Instead, you are verifying the token manually in the endpoint. You can use the middleware to verify the token and then check the purpose of the token in the endpoint.

// You have also created another endpoint app.get('/resend-verification', ...) which seems to be doing something similar to /resend-verification endpoint. You might want to consider removing or modifying one of them to avoid confusion.

// Also, you might want to consider protecting routes like /admins and /admins (delete all admins) with authentication and authorization middleware to prevent unauthorized access.


// const multer = require("multer");
// app.use('/uploads', express.static('uploads'));
// app.set("view engine", "ejs");

// app.post('/category', async (req, res) => {
//   const { category } = req.body;
//   await new Category({ name: category }).save();
//   res.redirect('/select-category');
// });

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