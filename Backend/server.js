const express = require("express");
const app = express();
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const Joi = require("joi");
const path = require("path");
const rateLimit = require("express-rate-limit");
const cookieParser = require("cookie-parser");
const nodemailer = require("nodemailer");

const Admin = require("./models/Admin");
const Category = require("./models/Category");

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

// Authentication Middleware
const authenticate = async (req, res, next) => {
  const token = req.cookies.token;
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await Admin.findById(decoded.adminId);
    // console.log(req.user)
    next();
  } catch (error) {
    res.status(401).json({ message: "Unauthorized" });
  }
};

// Verify Token Middleware
const verifyTokenMiddleware = async (req, res, next) => {
  const verificationToken = req.cookies.verificationToken;
  try {
    const decodedToken = jwt.verify(verificationToken, process.env.JWT_SECRET);
    if (decodedToken.purpose !== "resend-verification") {
      return res.status(401).json({ message: "Invalid token" });
    }
    req.adminId = decodedToken.adminId;
    next();
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({ message: "Token has expired" });
    } else if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ message: "Invalid token" });
    } else {
      throw error;
    }
  }
};

// Check User Permission
const checkPermission = (action) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({ message: "Please authenticate" });
      }
      const permissions = {
        admin: ["create", "view", "update", "delete", "search"],
        user: ["view", "search"],
      };
      if (!permissions[req.user.role] || !permissions[req.user.role].includes(action)) {
        return res.status(401).json({ message: "You don't have the permission to perform this operation" });
      }
      next();
    } catch (error) {
      res.status(500).json({ message: "Error checking permission" });
    }
  };
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
app.get("/admin-dashboard", authenticate, (req, res) => {
  // Only authenticated admins can access this route
  res.sendFile(path.join(__dirname, "../Frontend/views/admin/register.html"));
});
app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "../Frontend/views/admin/login.html"));
});
app.get("/get-admin-email", async (req, res) => {
  try {
    const verificationToken = req.cookies.verificationToken;
    const decodedToken = jwt.verify(verificationToken, process.env.JWT_SECRET);
    if (decodedToken.purpose !== "resend-verification") {
      return res.status(401).json({ message: "Invalid token" });
    }
    res.json({ email: decodedToken.email });
  } catch (error) {
    console.log(error);
    res.status(401).json({ message: "Invalid token" });
  }
});
app.get("/resend-verification", (req, res) => {
  res.sendFile(
    path.join(__dirname, "../Frontend/views/admin/resend-verification.html")
  );
});
app.get("/verify-email/:token", (req, res) => {
  res.sendFile(
    path.join(__dirname, "../Frontend/views/admin/verify-email.html")
  );
});
app.get("/forgot-password", (req, res) => {
  res.sendFile(
    path.join(__dirname, "../Frontend/views/admin/forgot-password.html")
  );
});
app.get("/reset-password/:token", (req, res) => {
  res.sendFile(
    path.join(__dirname, "../Frontend/views/admin/reset-password.html")
  );
});
app.get("/case-viewer", authenticate, (req, res) => {
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
      message: "Too many requests, please try again later.",
    });
  },
});

// Validation Schemas
const registerSchema = Joi.object({
  username: Joi.string().required().trim().min(3).messages({
    "string.empty": "Username is required",
    "string.min": "Username must contain at least 3 characters",
    "any.required": "Username is required",
  }),
  email: Joi.string().email().required().trim().messages({
    "string.empty": "Email is required",
    "string.email": "Invalid email format",
    "any.required": "Email is required",
  }),
  password: Joi.string().required().trim().min(4).max(8).messages({
    "string.empty": "Password is required",
    "string.min": "Password must contain at least 4 characters",
    "string.max": "Password must not exceed 8 characters",
    "any.required": "Password is required",
  }),
  terms: Joi.boolean().required().valid(true).messages({
    "boolean.base": "You must agree to the terms and conditions",
    "any.required": "You must agree to the terms and conditions",
    "any.valid": "You must agree to the terms and conditions",
  }),
});

const loginSchema = Joi.object({
  email: Joi.string().email().required().trim().messages({
    "string.empty": "Email is required",
    "string.email": "Invalid email format",
    "any.required": "Email is required",
  }),
  password: Joi.string().required().trim().messages({
    "string.empty": "Password is required",
    "any.required": "Password is required",
  }),
});

const forgotPasswordSchema = Joi.object({
  email: Joi.string().email().required().trim().messages({
    "string.empty": "Email is required",
    "string.email": "Invalid email format",
    "any.required": "Email is required",
  }),
});

const resetPasswordSchema = Joi.object({
  password: Joi.string().required().trim().min(4).max(8).messages({
    "string.empty": "Password is required",
    "string.min": "Password must contain at least 4 characters",
    "string.max": "Password must not exceed 8 characters",
    "any.required": "Password is required",
  }),
});

const categorySchema = Joi.object({
  name: Joi.string().required().trim().messages({
    "string.empty": "Category name is required",
    "any.required": "Category name is required",
  }),
  description: Joi.string().allow('').optional().trim(),
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
    role: "admin",
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
        res
          .status(500)
          .json({
            message:
              "Error sending verification email. Please try again later.",
          });
      } else {
        console.log("Email sent: " + info.response);
        res.status(200).json({
          message: "Registration successful, please verify your email",
          redirect: `/resend-verification/${admin._id}`,
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
    return res.status(400).json({ message: "Invalid Email or Password" });
  }

  const isValidPassword = await bcrypt.compare(password, admin.password);
  if (!isValidPassword) {
    return res.status(400).json({ message: "Invalid Email or Password" });
  }

  if (!admin.verified) {
    const verificationToken = jwt.sign(
      {
        adminId: admin._id,
        email: admin.email,
        purpose: "resend-verification",
      },
      process.env.JWT_SECRET
    );
    res.cookie("verificationToken", verificationToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      expires: new Date(Date.now() + 3600000), // 1 hour
    });
    return res.status(400).json({ message: "Email not verified" });
  }

  const token = jwt.sign({ adminId: admin._id, role: admin.role }, process.env.JWT_SECRET, {
    expiresIn: "1h",
  });

  res.cookie("token", token, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    expires: new Date(Date.now() + 3600000), // 1 hour
  });

  res.status(200).json({ message: "Login Successful" });
});

// Verify Email End point - Tested
app.get("/api/verify-email/:token", async (req, res) => {
  try {
    const token = req.params.token;
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const admin = await Admin.findById(decoded.adminId);
    if (!admin) {
      return res.status(404).json({ message: "Admin not found" });
    }
    admin.verified = true;
    await admin.save();
    res.status(200).json({ message: "Email verified successfully" });
  } catch (error) {
    console.log(error);
    res.status(400).json({ message: "Invalid or expired token" });
  }
});

// Forgot Password Endpoint - Tested
app.post("/forgot-password", async (req, res) => {
  try {
    await forgotPasswordSchema.validateAsync(req.body);
  } catch (error) {
    return res.status(400).json({
      message: "Invalid request data",
      error: error.details[0].message,
    });
  }

  try {
    const { email } = req.body;
    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(400).json({ message: "Admin not found" });
    }

    const resetToken = jwt.sign(
      { adminId: admin._id },
      process.env.JWT_SECRET,
      {
        expiresIn: "1h",
      }
    );

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
      subject: "Password Reset",
      text: `Reset your password by clicking this link: http://localhost:3000/reset-password/${resetToken}`,
    };
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.log(error);
        res.status(500).json({ message: "Error sending email" });
      } else {
        res.status(200).json({ message: "Password reset email sent" });
      }
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Error processing request" });
  }
});

// Reset Password Endpoint - Tested
app.post("/reset-password/:token", async (req, res) => {
  try {
    await resetPasswordSchema.validateAsync(req.body);
  } catch (error) {
    return res.status(400).json({
      message: "Invalid request data",
      error: error.details[0].message,
    });
  }

  try {
    const token = req.params.token;
    const { password } = req.body;

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const admin = await Admin.findById(decoded.adminId);
    if (!admin) {
      return res.status(400).json({ message: "Invalid token" });
    }

    if (admin.resetTokenExpiration < Date.now()) {
      return res.status(400).json({ message: "Token expired" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    admin.password = hashedPassword;
    admin.resetToken = undefined;
    admin.resetTokenExpiration = undefined;
    await admin.save();

    res.status(200).json({ message: "Password reset successful" });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Error resetting password" });
  }
});

// Resend Verification Endpoint - Tested
app.post("/resend-verification", verifyTokenMiddleware, async (req, res) => {
  try {
    const admin = await Admin.findById(req.adminId);
    if (!admin) {
      return res.status(404).json({ message: "Admin not found" });
    }

    if (admin.verified) {
      return res.status(400).json({ message: "Email already verified" });
    }

    const verifyToken = jwt.sign(
      { adminId: admin._id },
      process.env.JWT_SECRET,
      {
        expiresIn: "1h",
      }
    );

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: admin.email,
      subject: "Verify your email",
      text: `Verify your email by clicking this link: http://localhost:3000/verify-email/${verifyToken}`,
    };

    try {
      const info = await transporter.sendMail(mailOptions);
      console.log("Email sent: " + info.response);
      res.status(200).json({ message: "Email Verification sent" });
    } catch (error) {
      console.log(error);
      res.status(500).json({ message: "Error sending verification email" });
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Error processing request" });
  }
});

// Delete All Admins from Database End point - Tested
app.delete("/admins", async (req, res) => {
  try {
    await Admin.deleteMany({});
    res.status(200).json({ message: "All admins deleted successfully" });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Error deleting admins" });
  }
});

// Get All Admins from Database End point - Tested
app.get("/admins", async (req, res) => {
  try {
    const admins = await Admin.find().select("-password");
    res.status(200).json(admins);
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Error fetching admins" });
  }
});

// Create case (admin only)
app.post("/cases", authenticate, checkPermission("create"), async (req, res) => {
  try {
    const { title, description, category } = req.body;
    const caseDoc = new Case({ title, description, category });
    await caseDoc.save();
    res.status(201).json({ message: "Case created successfully" });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Error creating case" });
  }
});

// View All Cases (admin and user)
app.get("/cases", authenticate, checkPermission("view"), (req, res) => {
  return res.status(200).json({ message: "Get All Cases" })
});

// View Case by ID (admin and user)
app.get("/cases/:id", authenticate, checkPermission("view"), async (req, res) => {
  try {
    const caseId = req.params.id;
    const caseDoc = await Case.findById(caseId);
    if (!caseDoc) {
      return res.status(404).json({ message: "Case not found" });
    }
    res.status(200).json(caseDoc);
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Error fetching case" });
  }
});

// Update Case (admin only)
app.put("/cases/:id", authenticate, checkPermission("update"), (req, res) => {
  // Update case logic
  return res.status(200).json({ message: "Update Case by ID" })
});

// Delete Case (admin only)
app.delete("/cases/:id", authenticate, checkPermission("delete"), (req, res) => {
  // Delete case logic
  return res.status(200).json({ message: "Delete Case by ID" })
});

// Search Cases (admin and user)
app.get("/search/cases", authenticate, checkPermission("search"), (req, res) => {
  // Search cases logic
  return res.status(200).json({ message: "Search Cases" })
});

// Create Category (admin only)
app.post("/category", authenticate, checkPermission("create"), async (req, res) => {
  try {
    await categorySchema.validateAsync(req.body);
  } catch (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  const { name, description } = req.body;

  // Check if category already exists
  const existingCategory = await Category.findOne({ name });
  if (existingCategory) {
    return res.status(400).json({ message: "Category already exists" });
  }

  try {
    const categoryData = { name };
    if (description !== undefined && description.trim() !== '') {
      categoryData.description = description;
    }
    const category = new Category(categoryData);
    await category.save();
    res.status(201).json({ message: "Category created successfully" });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Error creating category" });
  }
});

// Get Category (admin and user)
app.get("/category", authenticate, checkPermission("view"), async (req, res) => {
  try {
    const categories = await Category.find();
    res.status(200).json(categories);
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Error fetching categories" });
  }
});

// Delete Category (admin only)
app.delete("/category/:id", authenticate, checkPermission("delete"), async (req, res) => {
  try {
    const categoryId = req.params.id;
    const category = await Category.findByIdAndDelete(categoryId);
    if (!category) {
      return res.status(404).json({ message: "Category not found" });
    }
    res.status(200).json({ message: "Category deleted successfully" });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Error deleting category" });
  }
});

// Update Category (admin only)
app.put("/category/:id", authenticate, checkPermission("update"), async (req, res) => {
  try {
    await categorySchema.validateAsync(req.body);
  } catch (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  try {
    const categoryId = req.params.id;
    const { name, description } = req.body;

    // Check if category name already exists
    const existingCategory = await Category.findOne({ name, _id: { $ne: categoryId } });
    if (existingCategory) {
      return res.status(400).json({ message: "Category name already exists" });
    }

    const updateData = { name };
    updateData.description = description.trim() === '' ? 'No Description' : description;

    const category = await Category.findByIdAndUpdate(categoryId, updateData, { new: true });
    if (!category) {
      return res.status(404).json({ message: "Category not found" });
    }
    res.status(200).json({ message: "Category updated successfully", category });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Error updating category" });
  }
});

app.listen(3000, () => console.log("Server running on http://localhost:3000"));
