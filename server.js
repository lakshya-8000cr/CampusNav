import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import dotenv from 'dotenv';
import path from 'path';
import multer from 'multer';
import { fileURLToPath } from 'url';
import fs from 'fs';
import nodemailer from 'nodemailer';
import crypto from 'crypto';
import { v2 as cloudinary } from 'cloudinary';

dotenv.config();

// Cloudinary Configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Temporary Upload Directory
const uploadsDir = path.join(__dirname, 'temp', 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Enhanced Logging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.originalUrl}`);
  next();
});

// MongoDB Schema
const itemSchema = new mongoose.Schema({
  name: String,
  description: String,
  location: String,
  date: { type: Date, default: Date.now },
  status: { 
    type: String, 
    enum: ['lost', 'found', 'resolved'], 
    required: true 
  },
  photo: String,
  photoPublicId: String,
  yourName: String,
  yourEmail: {
    type: String,
    required: true,
    match: /^[a-zA-Z0-9]+[0-9]{4}\.(?:be|btech|mtech|phd)[a-zA-Z]{2,4}[0-9]{2}@chitkara\.edu\.in$/
  },
  seenBy: [{
    name: String,
    phone: String,
    details: String,
    date: { type: Date, default: Date.now },
    email: String
  }],
  claims: [{
    name: String,
    email: String,
    details: String,
    date: { type: Date, default: Date.now }
  }]
}, { collection: 'Lost-found' });

const Item = mongoose.model('Item', itemSchema);

// File Upload Configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${Math.random().toString(36).substr(2, 9)}-${file.originalname}`);
  }
});

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    file.mimetype.startsWith('image/') ? cb(null, true) : cb(new Error('Only images allowed'));
  },
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB
});

// Email Configuration
const transporter = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Security Stores
const otpStore = new Map();
const verifiedEmails = new Set();

// OTP Functions
const generateOTP = () => crypto.randomInt(100000, 999999).toString();

async function sendOTPEmail(email, otp) {
  try {
    await transporter.verify();
    
    const mailOptions = {
      from: `Campus Navigator <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Your Verification Code',
      text: `Your OTP is: ${otp}\nValid for 10 minutes.`,
      html: `<div style="font-family: Arial, sans-serif; padding: 20px;">
              <h2>Campus Navigator Verification</h2>
              <p>Your verification code is:</p>
              <h1 style="color: #2563eb;">${otp}</h1>
              <p>This code will expire in 10 minutes.</p>
            </div>`
    };

    const info = await transporter.sendMail(mailOptions);
    console.log(`OTP sent to ${email}:`, info.messageId);
    return true;
  } catch (error) {
    console.error('Email Error:', error);
    throw new Error('Failed to send OTP. Please try again later.');
  }
}

// OTP Endpoints
app.post('/api/items/:id/request-otp', async (req, res) => {
  try {
    const { email } = req.body;
    const itemId = req.params.id;

    // Validation
    if (!email || !itemId) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email and item ID required' 
      });
    }

    // Find item
    const item = await Item.findById(itemId);
    if (!item) {
      return res.status(404).json({ 
        success: false, 
        message: 'Item not found' 
      });
    }

    // Email verification
    if (email !== item.yourEmail) {
      return res.status(403).json({ 
        success: false,
        message: 'This email does not match the original reporter',
        emailVerified: false
      });
    }

    // Generate and send OTP
    try {
      const otp = generateOTP();
      await sendOTPEmail(email, otp);
      otpStore.set(email, { 
        otp, 
        expiry: Date.now() + 600000,
        itemId 
      });

      return res.json({ 
        success: true,
        message: 'OTP sent to registered email',
        emailVerified: true
      });

    } catch (error) {
      return res.status(500).json({ 
        success: false,
        message: error.message || 'Failed to send OTP',
        emailError: true
      });
    }

  } catch (error) {
    console.error('OTP Request Error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
});

app.post('/api/verify-otp', (req, res) => {
  try {
    const { email, otp } = req.body;
    
    // Validate input
    if (!email || !otp) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email and OTP required' 
      });
    }

    // Check OTP existence
    const storedData = otpStore.get(email);
    if (!storedData) {
      return res.status(400).json({ 
        success: false, 
        message: 'OTP expired or invalid' 
      });
    }

    // Validate OTP
    if (Date.now() > storedData.expiry) {
      otpStore.delete(email);
      return res.status(400).json({ 
        success: false, 
        message: 'OTP expired' 
      });
    }

    if (otp !== storedData.otp) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid OTP' 
      });
    }

    // Mark email as verified
    verifiedEmails.add(email);
    otpStore.delete(email);

    res.json({ 
      success: true,
      message: 'OTP verified successfully',
      itemId: storedData.itemId
    });

  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
});

// Item Resolution
app.post('/api/items/:id/resolve', async (req, res) => {
  try {
    const { email } = req.body;
    const itemId = req.params.id;

    // Validate input
    if (!email || !itemId) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email and item ID required' 
      });
    }

    // Find item
    const item = await Item.findById(itemId);
    if (!item) {
      return res.status(404).json({ 
        success: false, 
        message: 'Item not found' 
      });
    }

    // Authorization checks
    if (email !== item.yourEmail) {
      return res.status(403).json({ 
        success: false,
        message: 'Unauthorized to resolve this item',
        authorized: false
      });
    }

    if (!verifiedEmails.has(email)) {
      return res.status(403).json({ 
        success: false,
        message: 'Email not verified with OTP',
        verified: false
      });
    }

    // Update item status
    item.status = 'resolved';
    await item.save();

    // Cleanup
    verifiedEmails.delete(email);

    // Send confirmation
    try {
      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: `Item Resolved: ${item.name}`,
        text: `Your item "${item.name}" has been marked as resolved.`
      });
    } catch (emailError) {
      console.error('Confirmation Email Error:', emailError);
    }

    res.json({ 
      success: true,
      message: 'Item resolved successfully',
      resolved: true
    });

  } catch (error) {
    console.error('Resolution Error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
});

// Other Routes (Keep existing implementations)
// ... [Include your existing /api/items, /seen, /claim routes here] ...

// Error Handler
app.use((err, req, res, next) => {
  console.error('Global Error:', err);
  res.status(500).json({ 
    success: false, 
    message: 'An unexpected error occurred' 
  });
});

// Database Connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  dbName: 'CampusNavigatorDB'
})
.then(() => {
  console.log('MongoDB connected');
  app.listen(port, () => {
    console.log(`Server running on port ${port}`);
    console.log(`Temporary uploads directory: ${uploadsDir}`);
  });
})
.catch(err => {
  console.error('Database Connection Error:', err);
  process.exit(1);
});

export default app;
