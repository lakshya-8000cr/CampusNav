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

// Cloudinary configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Create temporary uploads directory
const uploadsDir = path.join(__dirname, 'temp', 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Initialize Express app
const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Logging middleware
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  next();
});

// MongoDB Schema
const itemSchema = new mongoose.Schema({
  name: String,
  description: String,
  location: String,
  date: { type: Date, default: Date.now },
  status: { type: String, enum: ['lost', 'found', 'resolved'], required: true },
  photo: String,
  photoPublicId: String,
  yourName: String,
  yourEmail: String,
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

// Multer configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + '-' + file.originalname);
  }
});

const upload = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed!'), false);
    }
  },
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB
});

// Nodemailer configuration
const transporter = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Verification stores
const otpStore = new Map();
const verifiedEmails = new Set();

function generateOTP() {
  return crypto.randomInt(100000, 999999).toString();
}

async function sendOTPEmail(email, otp) {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Your OTP for Campus Navigator',
    text: `Your OTP is: ${otp}. Valid for 10 minutes.`
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log('OTP email sent');
  } catch (error) {
    console.error('Error sending OTP:', error);
    throw error;
  }
}

// Track submissions
const claimCounts = new Map();
const seenCounts = new Map();

// Enhanced OTP Endpoints
app.post('/api/items/:id/request-otp', async (req, res) => {
  try {
    const { email } = req.body;
    const itemId = req.params.id;

    if (!email) return res.status(400).json({ message: 'Email required' });

    const item = await Item.findById(itemId);
    if (!item) return res.status(404).json({ message: 'Item not found' });

    // Verify email matches original reporter
    if (email !== item.yourEmail) {
      return res.status(403).json({ 
        message: 'Email does not match original reporter. Use the email you reported with.',
        valid: false
      });
    }

    // Generate and send OTP
    const otp = generateOTP();
    await sendOTPEmail(email, otp);
    otpStore.set(email, { 
      otp, 
      expiry: Date.now() + 600000,
      itemId: itemId // Store associated item ID
    });

    res.json({ 
      message: 'OTP sent to registered email',
      valid: true
    });

  } catch (error) {
    console.error('OTP request error:', error);
    res.status(500).json({ message: 'Error processing OTP request' });
  }
});

app.post('/api/verify-otp', (req, res) => {
  const { email, otp } = req.body;
  
  if (!email || !otp) {
    return res.status(400).json({ message: 'Email and OTP required' });
  }

  const storedData = otpStore.get(email);
  if (!storedData) {
    return res.status(400).json({ message: 'OTP not found or expired' });
  }

  // Verify OTP and item association
  if (Date.now() > storedData.expiry) {
    otpStore.delete(email);
    return res.status(400).json({ message: 'OTP expired' });
  }

  if (otp !== storedData.otp) {
    return res.status(400).json({ message: 'Invalid OTP' });
  }

  verifiedEmails.add(email);
  otpStore.delete(email);
  res.json({ 
    message: 'OTP verified successfully',
    itemId: storedData.itemId
  });
});

// Cloudinary upload helper
async function uploadToCloudinary(filePath) {
  try {
    const result = await cloudinary.uploader.upload(filePath, {
      folder: 'campus-navigator'
    });
    
    fs.unlink(filePath, (err) => {
      if (err) console.error('Error deleting temp file:', err);
    });
    
    return result;
  } catch (error) {
    console.error('Cloudinary error:', error);
    throw error;
  }
}

// Item Routes
app.post('/api/items', upload.single('photo'), async (req, res) => {
  try {
    const requiredFields = ['name', 'description', 'location', 'status', 'yourName', 'yourEmail'];
    if (requiredFields.some(field => !req.body[field])) {
      return res.status(400).json({ message: 'Missing required fields' });
    }

    if (!verifiedEmails.has(req.body.yourEmail)) {
      return res.status(400).json({ message: 'Email not verified' });
    }

    let photoUrl = null;
    let photoPublicId = null;

    if (req.file) {
      try {
        const result = await uploadToCloudinary(req.file.path);
        photoUrl = result.secure_url;
        photoPublicId = result.public_id;
      } catch (error) {
        return res.status(500).json({ message: 'Image upload failed' });
      }
    }

    const newItem = new Item({
      ...req.body,
      photo: photoUrl,
      photoPublicId: photoPublicId
    });

    await newItem.save();
    verifiedEmails.delete(req.body.yourEmail);
    res.status(201).json(newItem);

  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Enhanced Resolve Endpoint
app.post('/api/items/:id/resolve', async (req, res) => {
  try {
    const { email } = req.body;
    const itemId = req.params.id;

    const item = await Item.findById(itemId);
    if (!item) return res.status(404).json({ message: 'Item not found' });

    // Final email verification check
    if (email !== item.yourEmail) {
      return res.status(403).json({ 
        message: 'Authorization failed. Email mismatch.',
        resolved: false
      });
    }

    // OTP verification check
    if (!verifiedEmails.has(email)) {
      return res.status(403).json({ 
        message: 'OTP verification required',
        resolved: false
      });
    }

    // Update status
    item.status = 'resolved';
    await item.save();

    // Cleanup verification
    verifiedEmails.delete(email);

    // Send confirmation
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: `Item Resolved: ${item.name}`,
      text: `Your item "${item.name}" has been marked as resolved.`
    };

    try {
      await transporter.sendMail(mailOptions);
      res.json({ 
        message: 'Item resolved successfully',
        resolved: true
      });
    } catch (error) {
      res.json({ 
        message: 'Resolution succeeded - notification failed',
        resolved: true
      });
    }

  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Other existing routes (keep these as-is)
app.get('/api/items', async (req, res) => {
  try {
    const items = await Item.find().sort({ date: -1 });
    res.json(items);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get('/api/items/:id', async (req, res) => {
  try {
    const item = await Item.findById(req.params.id);
    if (!item) return res.status(404).json({ message: 'Item not found' });
    res.json(item);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/items/:id/seen', async (req, res) => {
  // Keep existing seen route implementation
});

app.post('/api/items/:id/claim', async (req, res) => {
  // Keep existing claim route implementation
});

// Error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Server error', error: err.message });
});

// Database connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  dbName: 'CampusNavigatorDB'
})
.then(() => {
  console.log('MongoDB connected');
  app.listen(port, () => {
    console.log(`Server running on port ${port}`);
    console.log(`Temp uploads: ${uploadsDir}`);
  });
})
.catch(err => {
  console.error('MongoDB connection failed:', err);
  process.exit(1);
});

export default app;
