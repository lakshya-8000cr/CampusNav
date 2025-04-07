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

// Create temporary uploads directory (we'll delete files after upload to Cloudinary)
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
  photo: String, // This will now store Cloudinary URL instead of local path
  photoPublicId: String, // Store Cloudinary public ID for potential deletion later
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
}, {
  collection: 'Lost-found'
  // Removed duplicate status field here that was causing the issue
});

const Item = mongoose.model('Item', itemSchema);

// Multer configuration - store files temporarily
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
  limits: {
      fileSize: 5 * 1024 * 1024 // 5MB limit
  }
});

// Nodemailer configuration
const transporter = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE,
  auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
  }
});

// OTP and Email verification
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
      text: `Your OTP is: ${otp}. This OTP will expire in 10 minutes.`
  };

  try {
      await transporter.sendMail(mailOptions);
      console.log('OTP email sent successfully');
  } catch (error) {
      console.error('Error sending OTP email:', error);
      throw error;
  }
}

// Track submission counts separately for claims and seen
const claimCounts = new Map();
const seenCounts = new Map();

// Auth Routes
app.post('/api/request-otp', async (req, res) => {
  const { email } = req.body;
  if (!email) {
      return res.status(400).json({ message: 'Email is required' });
  }

  try {
      const otp = generateOTP();
      await sendOTPEmail(email, otp);
      otpStore.set(email, { otp, expiry: Date.now() + 600000 });
      res.json({ message: 'OTP sent successfully' });
  } catch (error) {
      console.error('Error in OTP request:', error);
      res.status(500).json({ message: 'Error sending OTP' });
  }
});

app.post('/api/verify-otp', (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) {
      return res.status(400).json({ message: 'Email and OTP are required' });
  }

  const storedOTPData = otpStore.get(email);
  if (!storedOTPData) {
      return res.status(400).json({ message: 'No OTP found for this email' });
  }

  if (Date.now() > storedOTPData.expiry) {
      otpStore.delete(email);
      return res.status(400).json({ message: 'OTP has expired' });
  }

  if (otp !== storedOTPData.otp) {
      return res.status(400).json({ message: 'Invalid OTP' });
  }

  verifiedEmails.add(email);
  otpStore.delete(email);
  res.json({ message: 'OTP verified successfully' });
});

// Helper function to upload to Cloudinary
async function uploadToCloudinary(filePath) {
  try {
    const result = await cloudinary.uploader.upload(filePath, {
      folder: 'campus-navigator'
    });
    
    // Delete the local file after upload
    fs.unlink(filePath, (err) => {
      if (err) console.error('Error deleting temporary file:', err);
    });
    
    return result;
  } catch (error) {
    console.error('Cloudinary upload error:', error);
    throw error;
  }
}

// Item Routes
app.post('/api/items', upload.single('photo'), async (req, res) => {
  try {
      console.log('Received item creation request:', req.body);
      if (!req.body.name || !req.body.description || !req.body.location || !req.body.status || !req.body.yourName || !req.body.yourEmail) {
          return res.status(400).json({ message: 'Missing required fields' });
      }

      if (!verifiedEmails.has(req.body.yourEmail)) {
          return res.status(400).json({ message: 'Email not verified. Please verify your email first.' });
      }

      let photoUrl = null;
      let photoPublicId = null;
      
      // Upload to Cloudinary if there's a file
      if (req.file) {
        try {
          const cloudinaryResult = await uploadToCloudinary(req.file.path);
          photoUrl = cloudinaryResult.secure_url;
          photoPublicId = cloudinaryResult.public_id;
        } catch (uploadError) {
          console.error('Error uploading to Cloudinary:', uploadError);
          return res.status(500).json({ message: 'Error uploading image' });
        }
      }

      const newItem = new Item({
          name: req.body.name,
          description: req.body.description,
          location: req.body.location,
          status: req.body.status,
          photo: photoUrl,
          photoPublicId: photoPublicId,
          yourName: req.body.yourName,
          yourEmail: req.body.yourEmail
      });

      await newItem.save();
      verifiedEmails.delete(req.body.yourEmail);
      res.status(201).json(newItem);
  } catch (error) {
      console.error('Error saving item:', error);
      res.status(500).json({ message: error.message });
  }
});

// The rest of your routes remain the same
app.get('/api/items', async (req, res) => {
  try {
      const items = await Item.find().sort({ date: -1 });
      res.json(items);
  } catch (error) {
      console.error('Error fetching items:', error);
      res.status(500).json({ message: error.message });
  }
});

app.get('/api/items/:id', async (req, res) => {
  try {
      const item = await Item.findById(req.params.id);
      if (!item) {
          return res.status(404).json({ message: 'Item not found' });
      }
      res.json(item);
  } catch (error) {
      console.error('Error fetching item:', error);
      res.status(500).json({ message: error.message });
  }
});

app.post('/api/items/:id/seen', async (req, res) => {
  try {
      const { name, phone, details, email } = req.body;
      
      // Check if email is provided and valid
      if (!email || !email.match(/^[a-zA-Z0-9]+[0-9]{4}\.(?:be|btech|mtech|phd)[a-zA-Z]{2,4}[0-9]{2}@chitkara\.edu\.in$/)) {
          return res.status(400).json({ message: 'Valid Chitkara University email is required.' });
      }

      // Check seen count
      const seenCount = seenCounts.get(email) || 0;
      if (seenCount >= 2) {
          return res.status(400).json({ message: 'You have reached the maximum number of information submissions allowed (2).' });
      }

      const item = await Item.findByIdAndUpdate(
          req.params.id,
          { $push: { seenBy: { name, phone, details, email } } },
          { new: true }
      );

      if (!item) {
          return res.status(404).json({ message: 'Item not found' });
      }

      // Increment seen count
      seenCounts.set(email, seenCount + 1);

      // Send email notification
      const mailOptions = {
          from: process.env.EMAIL_USER,
          to: item.yourEmail,
          subject: `Someone has seen your lost item: ${item.name}`,
          text: `
              Someone has information about your lost item: ${item.name}
              
              Details:
              Name: ${name}
              Phone: ${phone}
              Message: ${details}
              
              Please contact them for more information.
          `
      };

      try {
          await transporter.sendMail(mailOptions);
          res.json({ message: 'Information submitted and owner notified', notificationSent: true });
      } catch (error) {
          res.json({ message: 'Information submitted but owner could not be notified', notificationSent: false });
      }
  } catch (error) {
      console.error('Error submitting information:', error);
      res.status(500).json({ message: error.message });
  }
});

app.post('/api/items/:id/claim', async (req, res) => {
  try {
      const { name, email, details } = req.body;
      
      // Check if email is provided and valid
      if (!email || !email.match(/^[a-zA-Z0-9]+[0-9]{4}\.(?:be|btech|mtech|phd)[a-zA-Z]{2,4}[0-9]{2}@chitkara\.edu\.in$/)) {
          return res.status(400).json({ message: 'Valid Chitkara University email is required.' });
      }

      // Verify email is verified
      if (!verifiedEmails.has(email)) {
          return res.status(403).json({ message: 'Email not verified. Please verify your email first.' });
      }

      // Check claim count
      const claimCount = claimCounts.get(email) || 0;
      if (claimCount >= 2) {
          return res.status(400).json({ message: 'You have reached the maximum number of claims allowed (2).' });
      }

      const item = await Item.findByIdAndUpdate(
          req.params.id,
          { $push: { claims: { name, email, details } } },
          { new: true }
      );

      if (!item) {
          return res.status(404).json({ message: 'Item not found' });
      }

      // Increment claim count
      claimCounts.set(email, claimCount + 1);

      // Send email notification
      const mailOptions = {
          from: process.env.EMAIL_USER,
          to: item.yourEmail,
          subject: `Someone has claimed the found item: ${item.name}`,
          text: `
              Someone has claimed the found item: ${item.name}
              
              Claimant Details:
              Name: ${name}
              Email: ${email}
              Message: ${details}
              
              Please review the claim and contact them if the details match.
          `
      };

      try {
          await transporter.sendMail(mailOptions);
          res.json({ message: 'Claim submitted and finder notified', notificationSent: true });
      } catch (error) {
          res.json({ message: 'Claim submitted but finder could not be notified', notificationSent: false });
      }
  } catch (error) {
      console.error('Error submitting claim:', error);
      res.status(500).json({ message: error.message });
  }
});

// New route to resolve an item
app.post('/api/items/:id/resolve', async (req, res) => {
  try {
    const { email } = req.body;
    
    const item = await Item.findById(req.params.id);
    if (!item) {
      return res.status(404).json({ message: 'Item not found' });
    }

    if (email !== item.yourEmail) {
      return res.status(403).json({ message: 'You are not authorized to resolve this item. Only the person who reported this item can resolve it.' });
    }

    item.status = 'resolved';
    await item.save();

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: item.yourEmail,
      subject: `Your item has been marked as resolved: ${item.name}`,
      text: `
        Your item "${item.name}" has been marked as resolved.
        
        Thank you for using Campus Navigator!
      `
    };

    try {
      await transporter.sendMail(mailOptions);
      res.json({ message: 'Item resolved successfully and notification sent', notificationSent: true });
    } catch (error) {
      res.json({ message: 'Item resolved successfully but notification could not be sent', notificationSent: false });
    }
  } catch (error) {
    console.error('Error resolving item:', error);
    res.status(500).json({ message: error.message });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
      message: 'Something went wrong!',
      error: err.message
  });
});

// Connect to MongoDB and start server
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  dbName: 'CampusNavigatorDB'
})
.then(() => {
  console.log('MongoDB connected successfully');
  app.listen(port, () => {
      console.log(`Server running at http://localhost:${port}`);
      console.log(`Temporary uploads directory: ${uploadsDir}`);
  });
})
.catch(err => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});

export default app;
