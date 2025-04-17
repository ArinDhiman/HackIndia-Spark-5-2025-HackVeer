const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const dotenv = require('dotenv');
const multer = require('multer');
const path = require('path');

dotenv.config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Configure Multer for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    },
});
const upload = multer({
    storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
    fileFilter: (req, file, cb) => {
        const filetypes = /pdf|jpg|png/;
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = filetypes.test(file.mimetype);
        if (extname && mimetype) {
            cb(null, true);
        } else {
            cb(new Error('Only PDF, JPG, and PNG files are allowed'));
        }
    },
});

// Serve uploaded files statically
app.use('/uploads', express.static('uploads'));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, {
}).then(() => {
    console.log('Connected to MongoDB');
}).catch((err) => {
    console.error('MongoDB connection error:', err);
});

// Schemas
const donorSchema = new mongoose.Schema({
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    phone: { type: String, required: true },
    bloodType: { type: String, required: true },
    dob: { type: Date, required: true },
    address: { type: String, required: true },
    medicalReport: { type: String },
    termsAccepted: { type: Boolean, required: true },
    donorId: { type: String, unique: true },
}, { timestamps: true });

const patientSchema = new mongoose.Schema({
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    phone: { type: String, required: true },
    hospital: { type: String },
    patientId: { type: String },
    emergencyContact: {
        name: { type: String, required: true },
        phone: { type: String, required: true },
    },
    termsAccepted: { type: Boolean, required: true },
}, { timestamps: true });

const donationSchema = new mongoose.Schema({
    donorId: { type: mongoose.Schema.Types.ObjectId, ref: 'Donor', required: true },
    date: { type: Date, required: true },
    location: { type: String, required: true },
    type: { type: String, required: true },
    units: { type: Number, required: true },
    notes: { type: String },
}, { timestamps: true });

const appointmentSchema = new mongoose.Schema({
    donorId: { type: mongoose.Schema.Types.ObjectId, ref: 'Donor', required: true },
    date: { type: Date, required: true },
    location: { type: String, required: true },
    status: { type: String, enum: ['scheduled', 'confirmed', 'cancelled'], default: 'scheduled' },
}, { timestamps: true });

// Models
const Donor = mongoose.model('Donor', donorSchema);
const Patient = mongoose.model('Patient', patientSchema);
const Donation = mongoose.model('Donation', donationSchema);
const Appointment = mongoose.model('Appointment', appointmentSchema);

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ message: 'No token provided' });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ message: 'Invalid token' });
    }
};

// Generate unique donor ID
const generateDonorId = async () => {
    const count = await Donor.countDocuments();
    return `D${(count + 1).toString().padStart(5, '0')}`;
};

// Helper function to generate JWT
const generateToken = (user, role) => {
    return jwt.sign({ id: user._id, role }, JWT_SECRET, { expiresIn: '7d' });
};

// Donor Registration
app.post('/api/donor/register', upload.single('medicalReport'), async (req, res) => {
    try {
        const {
            firstName,
            lastName,
            email,
            password,
            phone,
            bloodType,
            dob,
            address,
            termsAccepted,
        } = req.body;

        // Validation
        if (!firstName || !lastName || !email || !password || !phone || !bloodType || !dob || !address || termsAccepted === undefined) {
            return res.status(400).json({ message: 'All required fields must be provided' });
        }

        // Check if donor exists
        const existingDonor = await Donor.findOne({ email });
        if (existingDonor) {
            return res.status(400).json({ message: 'Email already registered' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Generate donor ID
        const donorId = await generateDonorId();

        // Create donor
        const donor = new Donor({
            firstName,
            lastName,
            email,
            password: hashedPassword,
            phone,
            bloodType,
            dob,
            address,
            medicalReport: req.file ? `/uploads/${req.file.filename}` : null,
            termsAccepted: termsAccepted === 'true',
            donorId,
        });

        await donor.save();

        // Generate token
        const token = generateToken(donor, 'donor');

        res.status(201).json({
            message: 'Donor registered successfully',
            token,
            user: {
                id: donor._id,
                firstName,
                lastName,
                email,
                role: 'donor',
                donorId,
            },
        });
    } catch (error) {
        console.error('Donor registration error:', error);
        res.status(500).json({ message: error.message || 'Server error' });
    }
});

// Donor Login
app.post('/api/donor/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validation
        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }

        // Find donor
        const donor = await Donor.findOne({ email });
        if (!donor) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Check password
        const isMatch = await bcrypt.compare(password, donor.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Generate token
        const token = generateToken(donor, 'donor');

        res.status(200).json({
            message: 'Login successful',
            token,
            user: {
                id: donor._id,
                firstName: donor.firstName,
                lastName: donor.lastName,
                email: donor.email,
                role: 'donor',
                donorId: donor.donorId,
            },
        });
    } catch (error) {
        console.error('Donor login error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Patient Registration
app.post('/api/patient/register', async (req, res) => {
    try {
        const {
            firstName,
            lastName,
            email,
            password,
            phone,
            hospital,
            patientId,
            emergencyContact,
            termsAccepted,
        } = req.body;

        // Validation
        if (!firstName || !lastName || !email || !password || !phone || !emergencyContact || termsAccepted === undefined) {
            return res.status(400).json({ message: 'All required fields must be provided' });
        }

        // Parse emergencyContact if sent as separate fields
        let parsedEmergencyContact;
        if (typeof emergencyContact === 'string') {
            try {
                parsedEmergencyContact = JSON.parse(emergencyContact);
            } catch (error) {
                return res.status(400).json({ message: 'Invalid emergency contact format' });
            }
        } else {
            parsedEmergencyContact = {
                name: req.body['emergencyContact[name]'],
                phone: req.body['emergencyContact[phone]'],
            };
        }

        // Validate emergencyContact
        if (!parsedEmergencyContact.name || !parsedEmergencyContact.phone) {
            return res.status(400).json({ message: 'Emergency contact name and phone are required' });
        }

        // Check if patient exists
        const existingPatient = await Patient.findOne({ email });
        if (existingPatient) {
            return res.status(400).json({ message: 'Email already registered' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create patient
        const patient = new Patient({
            firstName,
            lastName,
            email,
            password: hashedPassword,
            phone,
            hospital,
            patientId,
            emergencyContact: parsedEmergencyContact,
            termsAccepted: termsAccepted === 'true' || termsAccepted === true,
        });

        await patient.save();

        // Generate token
        const token = generateToken(patient, 'patient');

        res.status(201).json({
            message: 'Patient registered successfully',
            token,
            user: {
                id: patient._id,
                firstName,
                lastName,
                email,
                role: 'patient',
            },
        });
    } catch (error) {
        console.error('Patient registration error:', error);
        res.status(500).json({ message: error.message || 'Server error' });
    }
});

// Patient Login
app.post('/api/patient/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validation
        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }

        // Find patient
        const patient = await Patient.findOne({ email });
        if (!patient) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Check password
        const isMatch = await bcrypt.compare(password, patient.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Generate token
        const token = generateToken(patient, 'patient');

        res.status(200).json({
            message: 'Login successful',
            token,
            user: {
                id: patient._id,
                firstName: patient.firstName,
                lastName: patient.lastName,
                email: patient.email,
                role: 'patient',
            },
        });
    } catch (error) {
        console.error('Patient login error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get Donor Profile
app.get('/api/donor/profile', verifyToken, async (req, res) => {
    try {
        if (req.user.role !== 'donor') {
            return res.status(403).json({ message: 'Unauthorized' });
        }
        const donor = await Donor.findById(req.user.id).select('-password');
        if (!donor) {
            return res.status(404).json({ message: 'Donor not found' });
        }
        res.status(200).json(donor);
    } catch (error) {
        console.error('Get donor profile error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Update Donor Profile
app.put('/api/donor/profile', verifyToken, upload.single('medicalReport'), async (req, res) => {
    try {
        if (req.user.role !== 'donor') {
            return res.status(403).json({ message: 'Unauthorized' });
        }
        const { firstName, lastName, phone, address, bloodType, dob } = req.body;
        const updateData = {
            firstName,
            lastName,
            phone,
            address,
            bloodType,
            dob,
        };
        if (req.file) {
            updateData.medicalReport = `/uploads/${req.file.filename}`;
        }
        const donor = await Donor.findByIdAndUpdate(req.user.id, updateData, { new: true }).select('-password');
        if (!donor) {
            return res.status(404).json({ message: 'Donor not found' });
        }
        res.status(200).json({ message: 'Profile updated successfully', donor });
    } catch (error) {
        console.error('Update donor profile error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get Donation History
app.get('/api/donor/donations', verifyToken, async (req, res) => {
    try {
        if (req.user.role !== 'donor') {
            return res.status(403).json({ message: 'Unauthorized' });
        }
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 5;
        const skip = (page - 1) * limit;

        const donations = await Donation.find({ donorId: req.user.id })
            .sort({ date: -1 })
            .skip(skip)
            .limit(limit);
        const total = await Donation.countDocuments({ donorId: req.user.id });

        res.status(200).json({
            donations,
            pagination: {
                page,
                limit,
                total,
                pages: Math.ceil(total / limit),
            },
        });
    } catch (error) {
        console.error('Get donation history error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Export Donation History
app.get('/api/donor/donations/export', verifyToken, async (req, res) => {
    try {
        if (req.user.role !== 'donor') {
            return res.status(403).json({ message: 'Unauthorized' });
        }
        const donations = await Donation.find({ donorId: req.user.id }).sort({ date: -1 });
        const csv = [
            'Date,Location,Type,Units,Notes',
            ...donations.map(d => `${d.date.toISOString().split('T')[0]},"${d.location}","${d.type}",${d.units},"${d.notes || ''}"`),
        ].join('\n');

        res.header('Content-Type', 'text/csv');
        res.attachment('donation_history.csv');
        res.send(csv);
    } catch (error) {
        console.error('Export donation history error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get Upcoming Appointments
app.get('/api/donor/appointments', verifyToken, async (req, res) => {
    try {
        if (req.user.role !== 'donor') {
            return res.status(403).json({ message: 'Unauthorized' });
        }
        const appointments = await Appointment.find({ donorId: req.user.id, date: { $gte: new Date() } })
            .sort({ date: 1 });
        res.status(200).json(appointments);
    } catch (error) {
        console.error('Get appointments error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Schedule New Appointment
app.post('/api/donor/appointments', verifyToken, async (req, res) => {
    try {
        if (req.user.role !== 'donor') {
            return res.status(403).json({ message: 'Unauthorized' });
        }
        const { date, location } = req.body;
        if (!date || !location) {
            return res.status(400).json({ message: 'Date and location are required' });
        }
        const appointment = new Appointment({
            donorId: req.user.id,
            date: new Date(date),
            location,
        });
        await appointment.save();
        res.status(201).json({ message: 'Appointment scheduled successfully', appointment });
    } catch (error) {
        console.error('Schedule appointment error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Confirm Appointment
app.put('/api/donor/appointments/:id/confirm', verifyToken, async (req, res) => {
    try {
        if (req.user.role !== 'donor') {
            return res.status(403).json({ message: 'Unauthorized' });
        }
        const appointment = await Appointment.findOneAndUpdate(
            { _id: req.params.id, donorId: req.user.id },
            { status: 'confirmed' },
            { new: true }
        );
        if (!appointment) {
            return res.status(404).json({ message: 'Appointment not found' });
        }
        res.status(200).json({ message: 'Appointment confirmed', appointment });
    } catch (error) {
        console.error('Confirm appointment error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Reschedule Appointment
app.put('/api/donor/appointments/:id/reschedule', verifyToken, async (req, res) => {
    try {
        if (req.user.role !== 'donor') {
            return res.status(403).json({ message: 'Unauthorized' });
        }
        const { date, location } = req.body;
        if (!date || !location) {
            return res.status(400).json({ message: 'Date and location are required' });
        }
        const appointment = await Appointment.findOneAndUpdate(
            { _id: req.params.id, donorId: req.user.id },
            { date: new Date(date), location, status: 'scheduled' },
            { new: true }
        );
        if (!appointment) {
            return res.status(404).json({ message: 'Appointment not found' });
        }
        res.status(200).json({ message: 'Appointment rescheduled', appointment });
    } catch (error) {
        console.error('Reschedule appointment error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get Eligibility Status
app.get('/api/donor/eligibility', verifyToken, async (req, res) => {
    try {
        if (req.user.role !== 'donor') {
            return res.status(403).json({ message: 'Unauthorized' });
        }
        const lastDonation = await Donation.findOne({ donorId: req.user.id }).sort({ date: -1 });
        let isEligible = true;
        let nextEligibleDate = null;

        if (lastDonation) {
            const lastDonationDate = new Date(lastDonation.date);
            nextEligibleDate = new Date(lastDonationDate.setDate(lastDonationDate.getDate() + 56));
            isEligible = new Date() >= nextEligibleDate;
        }

        res.status(200).json({
            isEligible,
            nextEligibleDate: nextEligibleDate ? nextEligibleDate.toISOString().split('T')[0] : null,
            lastDonation: lastDonation ? lastDonation.date.toISOString().split('T')[0] : null,
            totalUnits: await Donation.aggregate([
                { $match: { donorId: mongoose.Types.ObjectId(req.user.id) } },
                { $group: { _id: null, total: { $sum: '$units' } } },
            ]).then(result => result[0]?.total || 0),
        });
    } catch (error) {
        console.error('Get eligibility error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});