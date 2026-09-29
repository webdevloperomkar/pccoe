const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const path = require('path');
const { evaluateSecurityRules } = require('./securityEngine');

const app = express();
app.use(cors());
app.use(express.json());

// Serve static files from root directory
app.use(express.static(__dirname));

const db = require('./db');

// Test Connection
(async () => {
    try {
        const connection = await db.getConnection();
        console.log('✅ Connected to MySQL database.');
        connection.release();
    } catch (err) {
        console.error('❌ Database connection error:', err.message);
    }
})();

// Explicit route for Admin SOC Dashboard
app.get('/admin-security', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin-security.html'));
});

// ==========================================
// 2. RATE LIMITERS
// ==========================================

const registerLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 5, 
    message: { success: false, message: "Too many accounts created from this IP. Please try again later." }
});

const loginLimiter = rateLimit({
    windowMs: 10 * 60 * 1000, 
    max: 5, 
    message: { success: false, message: "Too many failed login attempts. Please try again after 10 minutes." }
});

const appointmentLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 3,
    message: { success: false, message: "Too many appointment requests. Please wait a few minutes before trying again." }
});

const doctorRegisterLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { success: false, message: "Too many doctor registration attempts. Please try again later." }
});

const doctorLoginLimiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    max: 5,
    message: { success: false, message: "Too many failed doctor login attempts. Please try again after 10 minutes." }
});

// ==========================================
// Global Audit Middleware
// ==========================================

app.use((req, res, next) => {
    const originalJson = res.json;

    res.json = function (data) {
        res.locals.body = data;
        return originalJson.apply(res, arguments);
    };

    res.on('finish', async () => {
        if (req.path.startsWith('/api/admin/security') || req.path.includes('admin-security')) return;

        const userId = req.body?.userId || req.query?.userId || 0;
        const userRole = req.body?.userRole || req.headers?.['x-user-role'] || 'Guest';
        const action = req.path;
        const status = res.statusCode < 400 ? 'ALLOWED' : 'DENIED';
        
        const recordsCount = Array.isArray(res.locals.body?.data) 
            ? res.locals.body.data.length 
            : (res.locals.body?.records?.length || 1);

        const logEntry = {
            userId,
            userRole,
            action,
            resourceType: req.path.split('/')[2] || 'EHR_Endpoint',
            status,
            recordsCount,
            isEmergencyOverride: req.body?.isEmergency === true
        };

        try {
            await db.query(
                `INSERT INTO access_logs (user_id, user_role, action, resource_type, records_count, status) 
                 VALUES (?, ?, ?, ?, ?, ?)`,
                [userId, userRole, action, logEntry.resourceType, recordsCount, status]
            );

            await evaluateSecurityRules(logEntry);
        } catch (err) {
            console.error("Audit Logging Error:", err.message);
        }
    });

    next();
});

// ==========================================
// ADMIN SECURITY DASHBOARD ENDPOINTS
// ==========================================

app.get('/api/admin/security-metrics', async (req, res) => {
    const userRole = req.headers['x-user-role'];

    // Block non-admin API requests if specified
    if (userRole && userRole !== 'Admin') {
        return res.status(403).json({ success: false, message: "Forbidden: Admin access required." });
    }

    try {
        const [logs] = await db.query('SELECT * FROM access_logs ORDER BY timestamp DESC LIMIT 30');
        const [alerts] = await db.query('SELECT * FROM security_alerts WHERE status = "OPEN" ORDER BY created_at DESC');
        const [counts] = await db.query(`
            SELECT 
                COUNT(*) as totalLogs,
                SUM(CASE WHEN status = 'DENIED' THEN 1 ELSE 0 END) as deniedAccess,
                (SELECT COUNT(*) FROM security_alerts WHERE status = 'OPEN') as activeAlerts
            FROM access_logs
        `);

        res.json({ success: true, metrics: counts[0], recentLogs: logs, activeAlerts: alerts });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.post('/api/admin/resolve-alert', async (req, res) => {
    const { alertId, status } = req.body;
    try {
        await db.query('UPDATE security_alerts SET status = ? WHERE id = ?', [status, alertId]);
        res.json({ success: true, message: `Alert updated to ${status}` });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ==========================================
// PATIENT ROUTES
// ==========================================

app.post('/api/patient/register', registerLimiter, async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ success: false, message: "All fields are required." });
    }

    try {
        const [existing] = await db.query('SELECT id FROM patients WHERE email = ?', [email]);
        if (existing.length > 0) {
            return res.status(400).json({ success: false, message: "Email is already registered." });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await db.query('INSERT INTO patients (email, password) VALUES (?, ?)', [email, hashedPassword]);

        res.status(201).json({ success: true, message: "Registration successful!" });
    } catch (error) {
        console.error("Registration Error:", error);
        res.status(500).json({ success: false, message: `Server error: ${error.message}` });
    }
});

app.post('/api/patient/login', loginLimiter, async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ success: false, message: "Please provide email and password." });
    }

    try {
        const [rows] = await db.query('SELECT * FROM patients WHERE email = ?', [email]);
        
        if (rows.length === 0) {
            return res.status(401).json({ success: false, message: "Invalid email or password." });
        }

        const patient = rows[0];
        const isMatch = await bcrypt.compare(password, patient.password);

        if (!isMatch) {
            return res.status(401).json({ success: false, message: "Invalid email or password." });
        }

        res.status(200).json({ 
            success: true, 
            message: "Login successful!",
            patient: { id: patient.id, email: patient.email }
        });
    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({ success: false, message: `Server error: ${error.message}` });
    }
});

app.get('/api/patient/dashboard/:patientId', async (req, res) => {
    const { patientId } = req.params;

    try {
        const [patientRows] = await db.query(
            'SELECT id, email, name, age, gender, blood_group FROM patients WHERE id = ?', 
            [patientId]
        );

        if (patientRows.length === 0) {
            return res.status(404).json({ success: false, message: "Patient not found." });
        }

        const [appointmentRows] = await db.query(
            'SELECT * FROM appointments WHERE patient_id = ? ORDER BY created_at DESC', 
            [patientId]
        );

        res.status(200).json({
            success: true,
            patient: patientRows[0],
            appointments: appointmentRows
        });
    } catch (error) {
        console.error("Dashboard Fetch Error:", error);
        res.status(500).json({ success: false, message: `Server error: ${error.message}` });
    }
});

app.post('/api/patient/book-appointment', appointmentLimiter, async (req, res) => {
    const { patientId, name, age, gender, bloodGroup, symptoms } = req.body;

    if (!patientId || !name || !age || !gender || !bloodGroup || !symptoms) {
        return res.status(400).json({ success: false, message: "All fields are required." });
    }

    try {
        const [existingUpcoming] = await db.query(
            'SELECT id FROM appointments WHERE patient_id = ? AND status = "Upcoming"',
            [patientId]
        );

        if (existingUpcoming.length > 0) {
            return res.status(400).json({
                success: false,
                message: "You already have an active upcoming appointment."
            });
        }

        await db.query(
            'UPDATE patients SET name = ?, age = ?, gender = ?, blood_group = ? WHERE id = ?',
            [name, age, gender, bloodGroup, patientId]
        );

        const [countRow] = await db.query(
            'SELECT COUNT(*) as count FROM appointments WHERE DATE(created_at) = CURDATE()'
        );
        const tokenNumber = countRow[0].count + 1;

        await db.query(
            'INSERT INTO appointments (patient_id, patient_name, age, gender, blood_group, symptoms, token_number) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [patientId, name, age, gender, bloodGroup, symptoms, tokenNumber]
        );

        res.status(201).json({
            success: true,
            message: "Appointment booked successfully!",
            tokenNumber: tokenNumber
        });
    } catch (error) {
        console.error("Booking Error:", error);
        res.status(500).json({ success: false, message: `Server error: ${error.message}` });
    }
});

// ==========================================
// DOCTOR ROUTES
// ==========================================

app.post('/api/doctor/register', doctorRegisterLimiter, async (req, res) => {
    const { fullName, licenseNo, specialization, email, phone, password } = req.body;

    if (!fullName || !licenseNo || !specialization || !email || !phone || !password) {
        return res.status(400).json({ success: false, message: "All fields are required." });
    }

    try {
        const [existing] = await db.query(
            'SELECT id FROM doctors WHERE email = ? OR license_no = ?',
            [email, licenseNo]
        );

        if (existing.length > 0) {
            return res.status(400).json({ success: false, message: "Email or Medical License Number already registered." });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        await db.query(
            'INSERT INTO doctors (full_name, license_no, specialization, email, phone, password) VALUES (?, ?, ?, ?, ?, ?)',
            [fullName, licenseNo, specialization, email, phone, hashedPassword]
        );

        res.status(201).json({ success: true, message: "Doctor registration successful!" });
    } catch (error) {
        console.error("Doctor Register Error:", error);
        res.status(500).json({ success: false, message: `Server error: ${error.message}` });
    }
});

app.post('/api/doctor/login', doctorLoginLimiter, async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ success: false, message: "Please provide both email and password." });
    }

    try {
        const [rows] = await db.query('SELECT * FROM doctors WHERE email = ?', [email]);

        if (rows.length === 0) {
            return res.status(401).json({ success: false, message: "Invalid email or password." });
        }

        const doctor = rows[0];
        const isMatch = await bcrypt.compare(password, doctor.password);

        if (!isMatch) {
            return res.status(401).json({ success: false, message: "Invalid email or password." });
        }

        res.status(200).json({
            success: true,
            message: "Doctor Login Successful!",
            doctor: {
                id: doctor.id,
                fullName: doctor.full_name,
                licenseNo: doctor.license_no,
                specialization: doctor.specialization,
                email: doctor.email
            }
        });
    } catch (error) {
        console.error("Doctor Login Error:", error);
        res.status(500).json({ success: false, message: `Server error: ${error.message}` });
    }
});

app.get('/api/doctor/queue', async (req, res) => {
    try {
        const [rows] = await db.query(
            'SELECT * FROM appointments WHERE status = "Upcoming" ORDER BY created_at ASC'
        );
        res.status(200).json({ success: true, appointments: rows });
    } catch (error) {
        console.error("Queue Fetch Error:", error);
        res.status(500).json({ success: false, message: `Database error: ${error.message}` });
    }
});

app.post('/api/doctor/update-appointment', async (req, res) => {
    const { appointmentId, prescription, status } = req.body;

    if (!appointmentId || !prescription || !status) {
        return res.status(400).json({ success: false, message: "Appointment ID, prescription, and status are required." });
    }

    try {
        await db.query(
            'UPDATE appointments SET prescription = ?, status = ? WHERE id = ?',
            [prescription, status, appointmentId]
        );

        res.status(200).json({ success: true, message: "Consultation saved and appointment updated successfully!" });
    } catch (error) {
        console.error("Update Appointment Error:", error);
        res.status(500).json({ success: false, message: `Server error: ${error.message}` });
    }
});

app.get('/api/doctor/history', async (req, res) => {
    try {
        const [rows] = await db.query(
            'SELECT * FROM appointments WHERE status IN ("Completed", "Cancelled") ORDER BY created_at DESC'
        );
        res.status(200).json({ success: true, appointments: rows });
    } catch (error) {
        console.error("History Fetch Error:", error);
        res.status(500).json({ success: false, message: `Server error: ${error.message}` });
    }
});

// ==========================================
// NURSE ROUTES
// ==========================================

app.post('/api/nurse/register', registerLimiter, async (req, res) => {
    const { name, email, phone, password } = req.body;

    if (!name || !email || !phone || !password) {
        return res.status(400).json({ success: false, message: "All fields are required." });
    }

    try {
        const [existing] = await db.query("SELECT id FROM nurses WHERE email = ?", [email]);
        if (existing.length > 0) {
            return res.status(400).json({ success: false, message: "Email is already registered." });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        await db.query(
            "INSERT INTO nurses (name, email, phone, password) VALUES (?, ?, ?, ?)",
            [name, email, phone, hashedPassword]
        );

        return res.json({ success: true, message: "Nurse account created successfully!" });
    } catch (error) {
        console.error("Error registering nurse:", error); 
        return res.status(500).json({ success: false, message: `Database error: ${error.message}` });
    }
});

app.post('/api/nurse/login', loginLimiter, async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ success: false, message: "Email and password are required." });
    }

    try {
        const [rows] = await db.query("SELECT * FROM nurses WHERE email = ?", [email]);
        if (rows.length === 0) {
            return res.status(401).json({ success: false, message: "Invalid email or password." });
        }

        const nurse = rows[0];
        const isMatch = await bcrypt.compare(password, nurse.password);
        if (!isMatch) {
            return res.status(401).json({ success: false, message: "Invalid email or password." });
        }

        return res.json({
            success: true,
            nurse: { id: nurse.id, name: nurse.name, email: nurse.email }
        });
    } catch (error) {
        console.error("Error logging in nurse:", error);
        return res.status(500).json({ success: false, message: `Server error: ${error.message}` });
    }
});

app.get('/api/nurse/dashboard/:nurseId', async (req, res) => {
    try {
        const [todayPatients] = await db.query(`
            SELECT a.id AS appointment_id, a.token_number, a.status, a.created_at, a.patient_name AS name, a.age, a.gender, a.symptoms
            FROM appointments a WHERE DATE(a.created_at) = CURDATE() ORDER BY a.token_number ASC
        `);

        const [upcomingPatients] = await db.query(`
            SELECT a.id AS appointment_id, a.token_number, a.status, a.created_at, a.patient_name AS name, a.age, a.gender, a.symptoms
            FROM appointments a WHERE a.status = 'Upcoming' ORDER BY a.created_at ASC
        `);

        return res.json({
            success: true,
            assignedPatientsCount: todayPatients.length,
            vitalsCount: todayPatients.length,
            appointmentsCount: upcomingPatients.length,
            todayPatients,
            upcomingPatients
        });
    } catch (error) {
        console.error("Error fetching nurse dashboard data from DB:", error);
        return res.status(500).json({ success: false, message: `Database query failed: ${error.message}` });
    }
});

app.post('/api/nurse/vitals', async (req, res) => {
    const { patientId, nurseId, temperature, bloodPressure, pulseRate, sp02 } = req.body;

    if (!patientId || !nurseId) {
        return res.status(400).json({ success: false, message: "Patient ID and Nurse ID are required." });
    }

    try {
        await db.query(
            `INSERT INTO patient_vitals (patient_id, nurse_id, temperature, blood_pressure, pulse_rate, sp02) VALUES (?, ?, ?, ?, ?, ?)`,
            [patientId, nurseId, temperature, bloodPressure, pulseRate, sp02]
        );

        res.status(201).json({ success: true, message: "Vitals recorded successfully!" });
    } catch (error) {
        console.error("Vitals Log Error:", error);
        res.status(500).json({ success: false, message: `Database error: ${error.message}` });
    }
});

app.get('/api/nurse/patients-list', async (req, res) => {
    try {
        const [patients] = await db.query('SELECT id, name, email FROM patients ORDER BY name ASC');
        res.status(200).json({ success: true, patients });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.post('/api/nurse/book-appointment', async (req, res) => {
    const { patientId, name, age, gender, bloodGroup, symptoms } = req.body;

    if (!patientId || !name || !age || !symptoms) {
        return res.status(400).json({ success: false, message: "Please fill out all required fields." });
    }

    try {
        const [countRow] = await db.query('SELECT COUNT(*) as count FROM appointments WHERE DATE(created_at) = CURDATE()');
        const tokenNumber = countRow[0].count + 1;

        await db.query(
            `INSERT INTO appointments (patient_id, patient_name, age, gender, blood_group, symptoms, token_number, status) 
             VALUES (?, ?, ?, ?, ?, ?, ?, 'Upcoming')`,
            [patientId, name, age, gender, bloodGroup || 'N/A', symptoms, tokenNumber]
        );

        res.status(201).json({
            success: true,
            message: `Appointment booked successfully! Token #${tokenNumber}`
        });
    } catch (error) {
        console.error("Nurse Booking Error:", error);
        res.status(500).json({ success: false, message: `Server error: ${error.message}` });
    }
});

// ==========================================
// ADMIN AUTHENTICATION
// ==========================================

app.post('/api/admin/login', async (req, res) => {
    const { username, password } = req.body;

    const ADMIN_USER = "admin";
    const ADMIN_PASS = "admin123"; 

    if (username === ADMIN_USER && password === ADMIN_PASS) {
        return res.json({
            success: true,
            admin: { id: 1, username: ADMIN_USER, role: 'Admin' }
        });
    } else {
        return res.status(401).json({
            success: false,
            message: "Invalid admin credentials."
        });
    }
});

// ==========================================
// AI ASSISTANT ROUTE (Google Gen AI SDK)
// ==========================================
const { GoogleGenAI } = require('@google/genai');

const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY || 'AQ.Ab8RN6JIO6SJbj_-Oxm4UPBd98RIJOnQCaelZhxJOcBjIr6Y0A' });

app.post('/api/ai/assistant', async (req, res) => {
    const { task, message } = req.body;

    try {
        let systemPrompt = "You are a helpful AI Assistant for a Hospital Management and SOC Security Platform.";

        switch (task) {
            case 'TRIAGE':
                systemPrompt = "You are a Hospital Triage Specialist. Analyze user symptoms and suggest the appropriate department (e.g., Cardiology, General Medicine, Neurology) and severity level (Low, Medium, High, Emergency). Include a concise medical disclaimer.";
                break;
            case 'SECURITY':
                systemPrompt = "You are a Cyber Security SOC Specialist. Analyze the provided query/incident and explain potential risks or recommended mitigation steps in simple terms.";
                break;
            case 'MEDICATION':
                systemPrompt = "You are a Pharmacy Advisory Assistant. Explain medication uses, general safety considerations, and common interactions concisely.";
                break;
            case 'APPOINTMENT':
                systemPrompt = "You are a Hospital Operations Assistant. Guide the user on how to prepare for tests, scans, or consultations.";
                break;
            case 'POLICY':
                systemPrompt = "You are a Hospital Information Desk Assistant. Answer questions regarding hospital policies, visiting hours, and patient care procedures.";
                break;
            case 'TRANSLATE_TERMS':
                systemPrompt = "You are a Medical Communicator. Translate complex medical jargon into easy-to-understand language for patients.";
                break;
            case 'METRICS_EXPLAINER':
                systemPrompt = "You are a Security Systems Operations Analyst. Explain what various security metrics, audit log flags, and threat categories mean.";
                break;
            default:
                systemPrompt = "You are an AI Copilot for the Hospital Management and Security Operations system.";
        }

        const response = await ai.models.generateContent({
            model: 'gemini-2.5-flash',
            contents: `${systemPrompt}\n\nUser Request: ${message}`
        });

        res.json({ success: true, reply: response.text });
    } catch (err) {
        console.error("AI Error:", err);
        res.status(500).json({ success: false, message: "AI Copilot unavailable." });
    }
});

// Port configuration for Cloud Deployment
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});