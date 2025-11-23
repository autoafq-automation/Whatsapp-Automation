const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { Client, LocalAuth, MessageMedia } = require('whatsapp-web.js');
const qrcode = require('qrcode');
const multer = require('multer');
const csv = require('csv-parser');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const SECRET_KEY = 'your-secret-key-change-this'; // In production, use environment variable

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const upload = multer({ dest: 'uploads/' });

const DB_FILE = 'leads_db.json';
const USERS_FILE = 'users.json';

app.use(express.static('public'));
app.use(express.json());

// --- Database Helper Functions ---
function loadDB() {
    if (!fs.existsSync(DB_FILE)) {
        return {};
    }
    try {
        return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    } catch (err) {
        console.error("Error reading DB:", err);
        return {};
    }
}

function saveDB(data) {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

function updateLeadState(phone, state, extraData = {}) {
    const db = loadDB();
    // Normalize phone to just digits for key
    const key = phone.replace(/\D/g, '');

    if (!db[key]) {
        db[key] = { phone: key, history: [] };
    }

    db[key].state = state;
    Object.assign(db[key], extraData);
    db[key].lastUpdated = new Date().toISOString();

    saveDB(db);
    io.emit('log', `[DB] Updated ${key} to state: ${state}`);
}

function getLead(phone) {
    const db = loadDB();
    const key = phone.replace(/\D/g, '');
    return db[key];
}



// --- User Helper Functions ---
function loadUsers() {
    if (!fs.existsSync(USERS_FILE)) {
        return {};
    }
    try {
        return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    } catch (err) {
        console.error("Error reading Users DB:", err);
        return {};
    }
}

function saveUsers(data) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(data, null, 2));
}

// --- Auth Middleware ---
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.sendStatus(401);

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}
const client = new Client({
    authStrategy: new LocalAuth(),
    puppeteer: {
        args: ['--no-sandbox', '--disable-setuid-sandbox'],
    }
});

let isClientReady = false;

client.on('qr', (qr) => {
    qrcode.toDataURL(qr, (err, url) => {
        if (err) {
            console.error('Error generating QR code', err);
            return;
        }
        io.emit('qr', url);
        io.emit('log', 'QR Code received. Please scan with WhatsApp.');
    });
});

client.on('ready', () => {
    isClientReady = true;
    io.emit('ready', true);
    io.emit('log', 'WhatsApp Client is ready!');
    console.log('Client is ready!');
});

client.on('authenticated', () => {
    io.emit('log', 'Authenticated successfully!');
    io.emit('qr', null);
});

client.on('disconnected', (reason) => {
    io.emit('log', `Client was disconnected: ${reason}`);
    isClientReady = false;
    client.initialize();
});

client.on('auth_failure', (msg) => {
    io.emit('log', `Authentication failure: ${msg}`);
});

client.on('message', async msg => {
    const contact = await msg.getContact();
    const name = contact.pushname || contact.number;
    const phone = contact.number; // e.g., "1234567890"
    const messageBody = msg.body.toLowerCase();

    io.emit('log', `Received message from ${name} (${phone}): ${msg.body}`);

    // Check if this is a lead we are tracking
    const lead = getLead(phone);

    if (lead && lead.state === 'CONTACTED') {
        // Check for "YES" (case-insensitive)
        const isInterested = messageBody.includes('yes');

        if (isInterested) {
            io.emit('log', `*** LEAD INTERESTED: ${name} ***`);
            updateLeadState(phone, 'INTERESTED');

            // Trigger the "ROI" sequence
            await sendROIMessage(msg.from, name, phone);
        }
    }
});

async function sendROIMessage(chatId, name, phone) {
    io.emit('log', `Sending ROI Message to ${name}...`);

    const roiMessage = `Perfect.
Let’s look at the ROI in a practical and realistic way, based on what we see across clinics in the region:

Most clinics today lose 20%–30% of their booking opportunities without realizing it.
Not because the staff is bad — but simply because patients expect instant replies, and if the clinic is busy, even a 3–5 minute delay is enough for the patient to message another doctor.

Here’s what that actually means financially:

When a clinic receives around 60–120 inquiries per week across WhatsApp, calls, and Instagram…
On average:

• 12–36 patients per week go unanswered or delayed
• That’s 48–144 lost bookings per month
• If the average treatment value is just $80–$250, the clinic is losing between:
$4,000 – $20,000+ per month
without noticing

And this is the baseline.
Dermatology and dental clinics often lose even more because their case values are higher.

Our AI receptionist stops this leak at the source.

It replies in 3 seconds — literally faster than any human — captures every patient, sends answers instantly, books appointments automatically, follows up with patients who don’t reply, and keeps your entire patient pipeline alive 24/7 in Arabic + English.

Clinics using it typically see:

• A 15%–40% increase in monthly bookings
• A dramatic drop in no-shows
• Higher conversion because patients get immediate attention
• And full visibility over all leads instead of relying on a busy receptionist

If you’d like, I can calculate the exact ROI for your clinic based on two numbers:
your specialty + how many new inquiries you usually get per week.

Customize this system for you gonna take less than 48 h if you are interested.
I will be happy to work with you if you are interested.`;

    try {
        await client.sendMessage(chatId, roiMessage);
        io.emit('log', `Sent ROI text to ${name}`);
        updateLeadState(phone, 'INFO_SENT');
    } catch (err) {
        io.emit('log', `Failed to send text: ${err.message}`);
    }
}

client.initialize();

// ... existing code ...

// --- API Routes ---

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).send('Username and password required');
    }

    const users = loadUsers();
    if (users[username]) {
        return res.status(400).send('User already exists');
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        users[username] = { password: hashedPassword };
        saveUsers(users);
        res.status(201).send('User registered');
    } catch (err) {
        res.status(500).send('Error registering user');
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    const users = loadUsers();
    const user = users[username];

    if (user == null) {
        return res.status(400).send('Cannot find user');
    }

    try {
        if (await bcrypt.compare(password, user.password)) {
            const accessToken = jwt.sign({ name: username }, SECRET_KEY);
            res.json({ accessToken: accessToken });
        } else {
            res.send('Not Allowed');
        }
    } catch (err) {
        res.status(500).send();
    }
});

app.get('/api/stats', authenticateToken, (req, res) => {
    const db = loadDB();
    const stats = {
        total: Object.keys(db).length,
        contacted: 0,
        interested: 0,
        infoSent: 0
    };

    Object.values(db).forEach(lead => {
        if (lead.state === 'CONTACTED') stats.contacted++;
        if (lead.state === 'INTERESTED') stats.interested++;
        if (lead.state === 'INFO_SENT') stats.infoSent++;
    });

    res.json(stats);
});

app.get('/api/export-interested', authenticateToken, (req, res) => {
    const db = loadDB();
    const interestedLeads = Object.values(db).filter(lead =>
        lead.state === 'INTERESTED' || lead.state === 'INFO_SENT'
    );

    const fields = ['phone', 'name', 'state', 'lastUpdated'];
    const json2csvParser = new (require('json2csv').Parser)({ fields });
    const csvData = json2csvParser.parse(interestedLeads);

    res.header('Content-Type', 'text/csv');
    res.attachment('interested_leads.csv');
    res.send(csvData);
});

app.post('/api/start-campaign', authenticateToken, upload.single('leads'), (req, res) => {
    // ... existing code ...
    if (!req.file) {
        return res.status(400).json({ error: 'No CSV file uploaded' });
    }

    if (!isClientReady) {
        return res.status(400).json({ error: 'WhatsApp client is not ready.' });
    }

    const results = [];
    fs.createReadStream(req.file.path)
        .pipe(csv())
        .on('data', (data) => results.push(data))
        .on('end', () => {
            processLeads(results);
            res.json({ message: `Campaign started with ${results.length} leads.` });
            fs.unlinkSync(req.file.path);
        });
});

async function processLeads(leads) {
    io.emit('log', `Starting campaign for ${leads.length} leads...`);

    for (const lead of leads) {
        let name = lead.Name || lead.name || 'there';
        let phone = lead.Phone || lead.phone;

        if (!phone) continue;

        let cleanPhone = phone.replace(/\D/g, '');

        // Skip if already contacted (check DB)
        const existingLead = getLead(cleanPhone);
        if (existingLead && (existingLead.state === 'CONTACTED' || existingLead.state === 'INTERESTED' || existingLead.state === 'INFO_SENT')) {
            io.emit('log', `Skipping ${name} (${cleanPhone}) - Already contacted.`);
            continue;
        }

        const chatId = `${cleanPhone}@c.us`;

        // The "Hook" Message
        const message = `Hi ${name}

Most clinics lose a large part of their booking opportunities simply because patients don’t get fast replies.
People message on WhatsApp, call, or send inquiries — and if the clinic is busy, even a small delay means the patient goes to another doctor.

Our system fixes this completely.

We built an AI receptionist that replies in 3 seconds, handles all patient communication across WhatsApp, calls, Instagram, and SMS, in Arabic and English.
It answers questions, books appointments instantly, follows up automatically, and keeps every patient engaged — 24/7.

Clinics using it usually see an immediate increase in bookings because they stop losing leads during rush hours and peak days.

If you’d like, I can show you how this would work for your clinic.
And if you want to know the ROI or the financial benefits your clinic could get from it, just reply YES.`;

        try {
            await client.sendMessage(chatId, message);
            io.emit('log', `Sent HOOK to ${name} (${cleanPhone})`);
            updateLeadState(cleanPhone, 'CONTACTED', { name: name });
        } catch (err) {
            io.emit('log', `Failed to send to ${name}: ${err.message}`);
        }

        const delay = 5000; // 5 seconds
        io.emit('log', `Waiting ${delay / 1000} seconds...`);
        await new Promise(resolve => setTimeout(resolve, delay));
    }

    io.emit('log', 'Campaign batch finished!');
}

const PORT = process.env.PORT || 3000;

// Only listen if run directly (not imported)
if (require.main === module) {
    server.listen(PORT, () => {
        console.log(`Server running on http://localhost:${PORT}`);
    });
}

module.exports = app;

