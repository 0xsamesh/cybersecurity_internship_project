const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const validator = require('validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const winston = require('winston');

const app = express();
const db = new sqlite3.Database(':memory:');
const JWT_SECRET = 'cybersecurity-intern-secret-key';

// PHASE 3: Added Winston Application Logging
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(({ timestamp, level, message }) => {
            return `[${timestamp}] ${level.toUpperCase()}: ${message}`;
        })
    ),
    transports: [
        new winston.transports.Console(),
        // Drops logs to physical file per assignment instructions
        new winston.transports.File({ filename: 'security.log' })
    ]
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(helmet());

logger.info('Secure Web Application Started. Helmet HTTP middleware activated.');

// Initialize database
db.serialize(() => {
    db.run("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT, profile_bio TEXT)");
    bcrypt.hash('supersecretpassword123!', 10, (err, hash) => {
        db.run("INSERT INTO users (username, password, profile_bio) VALUES (?, ?, ?)", ['admin', hash, 'I am the admin of this system.']);
        logger.info('Admin user seeded into SQLite Database'); // Using Winston here
    });
});

app.get('/', (req, res) => res.redirect('/login'));

// --- SIGNUP ---
app.get('/signup', (req, res) => {
    res.send(`
        <h1>Signup</h1>
        <form method="POST" action="/signup">
            <input type="text" name="username" placeholder="Username" required /><br/>
            <input type="password" name="password" placeholder="Password" required /><br/>
            <button type="submit">Signup</button>
        </form>
        <br/><a href="/login">Already have an account? Login here</a>
    `);
});

app.post('/signup', async (req, res) => {
    let { username, password } = req.body;

    if (!username || !password) return res.send('<h3>Please fill all fields.</h3>');
    username = validator.escape(username.trim());

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run('INSERT INTO users (username, password, profile_bio) VALUES (?, ?, ?)', [username, hashedPassword, "New user"], (err) => {
            if (err) {
                logger.error(`Signup failed for user: ${username}`);
                return res.send('<h3>Error creating user</h3>');
            }
            logger.info(`New user registered securely: ${username}`); // Log secure registration
            res.send('<h3>User created successfully! <a href="/login">Login here</a></h3>');
        });
    } catch (err) {
        logger.error(`Server error during signup serialization`);
        res.send('<h3>Server error.</h3>');
    }
});

// --- LOGIN ---
app.get('/login', (req, res) => {
    res.send(`
        <h1>Login</h1>
        <p style="color:red;">${validator.escape(req.query.error || '')}</p>
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="Username" required /><br/>
            <input type="password" name="password" placeholder="Password" required /><br/>
            <button type="submit">Login</button>
        </form>
        <br/><a href="/signup">Don't have an account? Signup here</a>
    `);
});

app.post('/login', (req, res) => {
    let { username, password } = req.body;
    if (!username || !password) return res.redirect('/login?error=Missing credentials');

    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, row) => {
        if (err || !row) {
            logger.warn(`Failed login attempt (Invalid Username) for: ${username}`); // Security Log
            return res.redirect('/login?error=Invalid credentials');
        }

        const passwordMatch = await bcrypt.compare(password, row.password);
        if (!passwordMatch) {
            logger.warn(`Failed login attempt (Invalid Password) for: ${username}`); // Security Log
            return res.redirect('/login?error=Invalid credentials');
        }

        const token = jwt.sign({ id: row.id, username: row.username }, JWT_SECRET, { expiresIn: '1h' });

        logger.info(`Successful login for user: ${username}. JWT Issued.`); // Security Log
        res.cookie('auth_token', token, { httpOnly: true });
        res.redirect('/profile');
    });
});

app.post('/api/login', (req, res) => {
    let { username, password } = req.body;
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, row) => {
        if (err || !row) return res.status(401).send('Invalid');
        const match = await bcrypt.compare(password, row.password);
        if (!match) return res.status(401).send('Invalid');

        logger.info(`API Token issued for: ${username}`);
        res.send({ token: jwt.sign({ id: row.id }, JWT_SECRET) });
    });
});

const requireAuth = (req, res, next) => {
    const cookieHeader = req.headers.cookie;
    if (!cookieHeader) return res.redirect('/login?error=Please login first');

    const tokenCookie = cookieHeader.split(';').find(c => c.trim().startsWith('auth_token='));
    if (!tokenCookie) return res.redirect('/login?error=Please login first');

    const token = tokenCookie.split('=')[1];

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            logger.warn(`Unauthorized access attempt denied automatically by JWT Validator`);
            return res.redirect('/login?error=Session expired');
        }
        req.user = decoded;
        next();
    });
};

// --- PROFILE ---
app.get('/profile', requireAuth, (req, res) => {
    db.get('SELECT * FROM users WHERE id = ?', [req.user.id], (err, row) => {
        if (!row) return res.redirect('/login');

        const safeBio = validator.escape(row.profile_bio || '');
        const safeUsername = validator.escape(row.username || '');

        res.send(`
            <h1>Welcome, ${safeUsername}!</h1>
            <h3>Your Profile Bio (Secured):</h3>
            <div style="border: 2px solid green; padding: 10px;">
                ${safeBio}
            </div>
            
            <hr/>
            <h3>Update Profile:</h3>
            <form method="POST" action="/profile">
                <textarea name="bio" rows="4" cols="50" placeholder="Type your bio..."></textarea><br/>
                <button type="submit">Update</button>
            </form>
            <br/>
            <a href="#" onclick="document.cookie='auth_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;'; window.location='/login';">Logout</a>
        `);
    });
});

app.post('/profile', requireAuth, (req, res) => {
    let { bio } = req.body;

    const sanitizedBio = validator.escape(bio || '');

    db.run('UPDATE users SET profile_bio = ? WHERE id = ?', [sanitizedBio, req.user.id], (err) => {
        logger.info(`User [ID: ${req.user.id}] updated their bio securely.`); // Data alteration log
        res.redirect('/profile');
    });
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`SECURE App running with Winston tracking on http://localhost:${PORT}`);
});
