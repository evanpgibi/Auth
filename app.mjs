import express from 'express';
import path from 'path';
import { MongoClient } from 'mongodb';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import 'dotenv/config';
import cors from 'cors';

const app = express();
const PORT = process.env.PORT || 3000;

// MongoDB setup
const client = new MongoClient(process.env.MONGO_URL);
await client.connect();
const db = client.db('auth');
const usersCollection = db.collection('users');
await usersCollection.createIndex({ username: 1 }, { unique: true });

const JWT_SECRET = process.env.JWT_SECRET;

app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cors({ origin: /localhost/, credentials: true }));

// Serve static HTML pages
app.use('/pages', express.static(path.join(path.resolve(), 'pages')));

// Input validation helper
function validateUserInput(username, password) {
    if (!username || !password) return false;
    if (typeof username !== 'string' || typeof password !== 'string') return false;
    if (username.length < 3 || password.length < 6) return false;
    return true;
}

// Signup route
app.post('/signup', async (req, res) => {
    const { username, password } = req.body;
    if (!validateUserInput(username, password)) {
        return res.status(400).send('Invalid username or password (min 3/6 chars)');
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await usersCollection.insertOne({ username, password: hashedPassword });
        res.redirect('/pages/login.html');
    } catch (err) {
        if (err.code === 11000) {
            res.status(409).send('User already exists');
        } else {
            res.status(500).send('Server error');
        }
    }
});

// Login route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!validateUserInput(username, password)) {
        return res.status(400).send('Invalid username or password');
    }
    try {
        const user = await usersCollection.findOne({ username });
        if (!user) return res.status(401).send('Invalid credentials');
        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(401).send('Invalid credentials');
        const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 60 * 60 * 1000
        });
        res.redirect('/dashboard');
    } catch (err) {
        res.status(500).send('Server error');
    }
});

// Middleware to verify JWT
function authenticateToken(req, res, next) {
    const token = req.cookies?.token || req.headers['authorization']?.split(' ')[1];
    if (!token) {
        return res.redirect('/pages/login.html');
    }
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.redirect('/pages/login.html');
        req.user = user;
        next();
    });
}

// Dashboard route (protected)
app.get('/dashboard', authenticateToken, (req, res) => {
    res.sendFile(path.join(path.resolve(), 'pages', 'dashboard.html'));
});

// Logout route
app.get('/logout', (req, res) => {
    res.clearCookie('token', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
    });
    res.redirect('/pages/login.html');
});

// Default route
app.get('/', (req, res) => {
    res.redirect('/pages/index.html');
});

// Enforce HTTPS in production
if (process.env.NODE_ENV === 'production') {
    app.use((req, res, next) => {
        if (req.headers['x-forwarded-proto'] !== 'https') {
            return res.redirect('https://' + req.headers.host + req.url);
        }
        next();
    });
}

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

export default app;
