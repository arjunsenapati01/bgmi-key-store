const express = require('express');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const path = require('path');
const { sequelize, User, SerialKey, Purchase } = require('./models');

const app = express();

// Constants
const KEY_CATEGORIES = ['Lethal', 'Win iOS', 'Vision'];
const KEY_DURATIONS = {
    '1_day': { name: '1 Day', days: 1 },
    '7_days': { name: '7 Days', days: 7 },
    '30_days': { name: '30 Days', days: 30 }
};

// Middleware
app.set('view engine', 'ejs');
app.use(express.static('static'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: 'your-secret-key-here',
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

// Passport configuration
passport.use(new LocalStrategy(async (username, password, done) => {
    try {
        const user = await User.findOne({ where: { username } });
        if (!user) return done(null, false);
        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) return done(null, false);
        return done(null, user);
    } catch (err) {
        return done(err);
    }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findByPk(id);
        done(null, user);
    } catch (err) {
        done(err);
    }
});

// Authentication middleware
const isAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) return next();
    res.redirect('/login');
};

const isAdmin = (req, res, next) => {
    if (req.isAuthenticated() && req.user.isAdmin) return next();
    res.status(403).json({ error: 'Unauthorized' });
};

// Routes
app.get('/', (req, res) => {
    res.render('index', { user: req.user });
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/login'
}));

app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        const existingUser = await User.findOne({ where: { username } });
        
        if (existingUser) {
            return res.redirect('/register');
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        await User.create({
            username,
            password: hashedPassword
        });
        
        res.redirect('/login');
    } catch (err) {
        res.redirect('/register');
    }
});

app.get('/dashboard', isAuthenticated, async (req, res) => {
    try {
        if (req.user.isAdmin) {
            const keys = await SerialKey.findAll();
            res.render('admin_dashboard', {
                keys,
                categories: KEY_CATEGORIES,
                durations: KEY_DURATIONS
            });
        } else {
            const categories = {};
            for (const category of KEY_CATEGORIES) {
                categories[category] = {};
                for (const [durationKey, durationInfo] of Object.entries(KEY_DURATIONS)) {
                    const keys = await SerialKey.findAll({
                        where: {
                            category,
                            duration: durationKey,
                            isUsed: false
                        }
                    });
                    categories[category][durationKey] = keys;
                }
            }

            const purchasedKeys = await SerialKey.findAll({
                include: [{
                    model: Purchase,
                    where: { UserId: req.user.id }
                }],
                order: [[Purchase, 'purchaseDate', 'DESC']]
            });

            res.render('user_dashboard', {
                categories,
                durations: KEY_DURATIONS,
                purchased_keys: purchasedKeys
            });
        }
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/admin/add_key', isAdmin, async (req, res) => {
    try {
        const { key, price, category, duration } = req.body;
        
        if (key.length > 50) {
            return res.status(400).json({ error: 'Key too long' });
        }
        
        if (!KEY_CATEGORIES.includes(category)) {
            return res.status(400).json({ error: 'Invalid category' });
        }
        
        if (!KEY_DURATIONS[duration]) {
            return res.status(400).json({ error: 'Invalid duration' });
        }
        
        await SerialKey.create({
            key,
            price: parseFloat(price),
            category,
            duration
        });
        
        res.json({ message: 'Key added successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/admin/add_bulk_keys', isAdmin, async (req, res) => {
    try {
        const { keys, price, category, duration } = req.body;
        
        if (!KEY_CATEGORIES.includes(category)) {
            return res.status(400).json({ error: 'Invalid category' });
        }
        
        if (!KEY_DURATIONS[duration]) {
            return res.status(400).json({ error: 'Invalid duration' });
        }
        
        const keysList = keys.split('\n').map(k => k.trim()).filter(k => k && k.length <= 50);
        
        await Promise.all(keysList.map(key => 
            SerialKey.create({
                key,
                price: parseFloat(price),
                category,
                duration
            })
        ));
        
        res.json({ message: `Added ${keysList.length} keys successfully` });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/buy/:keyId', isAuthenticated, async (req, res) => {
    try {
        const serialKey = await SerialKey.findByPk(req.params.keyId);
        
        if (!serialKey || serialKey.isUsed) {
            return res.status(400).json({ error: 'Key already used' });
        }
        
        await Purchase.create({
            UserId: req.user.id,
            SerialKeyId: serialKey.id
        });
        
        serialKey.isUsed = true;
        await serialKey.save();
        
        res.json({
            message: 'Purchase successful',
            key: serialKey.key,
            category: serialKey.category,
            duration: KEY_DURATIONS[serialKey.duration].name
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/logout', (req, res) => {
    req.logout(() => {
        res.redirect('/');
    });
});

// Initialize database and start server
(async () => {
    try {
        await sequelize.sync();
        
        // Create admin user if not exists
        const adminUser = await User.findOne({ where: { username: 'admin' } });
        if (!adminUser) {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            await User.create({
                username: 'admin',
                password: hashedPassword,
                isAdmin: true
            });
        }
        
        app.listen(5000, 'localhost', () => {
            console.log('Server running on http://localhost:5000');
        });
    } catch (err) {
        console.error('Failed to start server:', err);
    }
})(); 