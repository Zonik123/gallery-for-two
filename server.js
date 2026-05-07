const express = require('express');
const multer = require('multer');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

const uploadDir = path.join('/tmp', 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => {
        const unique = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, unique + path.extname(file.originalname));
    }
});
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } });

const db = new sqlite3.Database('/tmp/gallery.db');

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS albums (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, created_at INTEGER)`);
    db.run(`CREATE TABLE IF NOT EXISTS photos (id INTEGER PRIMARY KEY AUTOINCREMENT, album_id INTEGER, filename TEXT, original_name TEXT, uploaded_by TEXT, timestamp INTEGER)`);

    const users = [
        { username: 'user1', password: 'pass123' },
        { username: 'user2', password: 'pass456' }
    ];
    users.forEach(user => {
        db.get('SELECT id FROM users WHERE username = ?', [user.username], (err, row) => {
            if (!row) {
                bcrypt.hash(user.password, 10, (err, hash) => {
                    if (!err) db.run('INSERT INTO users (username, password) VALUES (?, ?)', [user.username, hash]);
                });
            }
        });
    });
});

app.use(express.json());
app.use(express.static('public'));
app.use(session({
    secret: 'gallery_secret_key_for_two',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 * 24 }
}));

function auth(req, res, next) {
    if (req.session.userId) next();
    else res.status(401).json({ error: 'Не авторизован' });
}

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (!user) return res.status(401).json({ error: 'Неверный логин или пароль' });
        bcrypt.compare(password, user.password, (err, result) => {
            if (result) {
                req.session.userId = user.id;
                req.session.username = user.username;
                res.json({ success: true, username: user.username });
            } else res.status(401).json({ error: 'Неверный логин или пароль' });
        });
    });
});

app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ success: true }); });

app.get('/api/me', (req, res) => {
    if (req.session.userId) res.json({ username: req.session.username });
    else res.status(401).json({ error: 'Не авторизован' });
});

app.get('/api/albums', auth, (req, res) => {
    db.all('SELECT * FROM albums ORDER BY created_at DESC', (err, albums) => res.json(albums));
});

app.post('/api/albums', auth, (req, res) => {
    const { name } = req.body;
    db.run('INSERT INTO albums (name, created_at) VALUES (?, ?)', [name, Date.now()], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id: this.lastID, name, created_at: Date.now() });
    });
});

app.get('/api/photos/:albumId', auth, (req, res) => {
    db.all('SELECT * FROM photos WHERE album_id = ? ORDER BY timestamp DESC', [req.params.albumId], (err, photos) => res.json(photos));
});

app.post('/api/upload/:albumId', auth, upload.array('photos', 20), (req, res) => {
    const files = req.files;
    if (!files || files.length === 0) return res.status(400).json({ error: 'Нет файлов' });
    let count = 0;
    files.forEach(file => {
        db.run(`INSERT INTO photos (album_id, filename, original_name, uploaded_by, timestamp) VALUES (?, ?, ?, ?, ?)`,
            [req.params.albumId, file.filename, file.originalname, req.session.username, Date.now()],
            (err) => { if (!err) count++; if (count === files.length) res.json({ success: true, count }); });
    });
});

app.delete('/api/photo/:photoId', auth, (req, res) => {
    db.get('SELECT filename FROM photos WHERE id = ?', [req.params.photoId], (err, photo) => {
        if (photo) {
            const filepath = path.join(uploadDir, photo.filename);
            if (fs.existsSync(filepath)) fs.unlinkSync(filepath);
            db.run('DELETE FROM photos WHERE id = ?', [req.params.photoId]);
        }
        res.json({ success: true });
    });
});

app.get('/uploads/:filename', auth, (req, res) => {
    res.sendFile(path.join(uploadDir, req.params.filename));
});

app.listen(PORT, () => console.log(`✅ Сервер запущен на порту ${PORT}`));
