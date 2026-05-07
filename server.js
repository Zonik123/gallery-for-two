const express = require('express');
const multer = require('multer');
const sqlite3 = require('sqlite3').verbose();
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
    db.run(`CREATE TABLE IF NOT EXISTS photos (id INTEGER PRIMARY KEY AUTOINCREMENT, album_id INTEGER, filename TEXT, original_name TEXT, uploaded_by TEXT, caption TEXT, timestamp INTEGER)`);
    db.run(`CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY AUTOINCREMENT, photo_id INTEGER, username TEXT, text TEXT, timestamp INTEGER)`);
    db.run(`CREATE TABLE IF NOT EXISTS likes (id INTEGER PRIMARY KEY AUTOINCREMENT, photo_id INTEGER, username TEXT, UNIQUE(photo_id, username))`);

    db.run(`INSERT OR IGNORE INTO users (id, username, password) VALUES (1, 'Danya', 'pass250')`);
    db.run(`INSERT OR IGNORE INTO users (id, username, password) VALUES (2, 'Nastunya', 'pass324')`);
});

app.use(express.json());
app.use(express.static('public'));
app.use(session({ secret: 'gallery_secret', resave: false, saveUninitialized: false, cookie: { maxAge: 24 * 60 * 60 * 1000 } }));

function auth(req, res, next) {
    if (req.session.userId) next();
    else res.status(401).json({ error: 'Не авторизован' });
}

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get('SELECT * FROM users WHERE username = ? AND password = ?', [username, password], (err, user) => {
        if (user) {
            req.session.userId = user.id;
            req.session.username = user.username;
            res.json({ success: true, username: user.username });
        } else {
            res.status(401).json({ error: 'Неверный логин или пароль' });
        }
    });
});

app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ success: true }); });
app.get('/api/me', (req, res) => { if (req.session.userId) res.json({ username: req.session.username }); else res.status(401).json({ error: 'Не авторизован' }); });

// Albums CRUD
app.get('/api/albums', auth, (req, res) => { db.all('SELECT * FROM albums ORDER BY created_at DESC', (err, albums) => res.json(albums || [])); });
app.post('/api/albums', auth, (req, res) => { db.run('INSERT INTO albums (name, created_at) VALUES (?, ?)', [req.body.name, Date.now()], function(err) { res.json({ id: this.lastID, name: req.body.name, created_at: Date.now() }); }); });
app.put('/api/albums/:id', auth, (req, res) => { db.run('UPDATE albums SET name = ? WHERE id = ?', [req.body.name, req.params.id], () => res.json({ success: true })); });
app.delete('/api/albums/:id', auth, (req, res) => {
    db.all('SELECT filename FROM photos WHERE album_id = ?', [req.params.id], (err, photos) => {
        if (photos) photos.forEach(photo => { const filepath = path.join(uploadDir, photo.filename); if (fs.existsSync(filepath)) fs.unlinkSync(filepath); });
        db.run('DELETE FROM comments WHERE photo_id IN (SELECT id FROM photos WHERE album_id = ?)', [req.params.id]);
        db.run('DELETE FROM likes WHERE photo_id IN (SELECT id FROM photos WHERE album_id = ?)', [req.params.id]);
        db.run('DELETE FROM photos WHERE album_id = ?', [req.params.id]);
        db.run('DELETE FROM albums WHERE id = ?', [req.params.id], () => res.json({ success: true }));
    });
});

// Photos
app.get('/api/photos/:albumId', auth, (req, res) => { db.all('SELECT * FROM photos WHERE album_id = ? ORDER BY timestamp DESC', [req.params.albumId], (err, photos) => res.json(photos || [])); });
app.post('/api/upload/:albumId', auth, upload.array('photos', 20), (req, res) => {
    const files = req.files;
    let captions = [];
    try { captions = JSON.parse(req.body.captions || '[]'); } catch(e) {}
    let count = 0;
    files.forEach((file, idx) => {
        db.run(`INSERT INTO photos (album_id, filename, original_name, uploaded_by, caption, timestamp) VALUES (?, ?, ?, ?, ?, ?)`, [req.params.albumId, file.filename, file.originalname, req.session.username, captions[idx] || '', Date.now()], () => { count++; if (count === files.length) res.json({ success: true, count }); });
    });
});
app.delete('/api/photo/:photoId', auth, (req, res) => { db.get('SELECT filename FROM photos WHERE id = ?', [req.params.photoId], (err, photo) => { if (photo) { const filepath = path.join(uploadDir, photo.filename); if (fs.existsSync(filepath)) fs.unlinkSync(filepath); } db.run('DELETE FROM photos WHERE id = ?', [req.params.photoId]); db.run('DELETE FROM comments WHERE photo_id = ?', [req.params.photoId]); db.run('DELETE FROM likes WHERE photo_id = ?', [req.params.photoId]); res.json({ success: true }); }); });
app.get('/uploads/:filename', auth, (req, res) => { res.sendFile(path.join(uploadDir, req.params.filename)); });

// Comments
app.get('/api/comments/:photoId', auth, (req, res) => { db.all('SELECT * FROM comments WHERE photo_id = ? ORDER BY timestamp ASC', [req.params.photoId], (err, comments) => res.json(comments || [])); });
app.post('/api/comments', auth, (req, res) => { db.run('INSERT INTO comments (photo_id, username, text, timestamp) VALUES (?, ?, ?, ?)', [req.body.photo_id, req.session.username, req.body.text, Date.now()], function(err) { res.json({ id: this.lastID, username: req.session.username, text: req.body.text, timestamp: Date.now() }); }); });

// Likes
app.get('/api/likes/:photoId', auth, (req, res) => { db.get('SELECT COUNT(*) as count FROM likes WHERE photo_id = ?', [req.params.photoId], (err, result) => { db.get('SELECT COUNT(*) as user_liked FROM likes WHERE photo_id = ? AND username = ?', [req.params.photoId, req.session.username], (err, liked) => { res.json({ count: result ? result.count : 0, userLiked: liked ? liked.user_liked > 0 : false }); }); }); });
app.post('/api/likes', auth, (req, res) => { db.run('INSERT OR IGNORE INTO likes (photo_id, username) VALUES (?, ?)', [req.body.photo_id, req.session.username], () => res.json({ success: true })); });
app.delete('/api/likes', auth, (req, res) => { db.run('DELETE FROM likes WHERE photo_id = ? AND username = ?', [req.body.photo_id, req.session.username], () => res.json({ success: true })); });

// Notifications
let clients = [];
app.get('/api/notifications/stream', auth, (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    clients.push({ res, username: req.session.username });
    req.on('close', () => { clients = clients.filter(c => c.res !== res); });
});

function notifyNewPhoto(photoData, uploader) {
    clients.forEach(client => { if (client.username !== uploader) client.res.write(`data: ${JSON.stringify(photoData)}\n\n`); });
}

// Override upload to send notifications
const originalUpload = app.post('/api/upload/:albumId', auth, upload.array('photos', 20), (req, res) => {
    const files = req.files;
    let captions = [];
    try { captions = JSON.parse(req.body.captions || '[]'); } catch(e) {}
    let count = 0;
    files.forEach((file, idx) => {
        db.run(`INSERT INTO photos (album_id, filename, original_name, uploaded_by, caption, timestamp) VALUES (?, ?, ?, ?, ?, ?)`, [req.params.albumId, file.filename, file.originalname, req.session.username, captions[idx] || '', Date.now()], function(err) {
            if (!err) notifyNewPhoto({ photoId: this.lastID, uploaded_by: req.session.username }, req.session.username);
            count++; if (count === files.length) res.json({ success: true, count });
        });
    });
});

app.listen(PORT, () => console.log(`✅ Сервер запущен на порту ${PORT}`));
