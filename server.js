const express = require('express');
const multer = require('multer');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Папка для загрузок
const uploadDir = path.join('/tmp', 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

// Хранилище для файлов
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => {
        const unique = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, unique + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage, 
    limits: { fileSize: 10 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowed = ['image/jpeg', 'image/png', 'image/webp', 'image/jpg'];
        if (allowed.includes(file.mimetype)) cb(null, true);
        else cb(new Error('Только фото (jpg, png, webp)'));
    }
});

// База данных
const db = new sqlite3.Database('/tmp/gallery.db');

// Создание таблиц
db.serialize(() => {
    // Пользователи
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        failed_attempts INTEGER DEFAULT 0,
        locked_until INTEGER DEFAULT 0
    )`);
    
    // Альбомы
    db.run(`CREATE TABLE IF NOT EXISTS albums (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        created_at INTEGER
    )`);
    
    // Фото
    db.run(`CREATE TABLE IF NOT EXISTS photos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        album_id INTEGER,
        filename TEXT,
        original_name TEXT,
        uploaded_by TEXT,
        timestamp INTEGER
    )`);
    
    // Комментарии
    db.run(`CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        photo_id INTEGER,
        username TEXT,
        text TEXT,
        timestamp INTEGER
    )`);
    
    // Лайки
    db.run(`CREATE TABLE IF NOT EXISTS likes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        photo_id INTEGER,
        username TEXT,
        UNIQUE(photo_id, username)
    )`);
    
    // Логи попыток входа
    db.run(`CREATE TABLE IF NOT EXISTS login_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        success INTEGER,
        ip TEXT,
        timestamp INTEGER
    )`);
    
    // Добавляем пользователей с хешированными паролями
    const users = [
        { username: 'Danya', password: 'pass250' },
        { username: 'Nastunya', password: 'pass324' }
    ];
    
    users.forEach(user => {
        db.get('SELECT id FROM users WHERE username = ?', [user.username], (err, row) => {
            if (!row) {
                bcrypt.hash(user.password, 12, (err, hash) => {
                    if (!err) {
                        db.run('INSERT INTO users (username, password, failed_attempts, locked_until) VALUES (?, ?, 0, 0)', 
                            [user.username, hash]);
                        console.log(`✅ Пользователь ${user.username} создан`);
                    }
                });
            } else {
                console.log(`👤 Пользователь ${user.username} уже существует`);
            }
        });
    });
});

// Middleware
app.use(express.json());
app.use(express.static('public'));
app.use(session({
    secret: 'ultra_secret_gallery_key_2025_change_me',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        maxAge: 1000 * 60 * 60 * 24,
        httpOnly: true,
        secure: false,
        sameSite: 'lax'
    }
}));

// Функция проверки блокировки
function isLocked(user) {
    if (user && user.locked_until > Date.now()) {
        return true;
    }
    return false;
}

// Функция логирования попыток входа
function logLoginAttempt(username, success, ip) {
    db.run('INSERT INTO login_logs (username, success, ip, timestamp) VALUES (?, ?, ?, ?)',
        [username, success ? 1 : 0, ip, Date.now()]);
}

// Middleware авторизации
function auth(req, res, next) {
    if (req.session.userId) next();
    else res.status(401).json({ error: 'Не авторизован' });
}

// --- API ---

// Логин с защитой от подбора
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Введите логин и пароль' });
    }
    
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (!user) {
            logLoginAttempt(username, false, ip);
            return res.status(401).json({ error: 'Неверный логин или пароль' });
        }
        
        // Проверка блокировки
        if (user.locked_until > Date.now()) {
            const remaining = Math.ceil((user.locked_until - Date.now()) / 1000 / 60);
            return res.status(423).json({ error: `Аккаунт заблокирован на ${remaining} минут` });
        }
        
        bcrypt.compare(password, user.password, (err, result) => {
            if (result) {
                // Успешный вход — сбрасываем попытки
                db.run('UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE id = ?', [user.id]);
                req.session.userId = user.id;
                req.session.username = user.username;
                logLoginAttempt(username, true, ip);
                res.json({ success: true, username: user.username });
            } else {
                // Неудачная попытка
                const newAttempts = (user.failed_attempts || 0) + 1;
                let lockedUntil = 0;
                
                if (newAttempts >= 5) {
                    lockedUntil = Date.now() + 15 * 60 * 1000; // блокировка на 15 минут
                }
                
                db.run('UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?', 
                    [newAttempts, lockedUntil, user.id]);
                logLoginAttempt(username, false, ip);
                
                let errorMsg = 'Неверный логин или пароль';
                if (newAttempts >= 5) {
                    errorMsg = 'Слишком много попыток. Аккаунт заблокирован на 15 минут';
                }
                res.status(401).json({ error: errorMsg });
            }
        });
    });
});

app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

app.get('/api/me', (req, res) => {
    if (req.session.userId) {
        res.json({ username: req.session.username });
    } else {
        res.status(401).json({ error: 'Не авторизован' });
    }
});

// Альбомы
app.get('/api/albums', auth, (req, res) => {
    db.all('SELECT * FROM albums ORDER BY created_at DESC', (err, albums) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(albums || []);
    });
});

app.post('/api/albums', auth, (req, res) => {
    const { name } = req.body;
    if (!name || name.trim() === '') {
        return res.status(400).json({ error: 'Название альбома не может быть пустым' });
    }
    db.run('INSERT INTO albums (name, created_at) VALUES (?, ?)', [name.trim(), Date.now()], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id: this.lastID, name: name.trim(), created_at: Date.now() });
    });
});

// Фото
app.get('/api/photos/:albumId', auth, (req, res) => {
    db.all('SELECT * FROM photos WHERE album_id = ? ORDER BY timestamp DESC', [req.params.albumId], (err, photos) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(photos || []);
    });
});

app.post('/api/upload/:albumId', auth, upload.array('photos', 20), (req, res) => {
    const files = req.files;
    if (!files || files.length === 0) {
        return res.status(400).json({ error: 'Нет файлов' });
    }
    
    let count = 0;
    files.forEach(file => {
        db.run(`INSERT INTO photos (album_id, filename, original_name, uploaded_by, timestamp) VALUES (?, ?, ?, ?, ?)`,
            [req.params.albumId, file.filename, file.originalname, req.session.username, Date.now()],
            (err) => {
                if (err) console.error(err);
                count++;
                if (count === files.length) {
                    res.json({ success: true, count: files.length });
                }
            });
    });
});

app.delete('/api/photo/:photoId', auth, (req, res) => {
    db.get('SELECT filename FROM photos WHERE id = ?', [req.params.photoId], (err, photo) => {
        if (photo) {
            const filepath = path.join(uploadDir, photo.filename);
            if (fs.existsSync(filepath)) fs.unlinkSync(filepath);
            db.run('DELETE FROM photos WHERE id = ?', [req.params.photoId]);
            db.run('DELETE FROM comments WHERE photo_id = ?', [req.params.photoId]);
            db.run('DELETE FROM likes WHERE photo_id = ?', [req.params.photoId]);
        }
        res.json({ success: true });
    });
});

app.get('/uploads/:filename', auth, (req, res) => {
    res.sendFile(path.join(uploadDir, req.params.filename));
});

// Комментарии
app.get('/api/comments/:photoId', auth, (req, res) => {
    db.all('SELECT * FROM comments WHERE photo_id = ? ORDER BY timestamp ASC', [req.params.photoId], (err, comments) => {
        res.json(comments || []);
    });
});

app.post('/api/comments', auth, (req, res) => {
    const { photo_id, text } = req.body;
    if (!text || text.trim() === '') return res.status(400).json({ error: 'Комментарий не может быть пустым' });
    
    // Экранирование для защиты от XSS
    const safeText = text.trim().replace(/[<>]/g, '').substring(0, 500);
    
    db.run('INSERT INTO comments (photo_id, username, text, timestamp) VALUES (?, ?, ?, ?)',
        [photo_id, req.session.username, safeText, Date.now()], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ id: this.lastID, username: req.session.username, text: safeText, timestamp: Date.now() });
        });
});

// Лайки
app.get('/api/likes/:photoId', auth, (req, res) => {
    db.get('SELECT COUNT(*) as count FROM likes WHERE photo_id = ?', [req.params.photoId], (err, result) => {
        db.get('SELECT COUNT(*) as user_liked FROM likes WHERE photo_id = ? AND username = ?', 
            [req.params.photoId, req.session.username], (err, liked) => {
                res.json({ count: result ? result.count : 0, userLiked: liked ? liked.user_liked > 0 : false });
            });
    });
});

app.post('/api/likes', auth, (req, res) => {
    const { photo_id } = req.body;
    db.run('INSERT OR IGNORE INTO likes (photo_id, username) VALUES (?, ?)', [photo_id, req.session.username], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, added: this.changes > 0 });
    });
});

app.delete('/api/likes', auth, (req, res) => {
    const { photo_id } = req.body;
    db.run('DELETE FROM likes WHERE photo_id = ? AND username = ?', [photo_id, req.session.username], function(err) {
        res.json({ success: true, removed: this.changes > 0 });
    });
});

// Уведомления — через SSE
const clients = [];
app.get('/api/notifications/stream', auth, (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    
    const client = { res, username: req.session.username };
    clients.push(client);
    
    req.on('close', () => {
        const index = clients.indexOf(client);
        if (index > -1) clients.splice(index, 1);
    });
});

// Функция отправки уведомлений всем кроме отправителя
function notifyNewPhoto(photoData, uploader) {
    clients.forEach(client => {
        if (client.username !== uploader) {
            client.res.write(`data: ${JSON.stringify(photoData)}\n\n`);
        }
    });
}

// Модифицируем загрузку, чтобы отправлять уведомления
const originalUpload = app.post('/api/upload/:albumId', auth, upload.array('photos', 20), (req, res) => {
    const files = req.files;
    if (!files || files.length === 0) {
        return res.status(400).json({ error: 'Нет файлов' });
    }
    
    let count = 0;
    files.forEach(file => {
        db.run(`INSERT INTO photos (album_id, filename, original_name, uploaded_by, timestamp) VALUES (?, ?, ?, ?, ?)`,
            [req.params.albumId, file.filename, file.originalname, req.session.username, Date.now()],
            function(err) {
                if (!err) {
                    // Отправляем уведомление
                    notifyNewPhoto({
                        photoId: this.lastID,
                        filename: file.filename,
                        uploaded_by: req.session.username,
                        timestamp: Date.now()
                    }, req.session.username);
                }
                count++;
                if (count === files.length) {
                    res.json({ success: true, count: files.length });
                }
            });
    });
});

app.listen(PORT, () => console.log(`✅ Защищённый сервер запущен на порту ${PORT}`));
