import * as fs from 'node:fs/promises';
import 'dotenv/config';
import express from 'express';
import path from 'path';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import authMiddleware from './middleware/auth.js';

const app = express();
app.use(express.json()); // Позволяет читать JSON в теле запроса

const PORT = process.env.PORT;

app.get('/', (_, res) => {
    res.send('API личного кабинета работает!');
});

app.listen(PORT, () => {
    console.log(`Сервер запущен на порту ${PORT}`);
});

const USERS_FILE = path.join('data', 'users.json');
const BLACKLIST_FILE = path.join('data', 'tokens_bl.json');

// Чтение пользователей из файла
async function readUsers() {
    const data = await fs.readFile(USERS_FILE, 'utf8');
    return JSON.parse(data);
}

// Запись пользователей в файл
async function writeUsers(users) {
    await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2));
}

// Чтение blacklist токенов
async function readBlacklist() {
    try {
        const data = await fs.readFile(BLACKLIST_FILE, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        // Если файла нет, возвращаем пустой массив
        return [];
    }
}

// Добавление токена в blacklist
async function addToBlacklist(token) {
    try {
        const blacklist = await readBlacklist();

        // Декодируем токен, чтобы узнать время истечения
        const decoded = jwt.decode(token);
        const expiresAt = decoded.exp * 1000; // Конвертируем в миллисекунды

        blacklist.push({
            token,
            expiresAt,
            blacklistedAt: new Date().toISOString(),
        });
        console.log('blacklist: ', blacklist);

        await fs.writeFile(BLACKLIST_FILE, JSON.stringify(blacklist, null, 2));
    } catch (error) {
        console.error('Ошибка при добавлении в blacklist:', error);
    }
}

// Проверка, находится ли токен в blacklist
async function isTokenBlacklisted(token) {
    try {
        const blacklist = await readBlacklist();
        const now = Date.now();

        // Фильтруем протухшие токены (чистим blacklist)
        const validBlacklist = blacklist.filter((item) => item.expiresAt > now);

        // Если есть протухшие, обновляем файл
        if (validBlacklist.length !== blacklist.length) {
            await fs.writeFile(
                BLACKLIST_FILE,
                JSON.stringify(validBlacklist, null, 2),
            );
        }

        return validBlacklist.some((item) => item.token === token);
    } catch (error) {
        return false;
    }
}

app.post('/api/register', async (req, res) => {
    try {
        // Проверяем, что тело не пустое
        if (!req.body || Object.keys(req.body).length === 0) {
            return res.status(400).json({
                message: 'Тело запроса пустое или не является JSON',
            });
        }
        const { email, password, name } = req.body;

        // Валидация
        if (!email || !password || !name) {
            return res.status(400).json({ message: 'Все поля обязательны' });
        }

        const users = await readUsers();

        // Проверка существования пользователя
        if (users.find((user) => user.email === email)) {
            return res.status(400).json({ message: 'Пользователь уже существует' });
        }

        // Хеширование пароля
        const hashedPassword = await bcrypt.hash(password, 10);

        // Создание нового пользователя
        const newUser = {
            id: Date.now(),
            email,
            password: hashedPassword,
            name,
            createdAt: new Date().toISOString(),
        };

        users.push(newUser);
        await writeUsers(users);

        res.status(201).json({ message: 'Пользователь успешно зарегистрирован' });
    } catch (error) {
        res.status(500).json({ message: 'Ошибка сервера' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const users = await readUsers();

        const user = users.find((user) => user.email === email);
        if (!user) {
            return res.status(401).json({ message: 'Неверный email или пароль' });
        }

        // Сравнение пароля с хешем
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Неверный email или пароль' });
        }

        // Генерация JWT токена
        const token = jwt.sign(
            { id: user.id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: '1h' },
        );

        res.json({
            token,
            user: {
                id: user.id,
                email: user.email,
                name: user.name,
            },
        });
    } catch (error) {
        res.status(500).json({ message: 'Ошибка сервера' });
    }
});

app.get('/api/profile', authMiddleware, async (req, res) => {
    try {
        const users = await readUsers();
        const user = users.find((u) => u.id === req.user.id);

        if (!user) {
            return res.status(404).json({ message: 'Пользователь не найден' });
        }

        // Проверяем, не отозван ли токен (дополнительная защита)
        const token = req.headers.authorization.replace('Bearer ', '');
        const isBlacklisted = await isTokenBlacklisted(token);

        if (isBlacklisted) {
            return res.status(401).json({ message: 'Сессия завершена' });
        }

        const { password, ...userData } = user;
        res.json({
            ...userData,
            sessionActive: true,
            lastActivity: new Date().toISOString(),
        });
    } catch (error) {
        res.status(500).json({ message: 'Ошибка сервера' });
    }
});

// logout endpoint
app.post('/api/logout', authMiddleware, async (req, res) => {
    try {
        const token = req.headers.authorization.replace('Bearer ', '');

        // Добавляем токен в blacklist
        await addToBlacklist(token);

        console.log(`Пользователь ${req.user.email} вышел из системы`);

        res.json({
            message: 'Вы вышли из системы',
            logoutTime: new Date().toISOString(),
        });
    } catch (error) {
        console.error('Ошибка при логауте:', error);
        res.status(500).json({ message: 'Ошибка сервера при выходе' });
    }
});
