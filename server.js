
import 'dotenv/config';
import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

import {
    readUsers,
    writeUsers,
    addToBlacklist,
    isTokenBlacklisted
} from './utils/file-handlers.js';

import authMiddleware from './middleware/auth.js';
import handleAuthRPC from './rpc/auth-handler.js';
import handleUserRPC from './rpc/user-handler.js';

const app = express();
app.use(express.json()); // Позволяет читать JSON в теле запроса

const PORT = process.env.PORT;


app.listen(PORT, () => {
    console.log(`Сервер запущен на порту ${PORT}`);
});

app.get('/', (_, res) => {
    res.send('API личного кабинета работает!');
});

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

// RPC стиль
app.post('/rpc', async (req, res) => {
    try {
        const { method, params, id } = req.body;

        // Проверка структуры запроса
        if (!method || typeof method !== 'string') {
            return res.json({
                jsonrpc: '2.0',
                error: { code: -32600, message: 'Invalid Request' },
                id: id || null
            });
        }

        // Роутинг методов
        const [namespace, action] = method.split('.');

        let result;
        switch (namespace) {
            case 'auth':
                result = await handleAuthRPC(action, params, req);
                break;
            case 'user':
                result = await handleUserRPC(action, params, req);
                break;
            default:
                throw new Error('Method not found');
        }

        // Успешный ответ
        res.json({
            jsonrpc: '2.0',
            result: result,
            id: id
        });

    } catch (error) {
        // Ошибка
        res.json({
            jsonrpc: '2.0',
            error: {
                code: -32603,
                message: error.message
            },
            id: req.body.id || null
        });
    }
});