
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

// Проверка работы API
app.get('/api/health', (_, res) => {
    res.json({
        success: true,
        data: {
            service: 'User Dashboard API',
            status: 'running',
            timestamp: new Date().toISOString()
        }
    });
});

// 1. РЕГИСТРАЦИЯ (Sign Up)
app.post('/api/auth/sign-up', async (req, res) => {
    try {
        console.log('📝 Sign Up запрос:', req.body);

        const { email, password, name } = req.body;

        // Валидация
        if (!email || !password || !name) {
            return res.status(400).json({
                success: false,
                error: 'Все поля обязательны: email, password, name'
            });
        }

        // Простая валидация email
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({
                success: false,
                error: 'Неверный формат email'
            });
        }

        const users = await readUsers();

        // Проверка существования пользователя
        if (users.find(user => user.email === email)) {
            return res.status(409).json({
                success: false,
                error: 'Пользователь с таким email уже существует'
            });
        }

        // Хеширование пароля
        const hashedPassword = await bcrypt.hash(password, 10);

        // Создание пользователя
        const newUser = {
            id: Date.now().toString(),
            email,
            password: hashedPassword,
            name,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };

        users.push(newUser);
        await writeUsers(users);

        console.log(`✅ Пользователь создан: ${email}`);

        res.status(201).json({
            success: true,
            data: {
                message: 'Пользователь успешно зарегистрирован',
                userId: newUser.id,
                user: {
                    id: newUser.id,
                    email: newUser.email,
                    name: newUser.name
                }
            }
        });

    } catch (error) {
        console.error('❌ Ошибка Sign Up:', error);
        res.status(500).json({
            success: false,
            error: 'Внутренняя ошибка сервера'
        });
    }
});

// 2. ВХОД (Sign In)
app.post('/api/auth/sign-in', async (req, res) => {
    try {
        console.log('🔐 Sign In запрос для:', req.body.email);

        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                success: false,
                error: 'Email и password обязательны'
            });
        }

        const users = await readUsers();
        const user = users.find(user => user.email === email);

        if (!user) {
            console.log('❌ Пользователь не найден:', email);
            return res.status(401).json({
                success: false,
                error: 'Неверный email или пароль'
            });
        }

        // Проверка пароля
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            console.log('❌ Неверный пароль для:', email);
            return res.status(401).json({
                success: false,
                error: 'Неверный email или пароль'
            });
        }

        // Генерация JWT токена
        const token = jwt.sign(
            {
                id: user.id,
                email: user.email,
                name: user.name
            },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        console.log(`✅ Успешный вход: ${email}`);

        res.json({
            success: true,
            data: {
                token,
                tokenType: 'Bearer',
                expiresIn: 3600, // секунд
                user: {
                    id: user.id,
                    email: user.email,
                    name: user.name
                }
            }
        });

    } catch (error) {
        console.error('❌ Ошибка Sign In:', error);
        res.status(500).json({
            success: false,
            error: 'Внутренняя ошибка сервера'
        });
    }
});

// 3. ВЫХОД (Sign Out)
app.post('/api/auth/sign-out', authMiddleware, async (req, res) => {
    try {
        const token = req.headers.authorization.replace('Bearer ', '');

        // Добавляем токен в blacklist
        await addToBlacklist(token);

        console.log(`🚪 Пользователь ${req.user.email} вышел из системы`);

        res.json({
            success: true,
            data: {
                message: 'Вы успешно вышли из системы',
                logoutTime: new Date().toISOString()
            }
        });

    } catch (error) {
        console.error('❌ Ошибка Sign Out:', error);
        res.status(500).json({
            success: false,
            error: 'Ошибка при выходе из системы'
        });
    }
});

// 4. ПОЛУЧЕНИЕ ПРОФИЛЯ  
app.get('/api/users/me', authMiddleware, async (req, res) => {
    try {
        const users = await readUsers();
        const user = users.find(u => u.id === req.user.id);

        if (!user) {
            return res.status(404).json({
                success: false,
                error: 'Пользователь не найден'
            });
        }

        const { password, ...userData } = user;

        res.json({
            success: true,
            data: {
                ...userData,
                sessionActive: true,
                lastActivity: new Date().toISOString()
            }
        });

    } catch (error) {
        console.error('❌ Ошибка получения профиля:', error);
        res.status(500).json({
            success: false,
            error: 'Ошибка при получении профиля'
        });
    }
});