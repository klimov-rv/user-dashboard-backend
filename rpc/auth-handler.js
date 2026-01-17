
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import {
    readUsers,
    writeUsers,
} from '../utils/file-handlers.js';

async function handleAuthRPC(action, params, req) {
    switch (action) {
        case 'register':
            return await authRegister(params);
        case 'login':
            return await authLogin(params);
        case 'logout':
            return await authLogout(params, req);
        case 'validate':
            return await authValidate(params);
        default:
            throw new Error(`Method auth.${action} not found`);
    }
}

// Регистрация
async function authRegister(params) {
    const { email, password, name } = params;

    if (!email || !password || !name) {
        throw new Error('Все поля обязательны');
    }

    const users = await readUsers();

    if (users.find(user => user.email === email)) {
        throw new Error('Пользователь уже существует');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
        id: Date.now(),
        email,
        password: hashedPassword,
        name,
        createdAt: new Date().toISOString()
    };

    users.push(newUser);
    await writeUsers(users);

    return {
        userId: newUser.id,
        message: 'Пользователь успешно зарегистрирован'
    };
}

// Вход
async function authLogin(params) {
    const { email, password } = params;

    const users = await readUsers();
    const user = users.find(user => user.email === email);

    if (!user) {
        throw new Error('Неверный email или пароль');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
        throw new Error('Неверный email или пароль');
    }

    const token = jwt.sign(
        { id: user.id, email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
    );

    return {
        token,
        user: {
            id: user.id,
            email: user.email,
            name: user.name
        },
        expiresIn: 3600 // секунд
    };
}

export default handleAuthRPC