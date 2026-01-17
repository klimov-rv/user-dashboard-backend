import jwt from 'jsonwebtoken';
import {
    readUsers,
} from '../utils/file-handlers.js';

async function handleUserRPC(action, params, req) {
    // Проверка аутентификации для всех user.* методов
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) {
        throw new Error('Требуется аутентификация');
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
    } catch (error) {
        throw new Error('Неверный токен');
    }

    switch (action) {
        case 'getProfile':
            return await userGetProfile(req.user);
        case 'updateProfile':
            return await userUpdateProfile(params, req.user);
        case 'changePassword':
            return await userChangePassword(params, req.user);
        default:
            throw new Error(`Method user.${action} not found`);
    }
}

async function userGetProfile(user) {
    const users = await readUsers();
    const userData = users.find(u => u.id === user.id);

    if (!userData) {
        throw new Error('Пользователь не найден');
    }

    const { password, ...profile } = userData;
    return profile;
}

export default handleUserRPC