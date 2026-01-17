import jwt from 'jsonwebtoken';
import { isTokenBlacklisted } from '../utils/file-handlers.js';

async function authMiddleware(req, res, next) {
    try {
        const authHeader = req.header('Authorization');
        console.log("authHeader:", authHeader)

        if (!authHeader) {
            return res.status(401).json({
                message: 'Требуется авторизация'
            });
        }

        const token = authHeader.replace('Bearer ', '');
        console.log("token:", token)

        // Проверяем blacklist
        const isBlacklisted = await isTokenBlacklisted(token);
        if (isBlacklisted) {
            return res.status(401).json({
                message: 'Сессия истекла. Войдите снова.'
            });
        }

        // Верифицируем токен
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                message: 'Токен истек'
            });
        }

        res.status(401).json({
            error,
            message: 'Неверный токен'
        });
    }
}

export default authMiddleware