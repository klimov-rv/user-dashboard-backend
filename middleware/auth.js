import jwt from 'jsonwebtoken';

async function authMiddleware(req, res, next) {
    try {
        const authHeader = req.header('Authorization');

        if (!authHeader) {
            return res.status(401).json({
                message: 'Требуется авторизация'
            });
        }

        const token = authHeader.replace('Bearer ', '');

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
            message: 'Неверный токен'
        });
    }
}

export default authMiddleware