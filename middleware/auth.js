import jwt from 'jsonwebtoken';

function authMiddleware(req, res, next) {
    // Токен в заголовке Authorization: Bearer <token>
    const authHeader = req.header('Authorization');

    if (!authHeader) {
        return res.status(401).json({ message: 'Нет токена, доступ запрещен' });
    }

    // Извлекаем токен из строки "Bearer <token>"
    const token = authHeader.replace('Bearer ', '');

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded; // Добавляем данные пользователя в запрос
        next();
    } catch (error) {
        res.status(401).json({ message: 'Неверный токен', error });
    }
}

export default authMiddleware