import * as fs from 'node:fs/promises';
import path from 'path';

const USERS_FILE = path.join('data', 'users.json');
const BLACKLIST_FILE = path.join('data', 'tokens_bl.json');

// Чтение пользователей из файла
export async function readUsers() {
    const data = await fs.readFile(USERS_FILE, 'utf8');
    return JSON.parse(data);
}

// Запись пользователей в файл
export async function writeUsers(users) {
    await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2));
}

// Чтение blacklist токенов
export async function readBlacklist() {
    try {
        const data = await fs.readFile(BLACKLIST_FILE, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        // Если файла нет, возвращаем пустой массив
        return [];
    }
}

// Добавление токена в blacklist
export async function addToBlacklist(token) {
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
export async function isTokenBlacklisted(token) {
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
