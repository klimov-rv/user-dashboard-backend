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
        await fs.access(BLACKLIST_FILE);
        const data = await fs.readFile(BLACKLIST_FILE, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        return [];
    }
}

// Добавление токена в blacklist
export async function addToBlacklist(token) {
    try {
        const blacklist = await readBlacklist();

        // Декодируем токен для получения времени истечения
        const decoded = jwt.decode(token);
        if (!decoded || !decoded.exp) {
            console.error('Не могу декодировать токен');
            return;
        }

        const expiresAt = decoded.exp * 1000; // в миллисекундах

        // Добавляем только если еще нет
        if (!blacklist.some(item => item.token === token)) {
            blacklist.push({
                token,
                expiresAt,
                blacklistedAt: new Date().toISOString()
            });

            await fs.writeFile(BLACKLIST_FILE, JSON.stringify(blacklist, null, 2));
            console.log('Токен добавлен в blacklist');
        }
    } catch (error) {
        console.error('Ошибка при добавлении в blacklist:', error);
    }
}

// Проверка, находится ли токен в blacklist
export async function isTokenBlacklisted(token) {
    try {
        const blacklist = await readBlacklist();
        const now = Date.now();

        // Фильтруем только актуальные токены
        const validBlacklist = blacklist.filter(item => item.expiresAt > now);

        // Удаляем протухшие из файла
        if (validBlacklist.length !== blacklist.length) {
            await fs.writeFile(BLACKLIST_FILE, JSON.stringify(validBlacklist, null, 2));
        }

        return validBlacklist.some(item => item.token === token);
    } catch (error) {
        return false;
    }
}
