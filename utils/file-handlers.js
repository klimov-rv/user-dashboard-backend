import * as fs from 'node:fs/promises';
import jwt from 'jsonwebtoken';
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
        const exists = await fileExists(BLACKLIST_FILE);
        if (!exists) {
            console.log("Файл blacklist не существует, возвращаю пустой массив.");
            return [];
        }

        const data = await fs.readFile(BLACKLIST_FILE, 'utf8');
        console.log("BLACKLIST_FILE data: ", data);
        return data ? JSON.parse(data) : [];
    } catch (error) {
        console.error("Ошибка при чтении blacklist:", error);
        return [];
    }
}

// Добавление токена в blacklist
export async function addToBlacklist(token) {
    try {
        console.log('addToBlacklist');
        const blacklist = await readBlacklist();
        console.log('blacklist: ', blacklist);

        // Декодируем токен для получения времени истечения
        const decoded = jwt.decode(token);
        if (!decoded || !decoded.exp) {
            console.error('Не могу декодировать токен');
            return;
        }

        const expiresAt = decoded.exp * 1000; // в миллисекундах

        console.log('decoded');
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

// Проверка существования файла
async function fileExists(filePath) {
    try {
        await fs.access(filePath);
        return true;
    } catch {
        return false;
    }
}


// Проверка, находится ли токен в blacklist
export async function isTokenBlacklisted(token) {
    try {
        const blacklist = await readBlacklist();
        console.log('blacklist: ', blacklist);
        const now = Date.now();

        // Фильтруем только актуальные токены
        const validBlacklist = blacklist.filter(item => item.expiresAt > now);
        console.log('validBlacklist: ', validBlacklist);

        // Удаляем протухшие из файла
        if (validBlacklist.length !== blacklist.length) {
            await fs.writeFile(BLACKLIST_FILE, JSON.stringify(validBlacklist, null, 2));
        }

        return validBlacklist.some(item => item.token === token);
    } catch (error) {
        return false;
    }
}
