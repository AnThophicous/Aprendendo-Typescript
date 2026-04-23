// Imports e afins.
import { db, skdb } from './database';
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { Request, Response, NextFunction } from 'express';

// Lógica de segurança e criptografia.
const IV_LENGTH = 16;

// Irmão, se tu soubesse metade do perrengue que passei para criar essa lógica, você nem iria querer ler essa bosta
// Eu tentei criar as lógicas do meu jeito, soq o chatgpt quase me chamou de Jamanta, pq eu queria guardar a SK de um jeito Horrivel
// E Tipo, ele falou: Irmão toda vez que teu app reiniciar uma nova chave vai ser gerada, arruma esse trem ai
// Ai eu ficava muito bravo, nossa fui uma luta.
// Mais suponho que não tenha nenhum erro aq, eu acho...

interface SecretKeyRow {
    key: string;
}

export interface User {
    id: number;
    password: string;
    name: string;
    email: string;
    role: string;
}

const row = skdb.prepare('SELECT key FROM secret_keys LIMIT 1').get() as SecretKeyRow | undefined;

let SECRET_KEY: Buffer;
if (row) {
    SECRET_KEY = Buffer.from(row.key, 'hex');
} else {
    SECRET_KEY = crypto.randomBytes(32);
    const stmt = skdb.prepare('INSERT INTO secret_keys (key) VALUES (?)');
    stmt.run(SECRET_KEY.toString('hex'));
}



export function encrypt(text: string) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', SECRET_KEY, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
}

export function decrypt(text: string) {
    const parts = text.split(':');
    const iv = Buffer.from(parts.shift()!, 'hex');
    const encryptedText = parts.join(':');
    const decipher = crypto.createDecipheriv('aes-256-cbc', SECRET_KEY, iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// Funções de usuário e token.
// Aq foi mais de boas.
// Ainda apanhei como sempre mais foi fluindo descentemente.

export function createUserID() {
    return uuidv4();
}

export function getUserByID(id: number): User | undefined {
    const stmt = db.prepare('SELECT * FROM users WHERE id = ?');
    return stmt.get(id) as User | undefined;
}

export function createUserToken(userID: number) {
    const token = 'sk-' + crypto.randomBytes(16).toString('hex');
    const stmt = db.prepare('INSERT INTO user_tokens (user_id, token) VALUES (?, ?)');
    stmt.run(userID, token);
    return token;
}

export function getUserByToken(token: string): User | undefined {
    const stmt = db.prepare(`SELECT users.* FROM users
    JOIN user_tokens ON users.id = user_tokens.user_id
    WHERE user_tokens.token = ?`);
    return stmt.get(token) as User | undefined;
}

export function deleteUserToken(token: string) {
    const stmt = db.prepare('DELETE FROM user_tokens WHERE token = ?');
    stmt.run(token);
}

export function renewUserToken(oldToken: string) {
    const user = getUserByToken(oldToken);
    if (!user) return null;
    deleteUserToken(oldToken);
    return createUserToken(user.id);
}

export function hashPassword(password: string) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
    return salt + ':' + hash;
}

export function verifyPassword(password: string, storedHash: string) {
    const [salt, hash] = storedHash.split(':');
    const hashToVerify = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
    return hash === hashToVerify;
}

export interface AuthenticatedRequest extends Request {
    user?: User;
}

export function authMiddleware(requiredRole?: string) {
    return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'No token provided' });

        const token = authHeader.split(' ')[1];
        const user = getUserByToken(token);
        if (!user) return res.status(401).json({ error: 'Invalid token' });
        if (requiredRole && user.role !== requiredRole) return res.status(403).json({ error: 'Forbidden' });
        req.user = user;
        next();
    };
}

export type RateLimitEntry = {
    timestamps: number[];
    blockedUntil?: number;
};

export const rateLimitStore: Record<string, RateLimitEntry> = {};

const WINDOW_MS = 1000;
const MAX_REQUESTS = 5;
const BLOCK_MS = 15 * 60 * 1000;

function getClientIp(req: any): string {
    const cloudflareIp = req.headers["cf-connecting-ip"];

    if (cloudflareIp) return String(cloudflareIp);
    if (req.ip) return String(req.ip);
    return (
        req.socket?.remoteAddress ||
        req.connection?.remoteAddress ||
        "unknown"
    );
}

// Aqui que tive que usar IA de verdade. Eu queria uma lógica anti Proxy, mais como a vida é cruel tive que recorrer para a IA.

export function isSuspiciousProxy(req: any): boolean {
    const hasCloudflare = Boolean(req.headers["cf-ray"] || req.headers["cf-connecting-ip"]);
    if (hasCloudflare) return false;

    const suspiciousHeaders = [
        "via",
        "forwarded",
        "x-real-ip",
        "x-proxy-id",
        "proxy-connection",
        "x-forwarded-host",
        "x-forwarded-proto"
    ];

    return suspiciousHeaders.some(header => Boolean(req.headers[header]));
}

export function rateLimit(req: any, res: any, next: any) {
    const ip = getClientIp(req);
    const now = Date.now();

    if (!rateLimitStore[ip]) {
        rateLimitStore[ip] = {
            timestamps: []
        };
    }

    const entry = rateLimitStore[ip];

    if (entry.blockedUntil && now < entry.blockedUntil) {
        return res.status(429).json({
            error: "Too many requests",
            retryAfter: Math.ceil((entry.blockedUntil - now) / 1000)
        });
    }

    entry.timestamps = entry.timestamps.filter(
        (timestamp: number) => now - timestamp < WINDOW_MS
    );

    if (isSuspiciousProxy(req)) {
        entry.blockedUntil = now + BLOCK_MS;

        return res.status(429).json({
            error: "Too many requests"
        });
    }

    if (entry.timestamps.length >= MAX_REQUESTS) {
        entry.blockedUntil = now + BLOCK_MS;

        return res.status(429).json({
            error: "Too many requests",
            retryAfter: Math.ceil(BLOCK_MS / 1000)
        });
    }

    entry.timestamps.push(now);

    next();
}

// Sim para as partes mais avançadas como proxy detection pedi ajuda do Chatgpt sim e ele me deu o código, eu não tava conseguindo aprender como fazer isso sem bloquear usuários reais então tive que pedir ajuda.
// Talvez eu seja um vibecoder bem assumido mesmo. kkkkk
// Não vejo nada de errado em pedir ajuda pro chatgpt, eu acho.