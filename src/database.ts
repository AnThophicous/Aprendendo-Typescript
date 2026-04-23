// Imports.
import Database from 'better-sqlite3';

// Configurações básicas.
export const db = new Database('mycrud.db');
export const skdb = new Database('mysks.db');

db.pragma('foreign_keys = ON');
skdb.pragma('cipher_default_compatibility = 4');

// Tabelas.
db.prepare(`
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user'
)`).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS user_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT NOT NULL UNIQUE,
    FOREIGN KEY (user_id) REFERENCES users(id)
)`).run();

// Preparando ambiente para chaves secretas.
skdb.prepare(`
CREATE TABLE IF NOT EXISTS secret_keys (
    key TEXT NOT NULL UNIQUE
)`).run();

export default db;