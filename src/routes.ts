// Importando aq as coisa
import express from 'express';
import { app } from './bridge';
import db from './database';
import { getUserByID, createUserToken, getUserByToken, deleteUserToken, renewUserToken, hashPassword, verifyPassword, authMiddleware, rateLimit, User, AuthenticatedRequest } from './security';
import nodemailer from 'nodemailer';

// O Chatgpt me recomendou dar uma aprofundada em Router's então decidi dar uma estudada, foi só uma passada de revisão, nada assim tão grande só aprendi a fazer o minimo. to meio sem tempo.
const usersRouter = express.Router();

// Configurações básicas dos emails, tentei usar um env ali pra não expor meus dados né :/
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.GOOGLE_APP_EMAIL,
        pass: process.env.GOOGLE_APP_PASSWORD
    }
});

// Falar que realmente tentei fazer algo mais diferente doq faria normalmente, eu dei uma mini praticada, conversei com o chatgpt pra ele me ajudar
// Alguns pontos que ele levantou foi justamente o Route que me ajudou a não ficar usando: app.get que é bem ineficiente.
// Gostei bastante de usar Router, parece que o código fica mais limpo. eu acho :)

usersRouter.get('/:id', authMiddleware(), rateLimit, (req: AuthenticatedRequest, res) => {
    const userId = Number(req.params.id);
    if (!userId) return res.status(400).json({ error: 'Invalid user id' });
    const user = getUserByID(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ id: user.id, name: user.name, email: user.email, role: user.role });
});

// Antes que perguntem, to Usando VSCODE
// Meu GIT tá inicializado e tem os commits, eu não fiquei commitando cada alteração que fiz pq sou bem esquecido.
// Eu até tentei ali dar uma variada na segurança com Rate Limit, mais não sei se tá seguro, dps vou pedir para revisarem.
// E SIM, a IA me ajudou por grande parte do projeto, como uma tutora de Ensinamentos, eu não copiei e colei. 
// Obvio que tem várias partes que eu não sei ao certo como funcionam pq não me aprofundei mais a maioria eu estudei mesmo que minimanete.

usersRouter.post('/register', rateLimit, (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'Missing fields' });

    const existingUser = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (existingUser) return res.status(400).json({ error: 'Email already in use' });

    const hashedPassword = hashPassword(password);
    const stmt = db.prepare('INSERT INTO users (name, email, password) VALUES (?, ?, ?)');
    const info = stmt.run(name, email, hashedPassword);
    const userID = info.lastInsertRowid as number;
    const token = createUserToken(userID);
    res.json({ token });
});

usersRouter.post('/login', rateLimit, (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Missing fields' });

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email) as User | undefined;
    if (!user || !verifyPassword(password, user.password)) return res.status(401).json({ error: 'Invalid credentials' });

    const token = createUserToken(user.id);
    res.json({ token });
});

usersRouter.post('/logout', rateLimit, authMiddleware(), (req: AuthenticatedRequest, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader ? authHeader.split(' ')[1] : undefined;
    if (!token) return res.status(401).json({ error: 'No token provided' });

    deleteUserToken(token);
    res.json({ message: 'Logged out successfully' });
});

usersRouter.post('/renew-token', rateLimit, authMiddleware(), (req: AuthenticatedRequest, res) => {
    const authHeader = req.headers['authorization'];
    const oldToken = authHeader ? authHeader.split(' ')[1] : undefined;
    if (!oldToken) return res.status(401).json({ error: 'No token provided' });

    const newToken = renewUserToken(oldToken);
    if (!newToken) return res.status(401).json({ error: 'Invalid token' });

    res.json({ token: newToken });
});

usersRouter.put('/password', rateLimit, authMiddleware(), (req: AuthenticatedRequest, res) => {
    if (!req.user) return res.status(401).json({ error: 'No token provided' });

    const generatedPassword = Math.random().toString(36).slice(-8);
    const hashedPassword = hashPassword(generatedPassword);
    db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hashedPassword, req.user.id);

    res.json({ message: 'Password updated successfully' });

    const mailOptions = {
        from: process.env.GOOGLE_APP_EMAIL,
        to: req.user.email,
        subject: 'Your new password',
        text: `Your new password is: ${generatedPassword}`
    };

    transporter.sendMail(mailOptions, (error: any, info: any) => {
        if (error) {
            console.error('Error sending email:', error);
        } else {
            console.log('Email sent:', info.response);
        }
    });
});

// Eu queria uma forma mais eficiente de Guardar esses mailOptins mais não sei ao certo como fazer isso.
// então só repeti a string em tudo que vi.

usersRouter.put('/role', rateLimit, authMiddleware('admin'), (req: AuthenticatedRequest, res) => {
    const { userToken, newRole } = req.body;
    if (!userToken || !newRole) return res.status(400).json({ error: 'Missing fields' });

    const user = getUserByToken(userToken);
    if (!user) return res.status(404).json({ error: 'User not found' });

    db.prepare('UPDATE users SET role = ? WHERE id = ?').run(newRole, user.id);
    res.json({ message: 'Role updated successfully' });
});

usersRouter.put('/email', rateLimit, authMiddleware(), (req: AuthenticatedRequest, res) => {
    if (!req.user) return res.status(401).json({ error: 'No token provided' });

    const { newEmail } = req.body;
    if (!newEmail) return res.status(400).json({ error: 'Missing fields' });

    const existingUser = db.prepare('SELECT * FROM users WHERE email = ?').get(newEmail);
    if (existingUser) return res.status(400).json({ error: 'Email already in use' });

    db.prepare('UPDATE users SET email = ? WHERE id = ?').run(newEmail, req.user.id);
    res.json({ message: 'Email updated successfully' });
});

usersRouter.put('/name', rateLimit, authMiddleware(), (req: AuthenticatedRequest, res) => {
    if (!req.user) return res.status(401).json({ error: 'No token provided' });

    const { newName } = req.body;
    if (!newName) return res.status(400).json({ error: 'Missing fields' });

    db.prepare('UPDATE users SET name = ? WHERE id = ?').run(newName, req.user.id);
    res.json({ message: 'Name updated successfully' });
});

usersRouter.put('/password/change', rateLimit, authMiddleware(), (req: AuthenticatedRequest, res) => {
    if (!req.user) return res.status(401).json({ error: 'No token provided' });

    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Missing fields' });
    if (!verifyPassword(currentPassword, req.user.password)) return res.status(401).json({ error: 'Invalid current password' });

    const hashedPassword = hashPassword(newPassword);
    db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hashedPassword, req.user.id);
    res.json({ message: 'Password changed successfully' });
});

usersRouter.put('/password/reset', rateLimit, (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Missing fields' });

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email) as User | undefined;
    if (!user) return res.status(404).json({ error: 'User not found' });

    const generatedPassword = Math.random().toString(36).slice(-8);
    const hashedPassword = hashPassword(generatedPassword);
    db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hashedPassword, user.id);
    res.json({ message: 'Password reset successfully' });

    const mailOptions = {
        from: process.env.GOOGLE_APP_EMAIL,
        to: user.email,
        subject: 'Your password has been reset',
        text: `Your new password is: ${generatedPassword}`
    };

    transporter.sendMail(mailOptions, (error: any, info: any) => {
        if (error) {
            console.error('Error sending email:', error);
        } else {
            console.log('Email sent:', info.response);
        }
    });
});

usersRouter.put('/email/reset', rateLimit, authMiddleware(), (req: AuthenticatedRequest, res) => {
    if (!req.user) return res.status(401).json({ error: 'No token provided' });

    const { newEmail } = req.body;
    if (!newEmail) return res.status(400).json({ error: 'Missing fields' });

    const existingUser = db.prepare('SELECT * FROM users WHERE email = ?').get(newEmail);
    if (existingUser) return res.status(400).json({ error: 'Email already in use' });

    db.prepare('UPDATE users SET email = ? WHERE id = ?').run(newEmail, req.user.id);
    res.json({ message: 'Email reset successfully' });
});

usersRouter.get('/data/all', rateLimit, authMiddleware('admin'), (req, res) => {
    const users = db.prepare('SELECT id, name, email, role FROM users').all() as User[];
    const firstUserId = users.length ? users[0].id : null;
    const tokenRow = firstUserId ? db.prepare('SELECT token FROM user_tokens WHERE user_id = ?').get(firstUserId) as { token: string } | undefined : undefined;
    const userToken = tokenRow?.token ?? null;
    res.json({ users, token: userToken });
});

usersRouter.get('/data/:id', rateLimit, authMiddleware('admin'), (req, res) => {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ error: 'Invalid user id' });
    const user = db.prepare('SELECT id, name, email, role FROM users WHERE id = ?').get(id) as User | undefined;
    if (!user) return res.status(404).json({ error: 'User not found' });

    const tokenRow = db.prepare('SELECT token FROM user_tokens WHERE user_id = ?').get(user.id) as { token: string } | undefined;
    const userToken = tokenRow?.token ?? null;
    res.json({ user, token: userToken });
});

app.get('/', (req, res) => {
    res.json({ message: 'API está rodando', endpoints: ['/users/register', '/users/login', '/users/:id'] });
});

app.use('/users', usersRouter);

// Eu tentei entender em média oq cada linha aqui faz, mais algumas fiquei em dúvida. depois peço ajuda pra galera de Cybersec
// mais deixando aqui os créditos das ferramentas que mais me ajudaram durante o projeto desse CRUD.
// CHATGPT -> Me ajudou a entender arquitetura, me falou de boas práticas e tentou me ensinar Clean Code, para mim tá bem fácil de Refatorar esse código acima, eu ainda precisaria da ajuda da IA para os Erros ou Warnings mais acho que conseguiria sim dar uma Refatorada ou adicionar mais coisas
// GITHUB COPILOT -> Ele me ajudou a escrever algumas partes do código, realmente foi bem útil em momentos que fiquei com dúvida, eu pedia pra ele me ajudar.
// GEMINI -> Caraca, que amigo sempre que eu precisava perguntar alguma coisa sobre blibliotecas ou pedir uma ajuda ou resumo de blibliotecas ela explicava de forma bem fácil de se entender. só escolhi better-sqlite3 por causa dela.

// De resto gostei bastante do projeto, não sei ao certo se tá funcionando, ainda vou testar, mais se der tudo certinho confio que sim né kkkk
// Bom de resto foi isso.