import { app } from './bridge';
import { users } from './data';
import { tokens } from './data';

app.get('/users', (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Token não fornecido' });
    }

    const validToken = tokens.find(t => t.accessToken === token);

    if (!validToken) {
        return res.status(403).json({ message: 'Token inválido' });
    }

    res.json(users);
});

app.get('/tokens', (req, res) => {
    res.json(tokens);
});

app.get('/', (req, res) => {
    res.json({ message: 'API está rodando', endpoints: ['/tokens', '/users'] });
});

app.post('/users-create', (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Token não fornecido' });
    }

    const validToken = tokens.find(t => t.accessToken === token);

    if (!validToken) {
        return res.status(403).json({ message: 'Token inválido' });
    }

    const { name, email } = req.body;

    if (!name || !email) {
        return res.status(400).json({ message: 'Nome e email são obrigatórios' });
    }

    const newUser = {
        id: users.length + 1,
        name,
        email,
    };
    
    users.push(newUser);
    res.status(201).json(newUser);
});

app.post('/users-get-by-id', (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Token não fornecido' });
    }

    const validToken = tokens.find(t => t.accessToken === token);

    if (!validToken) {
        return res.status(403).json({ message: 'Token inválido' });
    }

    const { id } = req.body;

    if (!id) {
        return res.status(400).json({ message: 'ID é obrigatório' });
    }

    const user = users.find(u => u.id === id);

    if (!user) {
        return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    res.json(user);
});

app.put('/users-update', (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Token não fornecido' });
    }

    const validToken = tokens.find(t => t.accessToken === token);

    if (!validToken) {
        return res.status(403).json({ message: 'Token inválido' });
    }

    const { id, name, email } = req.body;

    if (!id) {
        return res.status(400).json({ message: 'ID é obrigatório' });
    }

    const user = users.find(u => u.id === id);

    if (!user) {
        return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    if (name) {
        user.name = name;
    }
    
    if (email) {
        user.email = email;
    }

    res.json(user);
});

app.delete('/users-delete', (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Token não fornecido' });
    }

    const validToken = tokens.find(t => t.accessToken === token);

    if (!validToken) {
        return res.status(403).json({ message: 'Token inválido' });
    }

    const { id } = req.body;

    if (!id) {
        return res.status(400).json({ message: 'ID é obrigatório' });
    }

    const userIndex = users.findIndex(u => u.id === id);

    if (userIndex === -1) {
        return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    users.splice(userIndex, 1);
    res.json({ message: 'Usuário deletado com sucesso' });
});