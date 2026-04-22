import express from 'express';
import { User } from './data';

export const app = express();
const PORT = 4025;
app.use(express.json());

import './routes';

app.listen(PORT, () => {
  console.log(`tá rodando em: http://localhost:${PORT}`);
});