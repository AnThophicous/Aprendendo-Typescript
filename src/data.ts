import { generateToken } from './token-generator';

export type User = {
  id: number;
  name: string;
  email: string;
};

export const users: User[] = [
  { id: 1, name: 'Ada Lovelace', email: 'ada@example.com' },
  { id: 2, name: 'Grace Hopper', email: 'grace@example.com' },
];

export type Tokens = {
    accessToken: string;
};

export const tokens: Tokens[] = [
    { accessToken: generateToken() },
];

