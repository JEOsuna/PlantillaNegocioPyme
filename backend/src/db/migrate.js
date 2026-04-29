import 'dotenv/config';
import fs from 'node:fs';
import { db } from './index.js';

const sql = fs.readFileSync(new URL('./schema.sql', import.meta.url), 'utf8');
await db.query(sql);
console.log('✓ schema applied');
await db.end();
