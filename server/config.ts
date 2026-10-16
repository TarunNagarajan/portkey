import dotenv from 'dotenv';
import { parseConfiguration } from './configuration.js';

if (process.env.PORTKEY_LOAD_DOTENV !== 'false') dotenv.config({ quiet: true });

export const config = parseConfiguration(process.env);
