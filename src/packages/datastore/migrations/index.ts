import { CreateDatabase1717127220001 } from './1.CreateDatabase.js';
import { Presentations1758721139150 } from './2.Presentations.js';
import { Verifiers1759493650000 } from './3.Verifiers.js';
import { DIDPath1760691999150 } from './4.DIDPath.js';

export * from './migration-functions.js'

export const migrations = [
  CreateDatabase1717127220001,
  Presentations1758721139150,
  Verifiers1759493650000,
  DIDPath1760691999150
]
