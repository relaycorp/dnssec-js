import { DNSClass } from '../lib/DNSClass.js';

export const RECORD_TYPE = 'TXT';
export const RECORD_TYPE_ID = 16;
export const RECORD_CLASS = DNSClass.IN;
export const RECORD_CLASS_STR = 'IN';
export const RECORD_NAME = 'example.com';
export const RECORD_TTL = 42;

// RDATA serialisation according to RFC1035 (Section 3.3.14)
export const RECORD_DATA_TXT_DATA = Buffer.from('foo');
export const RECORD_DATA = Buffer.allocUnsafe(RECORD_DATA_TXT_DATA.byteLength + 1);
RECORD_DATA.writeUint8(RECORD_DATA_TXT_DATA.byteLength);
RECORD_DATA_TXT_DATA.copy(RECORD_DATA, 1);
