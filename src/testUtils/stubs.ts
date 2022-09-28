import { DNSClass } from '../lib/dns/DNSClass';
import { Record } from '../lib/dns/Record';

export const RECORD_NAME = 'example.com.';
export const RECORD_TYPE = 'TXT';
export const RECORD_TYPE_ID = 16; // TXT
export const RECORD_CLASS = DNSClass.IN;
export const RECORD_CLASS_STR = 'IN';
export const RECORD_TTL = 42;

// TXT RDATA serialisation according to RFC1035 (Section 3.3.14)
export const RECORD_DATA_TXT_DATA = Buffer.from('foo');
export const RECORD_DATA = Buffer.allocUnsafe(RECORD_DATA_TXT_DATA.byteLength + 1);
RECORD_DATA.writeUint8(RECORD_DATA_TXT_DATA.byteLength);
RECORD_DATA_TXT_DATA.copy(RECORD_DATA, 1);

export const RECORD = new Record(RECORD_NAME, RECORD_TYPE_ID, DNSClass.IN, RECORD_TTL, RECORD_DATA);
