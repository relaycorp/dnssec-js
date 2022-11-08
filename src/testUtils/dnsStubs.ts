import { DNSClass } from '../lib/dns/DNSClass';
import { Record } from '../lib/dns/Record';
import { Question } from '../lib/dns/Question';

export const RECORD_TLD = 'com.';
export const RECORD_LABEL = 'example.';

export const RECORD_NAME = `${RECORD_LABEL}${RECORD_TLD}`;
const RECORD_TYPE = 16; // TXT
export const RECORD_TYPE_STR = 'TXT';
const RECORD_CLASS = DNSClass.IN;
export const RECORD_CLASS_STR = 'IN';
const RECORD_TTL = 42;

// TXT RDATA serialisation according to RFC1035 (Section 3.3.14)
export const RECORD_DATA_TXT_DATA = Buffer.from('foo');
export const RECORD_DATA = Buffer.allocUnsafe(RECORD_DATA_TXT_DATA.byteLength + 1);
RECORD_DATA.writeUint8(RECORD_DATA_TXT_DATA.byteLength);
RECORD_DATA_TXT_DATA.copy(RECORD_DATA, 1);

export const RECORD = new Record(RECORD_NAME, RECORD_TYPE, RECORD_CLASS, RECORD_TTL, RECORD_DATA);

export const QUESTION: Question = {
  class: RECORD.class_,
  name: RECORD.name,
  type: RECORD.type,
};
