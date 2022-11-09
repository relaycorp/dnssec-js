import { DNSClass } from '../lib/dns/DNSClass';
import { Record } from '../lib/dns/Record';
import { Question } from '../lib/dns/Question';
import { RRSet } from '../lib/dns/RRSet';

export const RECORD_TLD = 'com.';

export const RECORD_TYPE_STR = 'TXT';
export const RECORD_CLASS_STR = 'IN';

// TXT RDATA serialisation according to RFC 1035 (Section 3.3.14)
export const RECORD_DATA_TXT_DATA = Buffer.from('foo');
export const RECORD_DATA = Buffer.allocUnsafe(RECORD_DATA_TXT_DATA.byteLength + 1);
RECORD_DATA.writeUint8(RECORD_DATA_TXT_DATA.byteLength);
RECORD_DATA_TXT_DATA.copy(RECORD_DATA, 1);

export const RECORD = new Record(
  `example.${RECORD_TLD}`,
  16, // TXT
  DNSClass.IN,
  42,
  RECORD_DATA,
);

export const QUESTION: Question = {
  class: RECORD.class_,
  name: RECORD.name,
  type: RECORD.type,
};

export const RRSET = RRSet.init(QUESTION, [RECORD]);
