import { DnsClass } from '../lib/dns/ianaClasses';
import { Record } from '../lib/dns/Record';
import { Question } from '../lib/dns/Question';
import { RRSet } from '../lib/dns/RRSet';
import { IANA_RR_TYPE_IDS, IANA_RR_TYPE_NAMES } from '../lib/dns/ianaRrTypes';

export const RECORD_TLD = 'com.';

// TXT RDATA serialisation according to RFC 1035 (Section 3.3.14)
export const RECORD_DATA_TXT_DATA = Buffer.from('foo');
const RECORD_DATA = Buffer.allocUnsafe(RECORD_DATA_TXT_DATA.byteLength + 1);
RECORD_DATA.writeUint8(RECORD_DATA_TXT_DATA.byteLength);
RECORD_DATA_TXT_DATA.copy(RECORD_DATA, 1);

export const RECORD = new Record(
  `example.${RECORD_TLD}`,
  IANA_RR_TYPE_IDS.TXT,
  DnsClass.IN,
  42,
  RECORD_DATA,
);

export const RECORD_TYPE_STR = IANA_RR_TYPE_NAMES[RECORD.typeId];
export const RECORD_CLASS_STR = 'IN';

export const QUESTION = new Question(RECORD.name, RECORD.typeId, RECORD.class_);

export const RRSET = RRSet.init(QUESTION, [RECORD]);
