/* eslint-disable import/exports-last */
import { DnsClass } from '../lib/dns/ianaClasses.js';
import { DnsRecord } from '../lib/dns/DnsRecord.js';
import { Question } from '../lib/dns/Question.js';
import { RrSet } from '../lib/dns/RrSet.js';
import { IANA_RR_TYPE_IDS, IANA_RR_TYPE_NAMES } from '../lib/dns/ianaRrTypes.js';

export const RECORD_TLD = 'com.';

// TXT RDATA serialisation according to RFC 1035 (Section 3.3.14)
export const RECORD_DATA_TXT_DATA = Buffer.from('foo');
const RECORD_DATA = Buffer.allocUnsafe(RECORD_DATA_TXT_DATA.byteLength + 1);
RECORD_DATA.writeUint8(RECORD_DATA_TXT_DATA.byteLength);
RECORD_DATA_TXT_DATA.copy(RECORD_DATA, 1);

export const RECORD = new DnsRecord(
  `example.${RECORD_TLD}`,
  IANA_RR_TYPE_IDS.TXT,
  DnsClass.IN,
  // eslint-disable-next-line @typescript-eslint/no-magic-numbers
  42,
  RECORD_DATA,
);

export const RECORD_TYPE_STR = IANA_RR_TYPE_NAMES[RECORD.typeId];
export const RECORD_CLASS_STR = 'IN';

export const QUESTION = new Question(RECORD.name, RECORD.typeId, RECORD.classId);

export const RRSET = RrSet.init(QUESTION, [RECORD]);
