import type { DnsRecord } from '../utils/dns/DnsRecord.js';

import type { DnssecRecordData } from './DnssecRecordData.js';
import type { DnskeyData } from './DnskeyData.js';
import type { DsData } from './DsData.js';
import type { RrsigData } from './RrsigData.js';

export interface DnssecRecord<Data extends DnssecRecordData> {
  readonly record: DnsRecord;
  readonly data: Data;
}

export type DnskeyRecord = DnssecRecord<DnskeyData>;

export type DsRecord = DnssecRecord<DsData>;

export type RrsigRecord = DnssecRecord<RrsigData>;
