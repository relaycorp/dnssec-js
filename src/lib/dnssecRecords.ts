import type { DnssecRecordData } from './rdata/DnssecRecordData.js';
import type { DnsRecord } from './dns/DnsRecord.js';
import type { DnskeyData } from './rdata/DnskeyData.js';
import type { DsData } from './rdata/DsData.js';
import type { RrsigData } from './rdata/RrsigData.js';

export interface DnssecRecord<Data extends DnssecRecordData> {
  readonly record: DnsRecord;
  readonly data: Data;
}

export type DnskeyRecord = DnssecRecord<DnskeyData>;

export type DsRecord = DnssecRecord<DsData>;

export type RrsigRecord = DnssecRecord<RrsigData>;
