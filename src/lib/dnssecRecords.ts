import type { DnssecRecordData } from './rdata/DnssecRecordData';
import type { DnsRecord } from './dns/DnsRecord';
import type { DnskeyData } from './rdata/DnskeyData';
import type { DsData } from './rdata/DsData';
import type { RrsigData } from './rdata/RrsigData';

export interface DnssecRecord<Data extends DnssecRecordData> {
  readonly record: DnsRecord;
  readonly data: Data;
}

export type DnskeyRecord = DnssecRecord<DnskeyData>;

export type DsRecord = DnssecRecord<DsData>;

export type RrsigRecord = DnssecRecord<RrsigData>;
