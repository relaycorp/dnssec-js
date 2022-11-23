import { DnssecRecordData } from './rdata/DnssecRecordData';
import { Record } from './dns/Record';
import { DnskeyData } from './rdata/DnskeyData';
import { DsData } from './rdata/DsData';
import { RrsigData } from './rdata/RrsigData';

export interface DnssecRecord<Data extends DnssecRecordData> {
  readonly record: Record;
  readonly data: Data;
}

export type DnskeyRecord = DnssecRecord<DnskeyData>;

export type DsRecord = DnssecRecord<DsData>;

export type RrsigRecord = DnssecRecord<RrsigData>;
