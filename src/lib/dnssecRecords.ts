import { DnssecRecordData } from './rdata/DnssecRecordData';
import { Record } from './dns/Record';
import { DnskeyData } from './rdata/DnskeyData';
import { DsData } from './rdata/DsData';
import { RrsigData } from './rdata/RrsigData';

export interface DnssecRecord<Data extends DnssecRecordData> {
  readonly record: Record;
  readonly data: Data;
}

export interface DnskeyRecord extends DnssecRecord<DnskeyData> {}

export interface DsRecord extends DnssecRecord<DsData> {}

export interface RrsigRecord extends DnssecRecord<RrsigData> {}
