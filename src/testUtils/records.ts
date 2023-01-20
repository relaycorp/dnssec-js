import type { DnssecRecord } from '../lib/records/dnssecRecords.js';
import type { DnssecRecordData } from '../lib/records/DnssecRecordData.js';

export function copyDnssecRecordData<
  Rdata extends DnssecRecordData,
  DnsRecord extends DnssecRecord<Rdata>,
>(originalRecord: DnsRecord, newData: Rdata): DnsRecord {
  // eslint-disable-next-line @typescript-eslint/consistent-type-assertions
  return {
    data: newData,
    record: originalRecord.record.shallowCopy({ data: newData.serialise() }),
  } as DnsRecord;
}
