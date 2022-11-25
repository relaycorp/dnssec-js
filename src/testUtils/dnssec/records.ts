import type { DnssecRecord } from '../../lib/dnssecRecords.js';
import type { DnssecRecordData } from '../../lib/rdata/DnssecRecordData.js';

export function copyDnssecRecordData<
  Rdata extends DnssecRecordData,
  DnsRecord extends DnssecRecord<Rdata>,
>(originalRecord: DnsRecord, newData: Rdata): DnsRecord {
  // eslint-disable-next-line @typescript-eslint/consistent-type-assertions
  return {
    data: newData,
    record: originalRecord.record.shallowCopy({ dataSerialised: newData.serialise() }),
  } as DnsRecord;
}
