import type { DnssecRecord } from '../../lib/dnssecRecords';
import type { DnssecRecordData } from '../../lib/rdata/DnssecRecordData';

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
