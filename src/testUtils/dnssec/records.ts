import type { DnssecRecord } from '../../lib/dnssecRecords';
import type { DnssecRecordData } from '../../lib/rdata/DnssecRecordData';

export function copyDnssecRecordData<D extends DnssecRecordData, R extends DnssecRecord<D>>(
  originalRecord: R,
  newData: D,
): R {
  return {
    data: newData,
    record: originalRecord.record.shallowCopy({ dataSerialised: newData.serialise() }),
  } as R;
}
