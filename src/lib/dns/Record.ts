import { DNSClass } from './DNSClass';
import { RecordType } from './RecordType';
import { serialiseName } from './name';

export class Record {
  constructor(
    public readonly name: string,
    public readonly type: RecordType,
    public readonly class_: DNSClass,
    public readonly ttl: number,
    public readonly data: Buffer,
  ) {}

  public serialise(): Buffer {
    const labelsSerialised = serialiseName(this.name);

    const typeSerialised = Buffer.allocUnsafe(2);
    typeSerialised.writeUInt16BE(this.type);

    const classSerialised = Buffer.allocUnsafe(2);
    classSerialised.writeUInt16BE(this.class_);

    const ttlSerialised = Buffer.allocUnsafe(4);
    ttlSerialised.writeUInt32BE(this.ttl);

    const dataLengthSerialised = Buffer.allocUnsafe(2);
    dataLengthSerialised.writeUInt16BE(this.data.length);

    return Buffer.concat([
      labelsSerialised,
      typeSerialised,
      classSerialised,
      ttlSerialised,
      dataLengthSerialised,
      this.data,
    ]);
  }
}
