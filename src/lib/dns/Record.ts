import { DNSClass } from './DNSClass';
import { RecordType } from './RecordType';

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

function serialiseName(name: string): Buffer {
  const labels = name
    .replace(/\.$/, '')
    .split('.')
    .map((label) => {
      const labelSerialised = Buffer.from(label);
      const lengthPrefix = Buffer.from([labelSerialised.byteLength]);
      return Buffer.concat([lengthPrefix, labelSerialised]);
    });
  return Buffer.concat([...labels, Buffer.alloc(1)]);
}
