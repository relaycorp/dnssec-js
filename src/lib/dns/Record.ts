import { DNSClass } from './DNSClass';
import { serialiseName } from './name';

/**
 * A "raw" DNS record with its data unserialised.
 */
export class Record {
  constructor(
    public readonly name: string,
    public readonly type: number,
    public readonly class_: DNSClass,
    public readonly ttl: number,
    public readonly dataSerialised: Buffer,
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
    dataLengthSerialised.writeUInt16BE(this.dataSerialised.length);

    return Buffer.concat([
      labelsSerialised,
      typeSerialised,
      classSerialised,
      ttlSerialised,
      dataLengthSerialised,
      this.dataSerialised,
    ]);
  }
}
