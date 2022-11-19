import { DnsClass } from './DnsClass';
import { serialiseName } from './name';
import { Question } from './Question';

interface RecordFields {
  readonly name: string;
  readonly type: number;
  readonly class: DnsClass;
  readonly ttl: number;
  readonly dataSerialised: Buffer;
}

/**
 * A "raw" DNS record with its data unserialised.
 */
export class Record {
  constructor(
    public readonly name: string,
    public readonly type: number,
    public readonly class_: DnsClass,
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

  public shallowCopy(partialRecord: Partial<RecordFields>): Record {
    const name = partialRecord.name ?? this.name;
    const type = partialRecord.type ?? this.type;
    const class_ = partialRecord.class ?? this.class_;
    const ttl = partialRecord.ttl ?? this.ttl;
    const dataSerialised = partialRecord.dataSerialised ?? this.dataSerialised;
    return new Record(name, type, class_, ttl, dataSerialised);
  }

  /**
   * Generate a question that this specific record would answer.
   *
   * It may or may not equal the question in the original query message.
   */
  public makeQuestion(): Question {
    return new Question(this.name, this.type, this.class_);
  }
}
