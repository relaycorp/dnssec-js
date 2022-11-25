import type { Codec } from '@leichtgewicht/dns-packet';
import { enc } from '@leichtgewicht/dns-packet';

import { lengthPrefixRdata } from '../utils/dns';

import type { DnsClass, DnsClassIdOrName } from './ianaClasses';
import { getDnsClassId } from './ianaClasses';
import { normaliseName, serialiseName } from './name';
import { Question } from './Question';
import type { IanaRrTypeIdOrName } from './ianaRrTypes';
import { getRrTypeId, getRrTypeName } from './ianaRrTypes';
import { DnsError } from './DnsError';

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
  public readonly name: string;

  public readonly typeId: number;

  public readonly class_: DnsClass;

  public readonly dataSerialised: Buffer;

  /**
   * @internal
   */
  public readonly dataFields: any;

  constructor(
    name: string,
    typeIdOrName: IanaRrTypeIdOrName,
    classIdOrName: DnsClassIdOrName,
    public readonly ttl: number,
    data: Buffer | object,
  ) {
    this.name = normaliseName(name);
    this.typeId = getRrTypeId(typeIdOrName);
    this.class_ = getDnsClassId(classIdOrName);

    const typeName = getRrTypeName(typeIdOrName);
    const dnsPacketCodec = enc(typeName);
    if (data instanceof Buffer) {
      this.dataSerialised = data;
      this.dataFields = deserialiseRdata(data, typeName, dnsPacketCodec);
    } else {
      this.dataSerialised = serialiseRdata(data, typeName, dnsPacketCodec);
      this.dataFields = data;
    }
  }

  public serialise(ttl: number | null = null): Buffer {
    const labelsSerialised = serialiseName(this.name);

    const typeSerialised = Buffer.allocUnsafe(2);
    typeSerialised.writeUInt16BE(this.typeId);

    const classSerialised = Buffer.allocUnsafe(2);
    classSerialised.writeUInt16BE(this.class_);

    const ttlSerialised = Buffer.allocUnsafe(4);
    ttlSerialised.writeUInt32BE(ttl ?? this.ttl);

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
    const type = partialRecord.type ?? this.typeId;
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
    return new Question(this.name, this.typeId, this.class_);
  }
}

function deserialiseRdata(serialisation: Buffer, typeName: string, codec: Codec<any>): any {
  const lengthPrefixedData = lengthPrefixRdata(serialisation);
  try {
    return codec.decode(lengthPrefixedData);
  } catch {
    throw new DnsError(`Data for record type ${typeName} is malformed`);
  }
}

function serialiseRdata(data: any, typeName: string, codec: Codec<any>): Buffer {
  let lengthPrefixedData: Uint8Array;
  try {
    lengthPrefixedData = codec.encode(data);
  } catch {
    throw new DnsError(`Data for record type ${typeName} is invalid`);
  }
  return Buffer.from(lengthPrefixedData.subarray(2));
}
