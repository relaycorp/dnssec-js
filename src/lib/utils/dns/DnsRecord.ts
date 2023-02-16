/* eslint-disable @typescript-eslint/no-magic-numbers */

import { enc, type Codec } from '@leichtgewicht/dns-packet';

import { lengthPrefixRdata } from './rdata.js';
import { getDnsClassId, type DnsClass, type DnsClassIdOrName } from './ianaClasses.js';
import { normaliseName, serialiseName } from './name.js';
import { Question } from './Question.js';
import { getRrTypeId, getRrTypeName, type IanaRrTypeIdOrName } from './ianaRrTypes.js';
import { DnsError } from './DnsError.js';

interface RecordFields {
  readonly name: string;
  readonly type: number;
  readonly class: DnsClass;
  readonly ttl: number;
  readonly data: unknown;
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

/**
 * A "raw" DNS record with its data unserialised.
 *
 * We're using the `Dns` prefix to avoid shadowing the TypeScript type `Record`.
 */
export class DnsRecord {
  public readonly name: string;

  public readonly typeId: number;

  public readonly classId: DnsClass;

  public readonly dataSerialised: Buffer;

  public readonly dataFields: any;

  public constructor(
    name: string,
    typeIdOrName: IanaRrTypeIdOrName,
    classIdOrName: DnsClassIdOrName,
    public readonly ttl: number,
    data: unknown,
  ) {
    this.name = normaliseName(name);
    this.typeId = getRrTypeId(typeIdOrName);
    this.classId = getDnsClassId(classIdOrName);

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
    classSerialised.writeUInt16BE(this.classId);

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

  public shallowCopy(partialRecord: Partial<RecordFields>): DnsRecord {
    const name = partialRecord.name ?? this.name;
    const type = partialRecord.type ?? this.typeId;
    const classId = partialRecord.class ?? this.classId;
    const ttl = partialRecord.ttl ?? this.ttl;
    const data = partialRecord.data ?? this.dataSerialised;
    return new DnsRecord(name, type, classId, ttl, data);
  }

  /**
   * Generate a question that this specific record would answer.
   *
   * It may or may not equal the question in the original query message.
   */
  public makeQuestion(): Question {
    return new Question(this.name, this.typeId, this.classId);
  }
}
