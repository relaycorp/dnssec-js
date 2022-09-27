import { Parser } from 'binary-parser';
import { fromUnixTime } from 'date-fns';

import { DNSSECAlgorithm } from '../../DNSSECAlgorithm';
import { NAME_PARSER_OPTIONS } from '../../dns/name';
import { InvalidRdataError } from '../../errors';

const PARSER = new Parser()
  .endianness('big')
  .uint16('type')
  .uint8('algorithm')
  .uint8('labels')
  .uint32('ttl')
  .uint32('signatureExpiry')
  .uint32('signatureInception')
  .uint16('keyTag')
  .array('signerName', NAME_PARSER_OPTIONS)
  .buffer('signature', { readUntil: 'eof' });

export class RRSIG {
  static deserialise(serialisation: Buffer): RRSIG {
    let parsingResult: any;
    try {
      parsingResult = PARSER.parse(serialisation);
    } catch (_) {
      throw new InvalidRdataError('RRSIG data is malformed');
    }

    if (parsingResult.signature.byteLength === 0) {
      throw new InvalidRdataError('Signature is empty');
    }

    return new RRSIG(
      parsingResult.type,
      parsingResult.algorithm,
      parsingResult.labels,
      parsingResult.ttl,
      fromUnixTime(parsingResult.signatureExpiry),
      fromUnixTime(parsingResult.signatureInception),
      parsingResult.keyTag,
      parsingResult.signerName,
      parsingResult.signature,
    );
  }

  constructor(
    public readonly type: number,
    public readonly algorithm: DNSSECAlgorithm,
    public readonly labels: number,
    public readonly ttl: number,
    public readonly signatureExpiry: Date,
    public readonly signatureInception: Date,
    public readonly keyTag: number,
    public readonly signerName: string,
    public readonly signature: Buffer,
  ) {}
}
