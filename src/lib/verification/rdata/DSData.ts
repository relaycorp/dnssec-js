import { Parser } from 'binary-parser';

import { DNSSECAlgorithm } from '../../DNSSECAlgorithm';
import { DigestType } from '../../DigestType';
import { MalformedRdata } from '../../errors';

const PARSER = new Parser()
  .endianness('big')
  .uint16('keyTag')
  .uint8('algorithm')
  .uint8('digestType')
  .buffer('digest', { readUntil: 'eof' });

export class DSData {
  static deserialise(serialisation: Buffer): DSData {
    let parsingResult: any;
    try {
      parsingResult = PARSER.parse(serialisation);
    } catch (_) {
      throw new MalformedRdata('DS data is malformed');
    }
    return new DSData(
      parsingResult.keyTag,
      parsingResult.algorithm,
      parsingResult.digestType,
      parsingResult.digest,
    );
  }

  constructor(
    readonly keyTag: number,
    readonly algorithm: DNSSECAlgorithm,
    readonly digestType: DigestType,
    readonly digest: Buffer,
  ) {}
}
