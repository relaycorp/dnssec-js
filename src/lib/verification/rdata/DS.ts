import { Parser } from 'binary-parser';

import { DNSSECAlgorithm } from '../../DNSSECAlgorithm';
import { DigestType } from '../../DigestType';
import { DNSSECValidationError, InvalidRdataError } from '../../errors';
import { DNSKEY } from './DNSKEY';
import { hashPublicKey } from '../../utils/crypto';

const PARSER = new Parser()
  .endianness('big')
  .uint16('keyTag')
  .uint8('algorithm')
  .uint8('digestType')
  .buffer('digest', { readUntil: 'eof' });

export class DS {
  static deserialise(serialisation: Buffer): DS {
    let parsingResult: any;
    try {
      parsingResult = PARSER.parse(serialisation);
    } catch (_) {
      throw new InvalidRdataError('DS data is malformed');
    }
    if (parsingResult.digest.byteLength === 0) {
      throw new InvalidRdataError('DS data is missing digest');
    }
    return new DS(
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

  /**
   * Verify that the `key` corresponds to the current DS data.
   *
   * @param key
   * @throws {DNSSECValidationError}
   */
  public verifyDnskey(key: DNSKEY): void {
    if (!key.flags.zoneKey) {
      throw new DNSSECValidationError('Zone Key flag is off');
    }
    if (key.protocol !== 3) {
      throw new DNSSECValidationError(`Protocol must be 3 (got ${key.protocol})`);
    }
    if (key.algorithm !== this.algorithm) {
      throw new DNSSECValidationError(
        `DS uses algorithm ${this.algorithm} but DNSKEY uses algorithm ${key.algorithm}`,
      );
    }
    const digest = hashPublicKey(key.publicKey, this.digestType);
    if (!digest.equals(this.digest)) {
      throw new DNSSECValidationError('DNSKEY key digest does not match that of DS data');
    }
  }
}
