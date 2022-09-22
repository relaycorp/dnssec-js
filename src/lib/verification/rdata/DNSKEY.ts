import { Parser } from 'binary-parser';
import { createPublicKey, KeyObject } from 'node:crypto';

import { DNSSECAlgorithm } from '../../DNSSECAlgorithm';
import { DNSKEYFlags } from '../../DNSKEYFlags';
import { InvalidRdataError } from '../../errors';

const PARSER = new Parser()
  .endianness('big')
  .bit8('zoneKey')
  .bit8('secureEntryPoint')
  .uint8('protocol')
  .uint8('algorithm')
  .buffer('publicKey', { readUntil: 'eof' });

export class DNSKEY {
  public static deserialise(serialisation: Buffer): DNSKEY {
    let parsingResult: any;
    try {
      parsingResult = PARSER.parse(serialisation);
    } catch (_) {
      throw new InvalidRdataError('DNSKEY data is malformed');
    }
    const publicKey = parsePublicKey(parsingResult.publicKey);
    const flags: DNSKEYFlags = {
      zoneKey: !!parsingResult.zoneKey,
      secureEntryPoint: !!parsingResult.secureEntryPoint,
    };
    return new DNSKEY(publicKey, parsingResult.protocol, parsingResult.algorithm, flags);
  }

  constructor(
    public readonly publicKey: KeyObject,
    public readonly protocol: number,
    public readonly algorithm: DNSSECAlgorithm,
    public readonly flags: DNSKEYFlags,
  ) {}
}

function parsePublicKey(publicKeySerialized: Buffer): KeyObject {
  if (publicKeySerialized.byteLength === 0) {
    throw new InvalidRdataError('DNSKEY data is missing public key');
  }
  return createPublicKey({
    key: publicKeySerialized,
    format: 'der',
    type: 'spki',
  });
}
