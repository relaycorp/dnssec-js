import { createHash } from 'node:crypto';

import { DigestType } from '../../DigestType';
import { generateDigest, getNodejsHashAlgo, getNodejsHashAlgorithmFromDnssecAlgo } from './hashing';
import { DnssecAlgorithm } from '../../DnssecAlgorithm';

describe('getNodejsHashAlgorithmFromDnssecAlgo', () => {
  test.each([
    [DnssecAlgorithm.DSA, 'sha1'],
    [DnssecAlgorithm.RSASHA1, 'sha1'],
    [DnssecAlgorithm.RSASHA256, 'sha256'],
    [DnssecAlgorithm.RSASHA512, 'sha512'],
    [DnssecAlgorithm.ECDSAP256SHA256, 'sha256'],
    [DnssecAlgorithm.ECDSAP384SHA384, 'sha384'],
    [DnssecAlgorithm.ED25519, null],
    [DnssecAlgorithm.ED448, null],
  ])('%s should use %s', (dnssecAlgo, nodejsHashAlgo) => {
    expect(getNodejsHashAlgorithmFromDnssecAlgo(dnssecAlgo)).toEqual(nodejsHashAlgo);
  });

  test('Non-IANA algorithms should not be supported', () => {
    const algorithm = 0;
    expect(() => getNodejsHashAlgorithmFromDnssecAlgo(algorithm)).toThrowWithMessage(
      Error,
      `Unsupported DNSSEC algorithm (${algorithm})`,
    );
  });
});

describe('getNodejsHashAlgo', () => {
  test.each([
    ['sha1', DigestType.SHA1],
    ['sha256', DigestType.SHA256],
    ['sha384', DigestType.SHA384],
  ])('%s should be supported', (nodejsHashAlgo, dnssecHashAlgo) => {
    const algorithmName = getNodejsHashAlgo(dnssecHashAlgo);

    expect(algorithmName).toEqual(nodejsHashAlgo);
  });

  test('Non-IANA algorithms should not be supported', () => {
    const algorithm = 0;
    expect(() => getNodejsHashAlgo(algorithm)).toThrowWithMessage(
      Error,
      `Unsupported hashing algorithm ${algorithm}`,
    );
  });
});

describe('generateDigest', () => {
  const PLAINTEXT = Buffer.from('hello world');

  test.each([
    ['sha1', DigestType.SHA1],
    ['sha256', DigestType.SHA256],
    ['sha384', DigestType.SHA384],
  ])('%s', (nodejsHashAlgo, dnssecHashAlgo) => {
    const digest = generateDigest(PLAINTEXT, dnssecHashAlgo);

    const hash = createHash(nodejsHashAlgo);
    hash.update(PLAINTEXT);
    const expectedDigest = hash.digest();

    expect(digest).toEqual(expectedDigest);
  });
});
