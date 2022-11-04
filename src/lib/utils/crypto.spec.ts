import { createHash } from 'node:crypto';

import { DigestType } from '../DigestType';
import { getNodejsHashAlgo, generateDigest } from './crypto';

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
