import { createHash, generateKeyPair, KeyObject } from 'node:crypto';
import { promisify } from 'node:util';

import { DigestType } from '../DigestType';
import { derSerialisePublicKey, getNodejsHashAlgo, hashPublicKey } from './crypto';

const generateKeyPairAsync = promisify(generateKeyPair);
let publicKey: KeyObject;
beforeAll(async () => {
  const keyPair = await generateKeyPairAsync('rsa-pss', { modulusLength: 2048 });
  publicKey = keyPair.publicKey;
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

test('derSerialisePublicKey', async () => {
  expect(derSerialisePublicKey(publicKey)).toEqual(
    publicKey.export({ format: 'der', type: 'spki' }),
  );
});

describe('hashPublicKey', () => {
  test.each([
    ['sha1', DigestType.SHA1],
    ['sha256', DigestType.SHA256],
    ['sha384', DigestType.SHA384],
  ])('%s', (nodejsHashAlgo, dnssecHashAlgo) => {
    const digest = hashPublicKey(publicKey, dnssecHashAlgo);

    const hash = createHash(nodejsHashAlgo);
    hash.update(derSerialisePublicKey(publicKey));
    const expectedDigest = hash.digest();

    expect(digest).toEqual(expectedDigest);
  });
});
