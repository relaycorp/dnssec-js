import { createHash, KeyObject } from 'node:crypto';

import { DigestType } from '../DigestType';
import { getNodejsHashAlgo, hashPublicKey } from './crypto';
import { generateRSAKeyPair } from '../../testUtils/crypto';
import { serialisePublicKey } from './keySerialisation';

let publicKey: KeyObject;
beforeAll(async () => {
  const keyPair = await generateRSAKeyPair();
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

describe('hashPublicKey', () => {
  test.each([
    ['sha1', DigestType.SHA1],
    ['sha256', DigestType.SHA256],
    ['sha384', DigestType.SHA384],
  ])('%s', (nodejsHashAlgo, dnssecHashAlgo) => {
    const digest = hashPublicKey(publicKey, dnssecHashAlgo);

    const hash = createHash(nodejsHashAlgo);
    hash.update(serialisePublicKey(publicKey));
    const expectedDigest = hash.digest();

    expect(digest).toEqual(expectedDigest);
  });
});
