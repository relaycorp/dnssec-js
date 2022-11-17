import { createPublicKey, generateKeyPair, KeyObject } from 'node:crypto';
import { promisify } from 'node:util';

import { deserialisePublicKey, serialisePublicKey } from './keySerialisation';
import { DnssecAlgorithm } from '../DnssecAlgorithm';

// Parameters taken from https://www.rfc-editor.org/rfc/rfc5702.html#section-6.1
const RSA_EXPONENT = 'AQAB';
const RSA_MODULUS =
  'wVwaxrHF2CK64aYKRUibLiH30KpPuPBjel7E8ZydQW1HYWHfoGmidzC2RnhwCC293hCzw-TFR2nqn8OVSY5t2Q';

describe('serialisePublicKey', () => {
  describe('RSA', () => {
    test('Exponent length prefix should span 1 octet if exponent spans up to 255 octets', () => {
      const exponentLength = 255;
      const exponent = Buffer.alloc(exponentLength, 'f').toString('base64url');
      const publicKey = importRsaPubKey(exponent, RSA_MODULUS);

      const serialisation = serialisePublicKey(publicKey);

      expect(serialisation[0]).toEqual(exponentLength);
    });

    test('Exponent length prefix should span 2 octets if exponent spans more than 255 octets', () => {
      const exponentLength = 256;
      const exponent = Buffer.alloc(exponentLength, 'f').toString('base64url');
      const publicKey = importRsaPubKey(exponent, RSA_MODULUS);

      const serialisation = serialisePublicKey(publicKey);

      expect(serialisation[0]).toEqual(0);
      expect(serialisation.readUint16BE(1)).toEqual(exponentLength);
    });

    test('Exponent should follow its length prefix', () => {
      const publicKey = importRsaPubKey(RSA_EXPONENT, RSA_MODULUS);

      const serialisation = serialisePublicKey(publicKey);

      const exponent = serialisation.subarray(1, serialisation[0] + 1);
      expect(exponent.toString('base64url')).toEqual(RSA_EXPONENT);
    });

    test('Modulus should follow exponent', () => {
      const publicKey = importRsaPubKey(RSA_EXPONENT, RSA_MODULUS);

      const serialisation = serialisePublicKey(publicKey);

      const modulus = serialisation.subarray(serialisation[0] + 1);
      expect(modulus.toString('base64url')).toEqual(RSA_MODULUS);
    });
  });

  test('Error should be thrown if algorithm is unsupported', async () => {
    const generateKeyPairAsync = promisify(generateKeyPair);
    const algorithm = 'x448';
    const keyPair = await generateKeyPairAsync(algorithm);

    expect(() => serialisePublicKey(keyPair.publicKey)).toThrowWithMessage(
      Error,
      `Unsupported algorithm (${algorithm})`,
    );
  });
});

describe('deserialisePublicKey', () => {
  describe('RSA', () => {
    test('Serialisation should contain at least 3 octets', () => {
      const serialisation = Buffer.allocUnsafe(2);

      expect(() =>
        deserialisePublicKey(serialisation, DnssecAlgorithm.RSASHA256),
      ).toThrowWithMessage(Error, 'Public key should contain at least 3 octets (got 2)');
    });

    test.each([1, 255, 256])(
      'Key with exponent spanning %s octets should be deserialised',
      (exponentLength) => {
        const exponent = Buffer.alloc(exponentLength, 'f').toString('base64url');
        const serialisation = serialisePublicKey(importRsaPubKey(exponent, RSA_MODULUS));

        const publicKey = deserialisePublicKey(serialisation, DnssecAlgorithm.RSASHA256);

        const publicKeyJwk = publicKey.export({ format: 'jwk' });
        expect(publicKeyJwk.e).toEqual(exponent);
        expect(publicKeyJwk.n).toEqual(RSA_MODULUS);
      },
    );

    test.each([DnssecAlgorithm.RSASHA1, DnssecAlgorithm.RSASHA256, DnssecAlgorithm.RSASHA512])(
      'RSA algorithm %s should be deserialised',
      (dnssecAlgorithm) => {
        const serialisation = serialisePublicKey(importRsaPubKey(RSA_EXPONENT, RSA_MODULUS));

        const publicKey = deserialisePublicKey(serialisation, dnssecAlgorithm);

        const publicKeyJwk = publicKey.export({ format: 'jwk' });
        expect(publicKeyJwk.e).toEqual(RSA_EXPONENT);
        expect(publicKeyJwk.n).toEqual(RSA_MODULUS);
      },
    );
  });

  test('Error should be thrown if algorithm is unsupported', () => {
    const invalidAlgorithm = 999 as any;
    expect(() => deserialisePublicKey(Buffer.allocUnsafe(1), invalidAlgorithm)).toThrowWithMessage(
      Error,
      `Unsupported algorithm (${invalidAlgorithm})`,
    );
  });
});

function importRsaPubKey(exponent: string, modulus: string): KeyObject {
  return createPublicKey({
    key: { n: modulus, e: exponent, kty: 'RSA' },
    format: 'jwk',
  });
}
