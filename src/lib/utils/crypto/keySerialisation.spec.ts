import type { KeyObject } from 'node:crypto';
import { createPublicKey } from 'node:crypto';

import { DnssecAlgorithm } from '../../DnssecAlgorithm';
import { DnssecError } from '../../DnssecError';

import { deserialisePublicKey, serialisePublicKey } from './keySerialisation';

// Parameters taken from https://www.rfc-editor.org/rfc/rfc5702.html#section-6.1
const RSA_PUB_KEY = {
  exponent: 'AQAB',
  modulus: 'wVwaxrHF2CK64aYKRUibLiH30KpPuPBjel7E8ZydQW1HYWHfoGmidzC2RnhwCC293hCzw-TFR2nqn8OVSY5t2Q',
};

// Parameters taken from https://www.rfc-editor.org/rfc/rfc6605.html#section-6
const ECDSA_PUB_KEYS = {
  p256: 'GojIhhXUN_u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP-e-MAnLr-Wi9xMWyQLc8NAA',

  p384:
    'xKYaNhWdGOfJ-nPrL8_arkwf2EY3MDJ-SErKivBVSum1w_egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ-OB-v8' +
    '_uX45NBwY8rp65F6Glur8I_mlVNgF6W_qTI37m40',
};

// Parameters taken from https://www.rfc-editor.org/rfc/rfc8080.html#section-6
const EDDSA_PUB_KEYS = {
  ed25519: 'l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4',
  ed448: '3kgROaDjrh0H2iuixWBrc8g2EpBBLCdGzHmn-G2MpTPhpj_OiBVHHSfPodx1FYYUcJKm1MDpJtIA',
};

describe('serialisePublicKey', () => {
  describe('RSA', () => {
    test('Exponent length prefix should span 1 octet if exponent spans up to 255 octets', () => {
      const exponentLength = 255;
      const exponent = Buffer.alloc(exponentLength, 'f').toString('base64url');
      const publicKey = importRsaPubKey(exponent, RSA_PUB_KEY.modulus);

      const serialisation = serialisePublicKey(publicKey, DnssecAlgorithm.RSASHA256);

      expect(serialisation[0]).toEqual(exponentLength);
    });

    test('Exponent length prefix should span 2 octets if exponent spans more than 255 octets', () => {
      const exponentLength = 256;
      const exponent = Buffer.alloc(exponentLength, 'f').toString('base64url');
      const publicKey = importRsaPubKey(exponent, RSA_PUB_KEY.modulus);

      const serialisation = serialisePublicKey(publicKey, DnssecAlgorithm.RSASHA256);

      expect(serialisation[0]).toBe(0);
      expect(serialisation.readUint16BE(1)).toEqual(exponentLength);
    });

    test('Exponent should follow its length prefix', () => {
      const publicKey = importRsaPubKey(RSA_PUB_KEY.exponent, RSA_PUB_KEY.modulus);

      const serialisation = serialisePublicKey(publicKey, DnssecAlgorithm.RSASHA256);

      const exponent = serialisation.subarray(1, serialisation[0] + 1);
      expect(exponent.toString('base64url')).toEqual(RSA_PUB_KEY.exponent);
    });

    test('Modulus should follow exponent', () => {
      const publicKey = importRsaPubKey(RSA_PUB_KEY.exponent, RSA_PUB_KEY.modulus);

      const serialisation = serialisePublicKey(publicKey, DnssecAlgorithm.RSASHA256);

      const modulus = serialisation.subarray(serialisation[0] + 1);
      expect(modulus.toString('base64url')).toEqual(RSA_PUB_KEY.modulus);
    });

    test.each([DnssecAlgorithm.RSASHA1, DnssecAlgorithm.RSASHA256, DnssecAlgorithm.RSASHA512])(
      'Algorithm %s should be supported',
      (algo) => {
        const publicKey = importRsaPubKey(RSA_PUB_KEY.exponent, RSA_PUB_KEY.modulus);

        serialisePublicKey(publicKey, algo);
      },
    );

    test('Non-RSA key should be refused', () => {
      const publicKey = importEcPubKey(ECDSA_PUB_KEYS.p256, 'P-256');

      expect(() => serialisePublicKey(publicKey, DnssecAlgorithm.RSASHA256)).toThrowWithMessage(
        Error,
        `Requested serialisation of RSA key but got ${publicKey.asymmetricKeyType} key`,
      );
    });
  });

  describe('ECDSA', () => {
    test('P-256 key should be supported', () => {
      const publicKey = importEcPubKey(ECDSA_PUB_KEYS.p256, 'P-256');

      const serialisation = serialisePublicKey(publicKey, DnssecAlgorithm.ECDSAP256SHA256);

      const serialisationBase64 = serialisation.toString('base64url');
      expect(serialisationBase64).toEqual(ECDSA_PUB_KEYS.p256);
    });

    test('P-384 key should be supported', () => {
      const publicKey = importEcPubKey(ECDSA_PUB_KEYS.p384, 'P-384');

      const serialisation = serialisePublicKey(publicKey, DnssecAlgorithm.ECDSAP384SHA384);

      const serialisationBase64 = serialisation.toString('base64url');
      expect(serialisationBase64).toEqual(ECDSA_PUB_KEYS.p384);
    });

    test('Non-ECDSA key should be refused', () => {
      const publicKey = importEdPubKey(EDDSA_PUB_KEYS.ed25519, 'Ed25519');

      expect(() =>
        serialisePublicKey(publicKey, DnssecAlgorithm.ECDSAP256SHA256),
      ).toThrowWithMessage(
        Error,
        `Requested serialisation of ECDSA key but got ${publicKey.asymmetricKeyType} key`,
      );
    });
  });

  describe('EdDSA', () => {
    test('Ed25519 should be supported', () => {
      const publicKey = importEdPubKey(EDDSA_PUB_KEYS.ed25519, 'Ed25519');

      const serialisation = serialisePublicKey(publicKey, DnssecAlgorithm.ED25519);

      expect(serialisation.toString('base64url')).toEqual(EDDSA_PUB_KEYS.ed25519);
    });

    test('Ed448 should be supported', () => {
      const publicKey = importEdPubKey(EDDSA_PUB_KEYS.ed448, 'Ed448');

      const serialisation = serialisePublicKey(publicKey, DnssecAlgorithm.ED448);

      expect(serialisation.toString('base64url')).toEqual(EDDSA_PUB_KEYS.ed448);
    });

    test('Non-EdDSA key should be refused', () => {
      const publicKey = importEcPubKey(ECDSA_PUB_KEYS.p256, 'P-256');

      expect(() => serialisePublicKey(publicKey, DnssecAlgorithm.ED25519)).toThrowWithMessage(
        Error,
        `Requested serialisation of EdDSA key but got ${publicKey.asymmetricKeyType} key`,
      );
    });
  });

  test('Error should be thrown if algorithm is unsupported', async () => {
    const algorithm = 0;
    const publicKey = importRsaPubKey(RSA_PUB_KEY.exponent, RSA_PUB_KEY.modulus);

    expect(() => serialisePublicKey(publicKey, algorithm)).toThrowWithMessage(
      Error,
      `Unsupported DNSSEC algorithm (${algorithm})`,
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
        const serialisation = serialisePublicKey(
          importRsaPubKey(exponent, RSA_PUB_KEY.modulus),
          DnssecAlgorithm.RSASHA256,
        );

        const publicKey = deserialisePublicKey(serialisation, DnssecAlgorithm.RSASHA256);

        const publicKeyJwk = publicKey.export({ format: 'jwk' });
        expect(publicKeyJwk.e).toEqual(exponent);
        expect(publicKeyJwk.n).toEqual(RSA_PUB_KEY.modulus);
      },
    );

    test.each([DnssecAlgorithm.RSASHA1, DnssecAlgorithm.RSASHA256, DnssecAlgorithm.RSASHA512])(
      'RSA algorithm %s should be deserialised',
      (dnssecAlgorithm) => {
        const serialisation = serialisePublicKey(
          importRsaPubKey(RSA_PUB_KEY.exponent, RSA_PUB_KEY.modulus),
          dnssecAlgorithm,
        );

        const publicKey = deserialisePublicKey(serialisation, dnssecAlgorithm);

        const publicKeyJwk = publicKey.export({ format: 'jwk' });
        expect(publicKeyJwk.e).toEqual(RSA_PUB_KEY.exponent);
        expect(publicKeyJwk.n).toEqual(RSA_PUB_KEY.modulus);
      },
    );
  });

  describe('ECDSA', () => {
    test('P-256 key should be supported', () => {
      const algorithm = DnssecAlgorithm.ECDSAP256SHA256;
      const serialisation = serialisePublicKey(
        importEcPubKey(ECDSA_PUB_KEYS.p256, 'P-256'),
        algorithm,
      );

      const deserialisation = deserialisePublicKey(serialisation, algorithm);

      expect(serialisePublicKey(deserialisation, algorithm)).toEqual(serialisation);
    });

    test('P-256 key should span 64 octets', () => {
      const algorithm = DnssecAlgorithm.ECDSAP256SHA256;
      const serialisation = serialisePublicKey(
        importEcPubKey(ECDSA_PUB_KEYS.p256, 'P-256'),
        algorithm,
      ).subarray(1);

      expect(() => deserialisePublicKey(serialisation, algorithm)).toThrowWithMessage(
        DnssecError,
        `ECDSA public key should span 64 octets (got ${serialisation.byteLength})`,
      );
    });

    test('P-384 key should be supported', () => {
      const algorithm = DnssecAlgorithm.ECDSAP384SHA384;
      const serialisation = serialisePublicKey(
        importEcPubKey(ECDSA_PUB_KEYS.p384, 'P-384'),
        algorithm,
      );

      const deserialisation = deserialisePublicKey(serialisation, algorithm);

      expect(serialisePublicKey(deserialisation, algorithm)).toEqual(serialisation);
    });

    test('P-384 key should span 96 octets', () => {
      const algorithm = DnssecAlgorithm.ECDSAP384SHA384;
      const serialisation = serialisePublicKey(
        importEcPubKey(ECDSA_PUB_KEYS.p384, 'P-384'),
        algorithm,
      ).subarray(1);

      expect(() => deserialisePublicKey(serialisation, algorithm)).toThrowWithMessage(
        DnssecError,
        `ECDSA public key should span 96 octets (got ${serialisation.byteLength})`,
      );
    });
  });

  describe('EdDSA', () => {
    test('Ed25519 should be supported', () => {
      const algorithm = DnssecAlgorithm.ED25519;
      const serialisation = serialisePublicKey(
        importEdPubKey(EDDSA_PUB_KEYS.ed25519, 'Ed25519'),
        algorithm,
      );

      const deserialisation = deserialisePublicKey(serialisation, algorithm);

      expect(serialisePublicKey(deserialisation, algorithm)).toEqual(serialisation);
    });

    test('Ed25519 key should span 32 octets', () => {
      const algorithm = DnssecAlgorithm.ED25519;
      const serialisation = serialisePublicKey(
        importEdPubKey(EDDSA_PUB_KEYS.ed25519, 'Ed25519'),
        algorithm,
      ).subarray(1);

      expect(() => deserialisePublicKey(serialisation, algorithm)).toThrowWithMessage(
        Error,
        `Ed25519 public key should span 32 octets (got ${serialisation.byteLength})`,
      );
    });

    test('Ed448 should be supported', () => {
      const algorithm = DnssecAlgorithm.ED448;
      const serialisation = serialisePublicKey(
        importEdPubKey(EDDSA_PUB_KEYS.ed448, 'Ed448'),
        algorithm,
      );

      const deserialisation = deserialisePublicKey(serialisation, algorithm);

      expect(serialisePublicKey(deserialisation, algorithm)).toEqual(serialisation);
    });

    test('Ed448 key should span 57 octets', () => {
      const algorithm = DnssecAlgorithm.ED448;
      const serialisation = serialisePublicKey(
        importEdPubKey(EDDSA_PUB_KEYS.ed448, 'Ed448'),
        algorithm,
      ).subarray(1);

      expect(() => deserialisePublicKey(serialisation, algorithm)).toThrowWithMessage(
        Error,
        `Ed448 public key should span 57 octets (got ${serialisation.byteLength})`,
      );
    });
  });

  test('Error should be thrown if algorithm is unsupported', () => {
    const invalidAlgorithm = 999 as any;
    expect(() => deserialisePublicKey(Buffer.allocUnsafe(1), invalidAlgorithm)).toThrowWithMessage(
      Error,
      `Unsupported DNSSEC algorithm (${invalidAlgorithm})`,
    );
  });
});

function importRsaPubKey(exponent: string, modulus: string): KeyObject {
  return createPublicKey({
    key: { n: modulus, e: exponent, kty: 'RSA' },
    format: 'jwk',
  });
}

function importEcPubKey(publicKeyBase64: string, curveName: string): KeyObject {
  const publicKeyBuffer = Buffer.from(publicKeyBase64, 'base64url');
  const parametersLength = publicKeyBuffer.byteLength / 2;
  const x = publicKeyBuffer.subarray(0, parametersLength).toString('base64url');
  const y = publicKeyBuffer.subarray(parametersLength).toString('base64url');
  return createPublicKey({
    key: { kty: 'EC', crv: curveName, x, y },
    format: 'jwk',
  });
}

function importEdPubKey(publicKeyBase64: string, curveName: string): KeyObject {
  return createPublicKey({
    key: { crv: curveName, kty: 'OKP', x: publicKeyBase64 },
    format: 'jwk',
  });
}
