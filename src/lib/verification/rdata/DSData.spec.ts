import { DSData } from './DSData';
import { MalformedRdata } from '../../errors';
import { ZoneSigner } from '../../signing/ZoneSigner';
import { DNSSECAlgorithm } from '../../DNSSECAlgorithm';
import { DigestType } from '../../DigestType';
import { hashKey } from '../../signing/rdata/ds';

describe('DSData', () => {
  describe('deserialise', () => {
    const algorithm = DNSSECAlgorithm.RSASHA256;
    const digestType = DigestType.SHA384;

    let dsDataSerialised: Buffer;
    let signer: ZoneSigner;
    beforeAll(async () => {
      signer = await ZoneSigner.generate(algorithm, '.');
      dsDataSerialised = signer.generateDs('com', 5, digestType).data;
    });

    test('Malformed value should be refused', () => {
      // Anything with fewer than 5 octets is malformed
      const malformedDSData = Buffer.allocUnsafe(3);

      expect(() => DSData.deserialise(malformedDSData)).toThrowWithMessage(
        MalformedRdata,
        'DS data is malformed',
      );
    });

    test('Key tag should be extracted', () => {
      const data = DSData.deserialise(dsDataSerialised);

      expect(data.keyTag).toEqual(signer.keyTag);
    });

    test('Algorithm should be extracted', () => {
      const data = DSData.deserialise(dsDataSerialised);

      expect(data.algorithm).toEqual(algorithm);
    });

    test('Digest type should be extracted', () => {
      const data = DSData.deserialise(dsDataSerialised);

      expect(data.digestType).toEqual(digestType);
    });

    test('Digest should be extracted', () => {
      const data = DSData.deserialise(dsDataSerialised);

      const digest = hashKey(signer.publicKey, digestType);
      expect(data.digest).toEqual(digest);
    });
  });
});
