import { jest } from '@jest/globals';
import { subSeconds } from 'date-fns';

import { QUESTION, RRSET } from '../testUtils/dnsStubs';

import { dnssecLookUp } from './lookup';
import type { Resolver } from './Resolver';
import { UnverifiedChain } from './UnverifiedChain';
import type { VerifiedRrSet } from './results';
import { SecurityStatus } from './SecurityStatus';
import { DatePeriod } from './DatePeriod';
import { IanaTrustAnchors } from './ianaTrustAnchors';
import type { TrustAnchor } from './TrustAnchor';
import type { DsData } from './rdata/DsData';
import { DnssecAlgorithm } from './DnssecAlgorithm';
import { DigestType } from './DigestType';

const MOCK_VERIFIER = jest.fn();

beforeEach(() => {
  MOCK_VERIFIER.mockReturnValueOnce({ status: SecurityStatus.SECURE, result: RRSET });
});

afterEach(() => {
  MOCK_VERIFIER.mockReset();
});

// eslint-disable-next-line @typescript-eslint/no-unsafe-argument
jest.spyOn(UnverifiedChain, 'retrieve').mockResolvedValue({ verify: MOCK_VERIFIER } as any);

describe('dnssecLookUp', () => {
  const RESOLVER = jest.fn<Resolver>();

  afterEach(() => {
    RESOLVER.mockReset();
  });

  test('Question should be used as is', async () => {
    await dnssecLookUp(QUESTION, RESOLVER);

    expect(UnverifiedChain.retrieve).toHaveBeenCalledTimes(1);
    expect(UnverifiedChain.retrieve).toHaveBeenCalledWith(QUESTION, expect.anything());
  });

  test('Resolver should be used as is', async () => {
    await dnssecLookUp(QUESTION, RESOLVER);

    expect(UnverifiedChain.retrieve).toHaveBeenCalledTimes(1);
    expect(UnverifiedChain.retrieve).toHaveBeenCalledWith(expect.anything(), RESOLVER);
  });

  describe('Validity period', () => {
    test('Single date should be converted to date period', async () => {
      const date = subSeconds(new Date(), 60);

      await dnssecLookUp(QUESTION, RESOLVER, { dateOrPeriod: date });

      expect(MOCK_VERIFIER).toHaveBeenCalledTimes(1);
      expect(MOCK_VERIFIER).toHaveBeenCalledWith(
        expect.toSatisfy<DatePeriod>((period) => period.overlaps(date, date)),
        expect.anything(),
      );
    });

    test('Date period should be used as is', async () => {
      const datePeriod = DatePeriod.init(new Date(), new Date());

      await dnssecLookUp(QUESTION, RESOLVER, { dateOrPeriod: datePeriod });

      expect(MOCK_VERIFIER).toHaveBeenCalledTimes(1);
      expect(MOCK_VERIFIER).toHaveBeenCalledWith(datePeriod, expect.anything());
    });

    test('Current date should be used by default', async () => {
      const startDate = new Date();

      await dnssecLookUp(QUESTION, RESOLVER);

      const endDate = new Date();
      expect(MOCK_VERIFIER).toHaveBeenCalledWith(
        expect.toSatisfy<DatePeriod>(
          (period) => period.start === period.end && period.overlaps(startDate, endDate),
        ),
        expect.anything(),
      );
    });
  });

  describe('Trust anchors', () => {
    test('IANA trust anchors should be used by default', async () => {
      await dnssecLookUp(QUESTION, RESOLVER);

      expect(MOCK_VERIFIER).toHaveBeenCalledTimes(1);
      expect(MOCK_VERIFIER).toHaveBeenCalledWith(expect.anything(), IanaTrustAnchors);
    });

    test('Custom trust anchors should be used if set', async () => {
      const trustAnchor: TrustAnchor = {
        algorithm: DnssecAlgorithm.RSASHA256,
        digest: Buffer.from('the digest'),
        digestType: DigestType.SHA256,
        keyTag: 42,
      };

      await dnssecLookUp(QUESTION, RESOLVER, { trustAnchors: [trustAnchor] });

      expect(MOCK_VERIFIER).toHaveBeenCalledTimes(1);
      expect(MOCK_VERIFIER).toHaveBeenCalledWith(
        expect.anything(),
        expect.toSatisfy<readonly DsData[]>(
          (anchors) =>
            anchors.length === 1 &&
            anchors[0].keyTag === trustAnchor.keyTag &&
            anchors[0].algorithm === trustAnchor.algorithm &&
            anchors[0].digestType === trustAnchor.digestType &&
            anchors[0].digest.equals(trustAnchor.digest),
        ),
      );
    });
  });

  test('Verification result should be output', async () => {
    const result = await dnssecLookUp(QUESTION, RESOLVER);

    expect(result).toStrictEqual<VerifiedRrSet>({
      status: SecurityStatus.SECURE,
      result: RRSET,
    });
  });
});
