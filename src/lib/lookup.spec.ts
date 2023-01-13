import { jest } from '@jest/globals';
import { subSeconds } from 'date-fns';

import { QUESTION, RRSET } from '../testUtils/dnsStubs.js';

import { dnssecLookUp } from './lookup.js';
import type { Resolver } from './Resolver.js';
import { UnverifiedChain } from './UnverifiedChain.js';
import type { VerifiedRrSet } from './results.js';
import { SecurityStatus } from './SecurityStatus.js';
import { DatePeriod } from './DatePeriod.js';
import type { TrustAnchor } from './TrustAnchor.js';
import type { DsData } from './rdata/DsData.js';
import { DnssecAlgorithm } from './DnssecAlgorithm.js';
import { DigestType } from './DigestType.js';
import { IANA_TRUST_ANCHORS } from './ianaTrustAnchors.js';

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
  const stubResolver = jest.fn<Resolver>();

  afterEach(() => {
    stubResolver.mockReset();
  });

  test('Question should be used as is', async () => {
    await dnssecLookUp(QUESTION, stubResolver);

    expect(UnverifiedChain.retrieve).toHaveBeenCalledTimes(1);
    expect(UnverifiedChain.retrieve).toHaveBeenCalledWith(QUESTION, expect.anything());
  });

  test('Resolver should be used as is', async () => {
    await dnssecLookUp(QUESTION, stubResolver);

    expect(UnverifiedChain.retrieve).toHaveBeenCalledTimes(1);
    expect(UnverifiedChain.retrieve).toHaveBeenCalledWith(expect.anything(), stubResolver);
  });

  describe('Validity period', () => {
    test('Single date should be converted to date period', async () => {
      const date = subSeconds(new Date(), 60);

      await dnssecLookUp(QUESTION, stubResolver, { dateOrPeriod: date });

      expect(MOCK_VERIFIER).toHaveBeenCalledTimes(1);
      expect(MOCK_VERIFIER).toHaveBeenCalledWith(
        expect.toSatisfy<DatePeriod>((period) => period.overlaps(date, date)),
        expect.anything(),
      );
    });

    test('Date period should be used as is', async () => {
      const datePeriod = DatePeriod.init(new Date(), new Date());

      await dnssecLookUp(QUESTION, stubResolver, { dateOrPeriod: datePeriod });

      expect(MOCK_VERIFIER).toHaveBeenCalledTimes(1);
      expect(MOCK_VERIFIER).toHaveBeenCalledWith(datePeriod, expect.anything());
    });

    test('Current date should be used by default', async () => {
      const startDate = new Date();

      await dnssecLookUp(QUESTION, stubResolver);

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
      await dnssecLookUp(QUESTION, stubResolver);

      expect(MOCK_VERIFIER).toHaveBeenCalledTimes(1);
      expect(MOCK_VERIFIER).toHaveBeenCalledWith(expect.anything(), IANA_TRUST_ANCHORS);
    });

    test('Custom trust anchors should be used if set', async () => {
      const trustAnchor: TrustAnchor = {
        algorithm: DnssecAlgorithm.RSASHA256,
        digest: Buffer.from('the digest'),
        digestType: DigestType.SHA256,
        keyTag: 42,
      };

      await dnssecLookUp(QUESTION, stubResolver, { trustAnchors: [trustAnchor] });

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
    const result = await dnssecLookUp(QUESTION, stubResolver);

    expect(result).toStrictEqual<VerifiedRrSet>({
      status: SecurityStatus.SECURE,
      result: RRSET,
    });
  });
});
