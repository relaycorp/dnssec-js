import { addMinutes, addSeconds, setMilliseconds, subSeconds } from 'date-fns';

import { QUESTION, RECORD, RRSET } from '../../testUtils/dnsStubs.js';
import { SecurityStatus } from '../SecurityStatus.js';
import { dnssecLookUp } from '../lookup.js';
import { type FailureStatus } from '../results.js';
import { DatePeriod } from '../DatePeriod.js';
import { DnsError } from '../dns/DnsError.js';

import { MockChain } from './MockChain.js';

describe('MockChain', () => {
  describe('generateResolver', () => {
    test('SECURE result should be generated if given an RRset', async () => {
      const mockChain = await MockChain.generate(RECORD.name);

      const { resolver, trustAnchors } = mockChain.generateFixture(RRSET, SecurityStatus.SECURE);

      const result = await dnssecLookUp(QUESTION, resolver, { trustAnchors });
      expect(result).toStrictEqual({
        status: SecurityStatus.SECURE,
        result: RRSET,
      });
    });

    test.each<FailureStatus>([
      SecurityStatus.INSECURE,
      SecurityStatus.BOGUS,
      SecurityStatus.INDETERMINATE,
    ])('%s result should be generated if requested', async (status) => {
      const mockChain = await MockChain.generate(RECORD.name);

      const { resolver, trustAnchors } = mockChain.generateFixture(RRSET, status);

      const result = await dnssecLookUp(QUESTION, resolver, { trustAnchors });
      expect(result.status).toStrictEqual(status);
    });

    test('Missing record should result in NXDOMAIN response', async () => {
      const mockChain = await MockChain.generate(RECORD.name);

      const { resolver, trustAnchors } = mockChain.generateFixture(RRSET, SecurityStatus.SECURE);

      await expect(
        dnssecLookUp(QUESTION.shallowCopy({ name: `sub.${QUESTION.name}` }), resolver, {
          trustAnchors,
        }),
      ).rejects.toThrowWithMessage(DnsError, /should have at least one matching record/u);
    });

    test('Signatures should be valid for 60 seconds by default', async () => {
      const testStartDate = new Date();
      const mockChain = await MockChain.generate(RECORD.name);

      const { resolver, trustAnchors } = mockChain.generateFixture(RRSET, SecurityStatus.SECURE);

      await expect(dnssecLookUp(QUESTION, resolver, { trustAnchors })).resolves.toHaveProperty(
        'status',
        SecurityStatus.SECURE,
      );
      await expect(
        dnssecLookUp(QUESTION, resolver, {
          dateOrPeriod: subSeconds(testStartDate, 1),
          trustAnchors,
        }),
      ).resolves.toHaveProperty('status', SecurityStatus.BOGUS);
      await expect(
        dnssecLookUp(QUESTION, resolver, {
          dateOrPeriod: addMinutes(addSeconds(testStartDate, 1), 5),
          trustAnchors,
        }),
      ).resolves.toHaveProperty('status', SecurityStatus.BOGUS);
    });

    test('Explicit signature period should be honoured', async () => {
      const now = setMilliseconds(new Date(), 0);
      const period = DatePeriod.init(subSeconds(now, 120), subSeconds(now, 60));
      const mockChain = await MockChain.generate(RECORD.name);

      const { resolver, trustAnchors } = mockChain.generateFixture(
        RRSET,
        SecurityStatus.SECURE,
        period,
      );

      await expect(
        dnssecLookUp(QUESTION, resolver, { dateOrPeriod: period.end, trustAnchors }),
      ).resolves.toHaveProperty('status', SecurityStatus.SECURE);
      await expect(
        dnssecLookUp(QUESTION, resolver, {
          dateOrPeriod: subSeconds(period.start, 1),
          trustAnchors,
        }),
      ).resolves.toHaveProperty('status', SecurityStatus.BOGUS);
      await expect(
        dnssecLookUp(QUESTION, resolver, {
          dateOrPeriod: addSeconds(period.end, 1),
          trustAnchors,
        }),
      ).resolves.toHaveProperty('status', SecurityStatus.BOGUS);
    });
  });
});
