import { DNSoverHTTPS } from 'dohdec';

import type { Resolver } from '../lib/Resolver';
import { Question } from '../lib/dns/Question';
import { SecurityStatus } from '../lib/SecurityStatus';
import { RRSet } from '../lib/dns/RRSet';
import type { FailureResult, VerifiedRRSet } from '../lib/results';
import { dnssecLookUp } from '../lib/lookup';

const DOH_CLIENT = new DNSoverHTTPS({ url: 'https://cloudflare-dns.com/dns-query' });

afterAll(() => {
  DOH_CLIENT.close();
});

async function retryUponFailure<Type>(
  wrappedFunction: () => Promise<Type>,
  attempts: number,
): Promise<Type> {
  try {
    return await wrappedFunction();
  } catch (error) {
    if (attempts <= 1) {
      throw error as Error;
    }
    return await retryUponFailure(wrappedFunction, attempts - 1);
  }
}

const RESOLVER: Resolver = async (question) =>
  (await retryUponFailure(
    async () =>
      DOH_CLIENT.lookup(question.name, {
        rrtype: question.getTypeName(),
        json: false,
        decode: false,
        dnssec: true, // Retrieve RRSig records
        dnssecCheckingDisabled: true,
      }),
    3,
  )) as Promise<Buffer>;

test('Positive response in valid DNSSEC zone should be SECURE', async () => {
  const question = new Question('dnssec-deployment.org.', 'A');

  const result = await dnssecLookUp(question, RESOLVER);

  expect(result).toStrictEqual<VerifiedRRSet>({
    status: SecurityStatus.SECURE,
    result: expect.any(RRSet),
  });
});

test('Response from bogus secure zone should be BOGUS', async () => {
  const question = new Question('dnssec-failed.org.', 'A');

  const result = await dnssecLookUp(question, RESOLVER);

  expect(result).toStrictEqual<FailureResult>({
    status: SecurityStatus.BOGUS,
    reasonChain: expect.arrayContaining([`Failed to verify zone ${question.name}`]),
  });
});
