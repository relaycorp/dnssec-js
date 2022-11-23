import { DNSoverHTTPS } from 'dohdec';

import { Resolver } from '../lib/Resolver';
import { Question } from '../lib/dns/Question';
import { SecurityStatus } from '../lib/SecurityStatus';
import { RRSet } from '../lib/dns/RRSet';
import { FailureResult, VerifiedRRSet } from '../lib/results';
import { dnssecLookUp } from '../lib/lookup';

const DOH_CLIENT = new DNSoverHTTPS({ url: 'https://cloudflare-dns.com/dns-query' });
afterAll(() => {
  DOH_CLIENT.close();
});

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

  expect(result).toEqual<VerifiedRRSet>({
    status: SecurityStatus.SECURE,
    result: expect.any(RRSet),
  });
});

test('Response from bogus secure zone should be BOGUS', async () => {
  const question = new Question('dnssec-failed.org.', 'A');

  const result = await dnssecLookUp(question, RESOLVER);

  expect(result).toEqual<FailureResult>({
    status: SecurityStatus.BOGUS,
    reasonChain: expect.arrayContaining([`Failed to verify zone ${question.name}`]),
  });
});

async function retryUponFailure<T>(function_: () => Promise<T>, attempts: number): Promise<T> {
  try {
    return function_();
  } catch (error) {
    if (attempts <= 1) {
      throw error;
    }
    return retryUponFailure(function_, attempts - 1);
  }
}
