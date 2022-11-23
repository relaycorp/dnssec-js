import { DNSoverHTTPS } from 'dohdec';

import { Resolver } from '../lib/Resolver';
import { Question } from '../lib/dns/Question';
import { SecurityStatus } from '../lib/SecurityStatus';
import { RRSet } from '../lib/dns/RRSet';
import { FailureResult, VerifiedRRSet } from '../lib/results';
import { dnssecLookup } from '../lib/lookup';

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
      }),
    3,
  )) as Promise<Buffer>;

test('Positive response in valid DNSSEC zone should be SECURE', async () => {
  const question = new Question('dnssec-deployment.org.', 'A');

  const result = await dnssecLookup(question, RESOLVER);

  expect(result).toEqual<VerifiedRRSet>({
    status: SecurityStatus.SECURE,
    result: expect.any(RRSet),
  });
});

test('Response from insecure zone should be INSECURE', async () => {
  const question = new Question('dnssec-failed.org.', 'A');

  const result = await dnssecLookup(question, RESOLVER);

  expect(result).toEqual<FailureResult>({
    status: SecurityStatus.INSECURE,
    reasonChain: expect.arrayContaining([`Failed to verify zone ${question.name}`]),
  });
});

async function retryUponFailure<T>(func: () => Promise<T>, attempts: number): Promise<T> {
  try {
    return func();
  } catch (err) {
    if (attempts <= 1) {
      throw err;
    }
    return retryUponFailure(func, attempts - 1);
  }
}
