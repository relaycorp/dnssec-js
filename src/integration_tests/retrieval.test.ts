import { DNSoverHTTPS } from 'dohdec';
import type { DOH_LookupOptions as DohLookupOptions } from 'dohdec/types/doh.js';

import type { Resolver } from '../lib/Resolver.js';
import { Question } from '../lib/utils/dns/Question.js';
import { SecurityStatus } from '../lib/SecurityStatus.js';
import { RrSet } from '../lib/utils/dns/RrSet.js';
import type { FailureResult, VerifiedRrSet } from '../lib/securityStatusResults.js';
import { dnssecLookUp } from '../lib/lookup.js';

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

const RESOLVER: Resolver = async (question) => {
  const options: DohLookupOptions = {
    rrtype: question.getTypeName(),
    json: false,
    decode: false,
    dnssec: true, // Retrieve RRSig records
    dnssecCheckingDisabled: true,
  };
  const lookUp = async () => DOH_CLIENT.lookup(question.name, options) as Promise<Buffer>;
  return retryUponFailure(lookUp, 3);
};

test('Positive response in valid DNSSEC zone should be SECURE', async () => {
  const question = new Question('dnssec-deployment.org.', 'A');

  const result = await dnssecLookUp(question, RESOLVER);

  expect(result).toStrictEqual<VerifiedRrSet>({
    status: SecurityStatus.SECURE,
    result: expect.toSatisfy((rrset) => rrset instanceof RrSet),
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
