import { DNSoverHTTPS } from 'dohdec';

import { Resolver } from '../lib/verification/Resolver';
import { Message } from '../lib/dns/Message';
import { UnverifiedChain, VerifiedChainResult } from '../lib/verification/UnverifiedChain';
import { Question } from '../lib/dns/Question';
import { SecurityStatus } from '../lib/verification/SecurityStatus';
import { RRSet } from '../lib/dns/RRSet';
import { DnsClass } from '../lib/dns/ianaClasses';
import { FailureResult } from '../lib/verification/results';

const DOH_CLIENT = new DNSoverHTTPS({ url: 'https://cloudflare-dns.com/dns-query' });
afterAll(() => {
  DOH_CLIENT.close();
});

const RESOLVER: Resolver = async (question) => {
  const messageRaw = await retryUponFailure(
    async () =>
      DOH_CLIENT.lookup(question.name, {
        rrtype: question.getTypeName(),
        json: false,
        decode: false,
        dnssec: true, // Retrieve RRSig records
      }),
    3,
  );
  return Message.deserialise(messageRaw as Buffer);
};

test('Positive response in valid DNSSEC zone should be SECURE', async () => {
  const question = new Question('dnssec-deployment.org.', 'A', DnsClass.IN);
  const chain = await UnverifiedChain.retrieve(question, RESOLVER);

  const result = chain.verify();

  expect(result).toEqual<VerifiedChainResult>({
    status: SecurityStatus.SECURE,
    result: expect.any(RRSet),
  });
});

test('Response from insecure zone should be INSECURE', async () => {
  const question = new Question('dnssec-failed.org.', 'A', DnsClass.IN);
  const chain = await UnverifiedChain.retrieve(question, RESOLVER);

  const result = chain.verify();

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
