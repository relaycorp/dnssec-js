import type { Question } from './dns/Question';
import type { Resolver } from './Resolver';
import type { VerificationOptions } from './VerificationOptions';
import type { ChainVerificationResult } from './results';
import { UnverifiedChain } from './UnverifiedChain';
import { DatePeriod } from './DatePeriod';
import { IANA_TRUST_ANCHORS } from './IANA_TRUST_ANCHORS';
import type { TrustAnchor } from './TrustAnchor';
import { DsData } from './rdata/DsData';

/**
 * Retrieve RRset for `question` and return it only if DNSSEC validation succeeds.
 *
 * @param question
 * @param resolver
 * @param options
 */
export async function dnssecLookUp(
  question: Question,
  resolver: Resolver,
  options: Partial<VerificationOptions> = {},
): Promise<ChainVerificationResult> {
  const unverifiedChain = await UnverifiedChain.retrieve(question, resolver);

  const dateOrPeriod = options.dateOrPeriod ?? new Date();
  const datePeriod =
    dateOrPeriod instanceof DatePeriod ? dateOrPeriod : DatePeriod.init(dateOrPeriod, dateOrPeriod);
  const dsData = options.trustAnchors
    ? convertTrustAnchors(options.trustAnchors)
    : IANA_TRUST_ANCHORS;
  return unverifiedChain.verify(datePeriod, dsData);
}

function convertTrustAnchors(trustAnchors: readonly TrustAnchor[]): readonly DsData[] {
  return trustAnchors.map((a) => new DsData(a.keyTag, a.algorithm, a.digestType, a.digest));
}
