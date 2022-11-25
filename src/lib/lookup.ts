import type { Question } from './dns/Question';
import type { Resolver } from './Resolver';
import type { VerificationOptions } from './VerificationOptions';
import type { ChainVerificationResult } from './results';
import { UnverifiedChain } from './UnverifiedChain';
import { DatePeriod } from './DatePeriod';
import { IanaTrustAnchors } from './ianaTrustAnchors';
import type { TrustAnchor } from './TrustAnchor';
import { DsData } from './rdata/DsData';

function convertTrustAnchors(trustAnchors: readonly TrustAnchor[]): readonly DsData[] {
  return trustAnchors.map(
    (anchor) => new DsData(anchor.keyTag, anchor.algorithm, anchor.digestType, anchor.digest),
  );
}

/**
 * Retrieve RRset for `question` and return it only if DNSSEC validation succeeds.
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
    : IanaTrustAnchors;
  return unverifiedChain.verify(datePeriod, dsData);
}
