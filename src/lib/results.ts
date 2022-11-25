import type { SecurityStatus } from './SecurityStatus';
import type { RrSet } from './dns/RrSet';

interface BaseResult {
  readonly status: SecurityStatus;
}

export interface SuccessfulResult<Result> extends BaseResult {
  readonly status: SecurityStatus.SECURE;
  readonly result: Result;
}

export interface FailureResult extends BaseResult {
  readonly status: SecurityStatus.BOGUS | SecurityStatus.INDETERMINATE | SecurityStatus.INSECURE;
  readonly reasonChain: readonly string[];
}

export type VerificationResult<Result = void> = FailureResult | SuccessfulResult<Result>;

export type VerifiedRrSet = SuccessfulResult<RrSet>;
export type ChainVerificationResult = FailureResult | VerifiedRrSet;

export function augmentFailureResult(
  originalResult: FailureResult,
  additionalReason: string,
): FailureResult {
  return {
    status: originalResult.status,
    reasonChain: [additionalReason, ...originalResult.reasonChain],
  };
}
