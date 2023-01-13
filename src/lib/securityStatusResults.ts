import type { SecurityStatus } from './SecurityStatus.js';
import type { RrSet } from './utils/dns/RrSet.js';

interface BaseResult {
  readonly status: SecurityStatus;
}

export interface SuccessfulResult<Result> extends BaseResult {
  readonly status: SecurityStatus.SECURE;
  readonly result: Result;
}

export type FailureStatus =
  | SecurityStatus.BOGUS
  | SecurityStatus.INDETERMINATE
  | SecurityStatus.INSECURE;

export interface FailureResult extends BaseResult {
  readonly status: FailureStatus;
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
