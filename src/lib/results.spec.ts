import type { FailureResult } from './results.js';
import { augmentFailureResult } from './results.js';
import { SecurityStatus } from './SecurityStatus.js';

describe('augmentFailureResult', () => {
  const ORIGINAL_RESULT: FailureResult = {
    reasonChain: ['Whoops'],
    status: SecurityStatus.INDETERMINATE,
  };

  const ADDITIONAL_REASON = 'Oh noes';

  test('Original status should be preserved', () => {
    const newResult = augmentFailureResult(ORIGINAL_RESULT, ADDITIONAL_REASON);

    expect(newResult.status).toStrictEqual(ORIGINAL_RESULT.status);
  });

  test('New reason should be added to the beginning', () => {
    const newResult = augmentFailureResult(ORIGINAL_RESULT, ADDITIONAL_REASON);

    expect(newResult.reasonChain).toHaveLength(ORIGINAL_RESULT.reasonChain.length + 1);
    expect(newResult.reasonChain[0]).toStrictEqual(ADDITIONAL_REASON);
  });
});
