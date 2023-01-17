import { augmentFailureResult, type FailureResult } from './securityStatusResults.js';
import { SecurityStatus } from './SecurityStatus.js';

describe('augmentFailureResult', () => {
  const stubOriginalResult: FailureResult = {
    reasonChain: ['Whoops'],
    status: SecurityStatus.INDETERMINATE,
  };

  const stubAdditionalReason = 'Oh noes';

  test('Original status should be preserved', () => {
    const newResult = augmentFailureResult(stubOriginalResult, stubAdditionalReason);

    expect(newResult.status).toStrictEqual(stubOriginalResult.status);
  });

  test('New reason should be added to the beginning', () => {
    const newResult = augmentFailureResult(stubOriginalResult, stubAdditionalReason);

    expect(newResult.reasonChain).toHaveLength(stubOriginalResult.reasonChain.length + 1);
    expect(newResult.reasonChain[0]).toStrictEqual(stubAdditionalReason);
  });
});
