import { addSeconds, subSeconds } from 'date-fns';

import { DatePeriod } from './dates.js';

const NOW = new Date();

describe('init', () => {
  test('Start date before end date should be accepted', () => {
    const start = new Date();
    const end = addSeconds(start, 1);

    const period = DatePeriod.init(start, end);

    expect(period.start).toStrictEqual(start);
    expect(period.end).toStrictEqual(end);
  });

  test('Start date equal to end date should be accepted', () => {
    const date = new Date();

    const period = DatePeriod.init(date, date);

    expect(period.start).toStrictEqual(date);
    expect(period.end).toStrictEqual(date);
  });

  test('Start date after end date should be refused', () => {
    const start = new Date();
    const end = subSeconds(start, 1);

    expect(() => DatePeriod.init(start, end)).toThrowWithMessage(
      Error,
      `End date should not be before start date (${start.toISOString()} <= ${end.toISOString()})`,
    );
  });
});

describe('overlaps', () => {
  const stubPeriod = DatePeriod.init(subSeconds(NOW, 1), addSeconds(NOW, 1));

  test('Other period should not have a start date after end date', () => {
    const start = new Date();
    const end = subSeconds(start, 1);

    expect(stubPeriod.overlaps(start, end)).toBeFalse();
  });

  test('Other end date should not be before own start date', () => {
    const end = subSeconds(stubPeriod.start, 1);
    const start = subSeconds(end, 1);

    expect(stubPeriod.overlaps(start, end)).toBeFalse();
  });

  test('Other start date should not be after own end date', () => {
    const start = addSeconds(stubPeriod.end, 1);
    const end = addSeconds(start, 1);

    expect(stubPeriod.overlaps(start, end)).toBeFalse();
  });

  test('Other start date may be before own start date', () => {
    const start = subSeconds(stubPeriod.start, 1);
    const end = addSeconds(start, 1);

    expect(stubPeriod.overlaps(start, end)).toBeTrue();
  });

  test('Other end date may be after own end date', () => {
    const end = addSeconds(stubPeriod.end, 1);
    const start = subSeconds(end, 1);

    expect(stubPeriod.overlaps(start, end)).toBeTrue();
  });

  test('Other period may be within own period', () => {
    const start = addSeconds(stubPeriod.start, 0.5);
    const end = subSeconds(stubPeriod.end, 1);

    expect(stubPeriod.overlaps(start, end)).toBeTrue();
  });

  test('Other period may equal own period', () => {
    expect(stubPeriod.overlaps(stubPeriod.start, stubPeriod.end)).toBeTrue();
  });

  test('Own date may be a single point in time within other period', () => {
    const period = DatePeriod.init(NOW, NOW);
    const start = subSeconds(NOW, 1);
    const end = addSeconds(NOW, 1);

    expect(period.overlaps(start, end)).toBeTrue();
  });
});
