import { type DatePeriod } from './DatePeriod.js';

export interface DatedValue<Value> {
  readonly value: Value;
  readonly datePeriods: readonly DatePeriod[];
}
