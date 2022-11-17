import { DatePeriod } from './DatePeriod';
import { DsData } from '../rdata/DsData';

export interface VerificationOptions {
  readonly dateOrPeriod: Date | DatePeriod;
  readonly trustAnchors: readonly DsData[];
}
