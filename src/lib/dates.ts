export interface IDatePeriod {
  readonly start: Date;
  readonly end: Date;
}

export class DatePeriod implements IDatePeriod {
  public static init(start: Date, end: Date): DatePeriod {
    if (end < start) {
      throw new Error(
        `End date should not be before start date (${start.toISOString()} <= ${end.toISOString()})`,
      );
    }
    return new DatePeriod(start, end);
  }

  protected constructor(public readonly start: Date, public readonly end: Date) {}

  public overlaps(otherStart: Date, otherEnd: Date): boolean {
    if (otherEnd < otherStart) {
      // The other date period is invalid
      return false;
    }

    if (otherEnd < this.start) {
      return false;
    }

    return this.end >= otherStart;
  }
}
