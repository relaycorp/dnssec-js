export class DatePeriod {
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

    return otherStart <= this.end;
  }

  public intersect(otherPeriod: DatePeriod): DatePeriod | undefined {
    if (!this.overlaps(otherPeriod.start, otherPeriod.end)) {
      return undefined;
    }
    const start = this.start < otherPeriod.start ? otherPeriod.start : this.start;
    const end = this.end < otherPeriod.end ? this.end : otherPeriod.end;
    return new DatePeriod(start, end);
  }
}
