import type { IanaRrTypeIdOrName, IanaRrTypeName } from './ianaRrTypes';
import { getRrTypeId, IANA_RR_TYPE_NAMES } from './ianaRrTypes';
import { DnsError } from './DnsError';
import type { DnsClassIdOrName } from './ianaClasses';
import { DnsClass, getDnsClassId } from './ianaClasses';
import { normaliseName } from './name';

interface QuestionFields {
  readonly name: string;
  readonly type: number;
  readonly class: DnsClass;
}

export class Question {
  public readonly name: string;

  public readonly typeId: number;

  public readonly classId: DnsClass;

  public constructor(
    name: string,
    type: IanaRrTypeIdOrName,
    classIdOrName: DnsClassIdOrName = DnsClass.IN,
  ) {
    this.name = normaliseName(name);
    this.typeId = getRrTypeId(type);
    this.classId = getDnsClassId(classIdOrName);
  }

  public get key(): string {
    return `${this.name}/${this.typeId}`;
  }

  public getTypeName(): IanaRrTypeName {
    const name = IANA_RR_TYPE_NAMES[this.typeId];
    if (!name) {
      throw new DnsError(`RR type id ${this.typeId} is not defined by IANA`);
    }
    return name;
  }

  public equals(differentQuestion: Question) {
    return (
      this.name === differentQuestion.name &&
      this.typeId === differentQuestion.typeId &&
      this.classId === differentQuestion.classId
    );
  }

  public shallowCopy(fields: Partial<QuestionFields>): Question {
    const newName = fields.name ?? this.name;
    const newType = fields.type ?? this.typeId;
    const newClass = fields.class ?? this.classId;
    return new Question(newName, newType, newClass);
  }
}
