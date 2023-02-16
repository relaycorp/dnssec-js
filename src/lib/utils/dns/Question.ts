import {
  getRrTypeId,
  type IanaRrTypeIdOrName,
  type IanaRrTypeName,
  IANA_RR_TYPE_NAMES,
} from './ianaRrTypes.js';
import { DnsError } from './DnsError.js';
import { DnsClass, type DnsClassIdOrName, getDnsClassId } from './ianaClasses.js';
import { normaliseName } from './name.js';

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
    if (!(this.typeId in IANA_RR_TYPE_NAMES)) {
      throw new DnsError(`RR type id ${this.typeId} is not defined by IANA`);
    }
    return IANA_RR_TYPE_NAMES[this.typeId];
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
