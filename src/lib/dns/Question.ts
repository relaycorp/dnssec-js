import { getRrTypeId, IANA_RR_TYPE_NAMES, IanaRrTypeIdOrName, IanaRrTypeName } from './ianaRrTypes';
import { DnsError } from './DnsError';
import { DnsClass, DnsClassIdOrName, getDnsClassId } from './ianaClasses';
import { normaliseName, serialiseName } from './name';

export interface QuestionFields {
  readonly name: string;
  readonly type: number;
  readonly class: DnsClass;
}

export class Question {
  public readonly name: string;
  public readonly typeId: number;
  public readonly class_: DnsClass;

  constructor(name: string, type: IanaRrTypeIdOrName, class_: DnsClassIdOrName) {
    this.name = normaliseName(name);
    this.typeId = getRrTypeId(type);
    this.class_ = getDnsClassId(class_);
  }

  get key(): string {
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
      this.class_ === differentQuestion.class_
    );
  }

  public serialise(): Buffer {
    const nameSerialised = serialiseName(this.name);

    const serialisation = Buffer.allocUnsafe(nameSerialised.byteLength + 4);
    nameSerialised.copy(serialisation);
    serialisation.writeUInt16BE(this.typeId, nameSerialised.byteLength);
    serialisation.writeUInt16BE(this.class_, nameSerialised.byteLength + 2);
    return serialisation;
  }

  public shallowCopy(fields: Partial<QuestionFields>): Question {
    const newName = fields.name ?? this.name;
    const newType = fields.type ?? this.typeId;
    const newClass = fields.class ?? this.class_;
    return new Question(newName, newType, newClass);
  }
}
