import { DNSClass } from './DNSClass';
import { serialiseName } from './name';

export interface QuestionFields {
  readonly name: string;
  readonly type: number;
  readonly class: DNSClass;
}

export class Question {
  constructor(
    public readonly name: string,
    public readonly type: number,
    public readonly class_: DNSClass,
  ) {}

  public equals(differentQuestion: Question) {
    return (
      this.name === differentQuestion.name &&
      this.type === differentQuestion.type &&
      this.class_ === differentQuestion.class_
    );
  }

  public serialise(): Buffer {
    const nameSerialised = serialiseName(this.name);

    const serialisation = Buffer.allocUnsafe(nameSerialised.byteLength + 4);
    nameSerialised.copy(serialisation);
    serialisation.writeUInt16BE(this.type, nameSerialised.byteLength);
    serialisation.writeUInt16BE(this.class_, nameSerialised.byteLength + 2);
    return serialisation;
  }

  public shallowCopy(fields: Partial<QuestionFields>): Question {
    const newName = fields.name ?? this.name;
    const newType = fields.type ?? this.type;
    const newClass = fields.class ?? this.class_;
    return new Question(newName, newType, newClass);
  }
}
