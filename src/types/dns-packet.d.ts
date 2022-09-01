declare module 'dns-packet' {
  export * from 'dns-packet';

  export namespace a {
    export function decode(serialisation: Buffer): any;
  }
}
