# `@relaycorp/dnssec`

[![npm version](https://badge.fury.io/js/@relaycorp%2Fdnssec.svg)](https://www.npmjs.com/package/@relaycorp/dnssec)

This is a resolver-agnostic DNSSEC verification library for Node.js that allows you to use any transport you want: UDP, DNS-over-TLS (DoT), DNS-over-HTTPS (DoH), etc.

The latest version can be installed from NPM:

```shell
npm install @relaycorp/dnssec
```

## Usage

You need to write a thin integration with your preferred resolver, keeping the following in mind:

- DNS responses MUST include DNSSEC signatures (i.e., `RRSIG` records).
- DNS responses MUST be passed as a `Buffer` using DNS wire format (as defined in [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035)), or else you'll have to initialise a `Message` that contains all the relevant parts of the response (see below).
- You SHOULD instruct your resolver not to do DNSSEC validation remotely.

For example, this is how you could use [dohdec](https://www.npmjs.com/package/dohdec)'s DNS-over-HTTPS resolver with Cloudflare to retrieve `A` records for a particular domain name:

```js
// main.js
import { dnssecLookUp, Question, SecurityStatus } from '@relaycorp/dnssec';
import { DNSoverHTTPS } from 'dohdec';

const doh = new DNSoverHTTPS({ url: 'https://cloudflare-dns.com/dns-query' });

async function getARecord(domain) {
  return await dnssecLookUp(new Question(domain, 'A'), async (question) =>
    doh.lookup(question.name, {
      rrtype: question.getTypeName(),
      json: false, // Request DNS message in wire format
      decode: false, // Don't parse the DNS message
      dnssec: true, // Retrieve RRSIG records
      dnssecCheckingDisabled: true, // Disable server-side DNSSEC validation
    }),
  );
}

const [domainName] = process.argv.slice(2);
const result = await getARecord(domainName);
if (result.status === SecurityStatus.SECURE) {
  console.log(`${domainName}/A =`, result.result);
} else {
  const reason = result.reasonChain.join(', ');
  console.error(`DNSSEC verification for ${domain}/A failed: ${reason}`);
}
```

And here's what requesting a valid `A` record would look like with the script above:

```
$ node main.js example.com
example.com/A = RrSet {
  name: 'example.com.',
  classId: 1,
  type: 1,
  ttl: 83076,
  records: [
    DnsRecord {
      ttl: 83076,
      name: 'example.com.',
      typeId: 1,
      classId: 1,
      dataSerialised: <Buffer 5d b8 d8 22>,
      dataFields: '93.184.216.34'
    }
  ]
}
```

### Successful RRset

When DNSSEC validation succeeds, you get a `VerifiedRrSet` object with the following properties:

- `status`: Set to `SecurityStatus.SECURE`.
- `result`: An RRset containing one or more records (`DnsRecord` instances). Each record exposes its data in both serialised and deserialised forms in the `dataSerialised` and `dataFields` properties, respectively. `dataFields` is an object whose structure is determined by [`dns-packet`](https://www.npmjs.com/package/dns-packet).

### Error handling

As this is primarily a DNSSEC library, we treat DNS and DNSSEC errors differently:

- Any input that violates DNS RFCs in ways from which we can't recover will result in errors.
- Any input that violates DNSSEC RFCs will result in one of the three failure _security statuses_ defined in [RFC 4035 (Section 4.3)](https://www.rfc-editor.org/rfc/rfc4035#section-4.3): insecure, bogus or indeterminate.

However, errors are thrown upon attempting to parse malformed RDATA values for DNSSEC records -- we use a third-party library that parses the DNS message eagerly.

### Validation period

By default, DNSSEC signatures MUST be valid at the time the `dnssecLookUp()` function is called, but this can be customised by passing a `Date` or `DatePeriod` instance.

A `DatePeriod` instance is useful when you just want signatures to be valid **at any point** within a given time period. For example, if you want to tolerate [clock drift](https://en.wikipedia.org/wiki/Clock_drift), you could accept signatures valid in the past hour:

```js
import { DatePeriod, dnssecLookUp } from '@relaycorp/dnssec';
import { subHours } from 'date-fns';

const now = new Date();
const datePeriod = DatePeriod.init(now, subHours(now, 1));
dnssecLookUp(QUESTION, RESOLVER, { dateOrPeriod: datePeriod });
```

### Custom trust anchors

By default, the root `DNSKEY`(s) are verified against a local copy of [IANA's trust anchors](https://www.iana.org/dnssec/files). This can be customised with the `trustAnchors` option; e.g.:

```js
import {
  dnssecLookUp,
  DnssecAlgorithm,
  DigestType,
  TrustAnchor,
} from '@relaycorp/dnssec';

const customTrustAnchor: TrustAnchor = {
  algorithm: DnssecAlgorithm.RSASHA256,
  digest: Buffer.from('the digest'),
  digestType: DigestType.SHA256,
  keyTag: 42,
};
dnssecLookUp(QUESTION, RESOLVER, { trustAnchors: [customTrustAnchor] });
```

### Responses parsed eagerly

If your DNS lookup library parses responses eagerly and doesn't give you access to the original response in wire format, you will have to convert their messages to `Message` instances. Refer to our API docs to learn how to initialise `Message`s.

## Testing

To facilitate the simulation of the various outcomes of DNSSEC validation, we provide the `MockChain` utility so that you can pass a custom resolver and trust anchor to `dnssecLookUp()`. This is particularly useful in unit tests where you aren't able to mock this module (e.g., Jest doesn't support mocking our ESM as of this writing).

The following example shows how to generate a verified RRset:

```javascript
import {
  dnssecLookUp,
  DnsRecord,
  MockChain,
  RrSet,
  SecurityStatus,
} from '@relaycorp/dnssec';

const RECORD = new DnsRecord(
  `example.com.`,
  'TXT',
  DnsClass.IN,
  42,
  'The data',
);
const QUESTION = RECORD.makeQuestion();
const RRSET = RrSet.init(QUESTION, [RECORD]);

test('Generating a SECURE result', async () => {
  const mockChain = await MockChain.generate(RECORD.name);

  const { resolver, trustAnchors } = mockChain.generateFixture(
    RRSET,
    SecurityStatus.SECURE,
  );

  const result = await dnssecLookUp(QUESTION, resolver, { trustAnchors });
  expect(result).toStrictEqual({
    status: SecurityStatus.SECURE,
    result: RRSET,
  });
});
```

## API documentation

The API documentation is available on [docs.relaycorp.tech](https://docs.relaycorp.tech/dnssec-js/).

## Missing functionality

This library implements all the relevant RFCs defining DNSSEC, except for the following functionality that we didn't need, but for which you're welcome to propose PRs:

- [Denial of existence](https://github.com/relaycorp/dnssec-js/issues/17) (`NSEC` and `NSEC3` records).
- DSA (DNSSEC algorithm `3`) because [it's too insecure and hardly used](https://github.com/relaycorp/dnssec-js/issues/50).

The following [DNSSEC algorithms](https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml#dns-sec-alg-numbers-1) are unsupported, and we probably won't accept PRs for them:

- [GOST](https://en.wikipedia.org/wiki/GOST) (`12`) due to lack of support in Node.js, and its lack of popularity and security doesn't seem to justify integrating a third party NPM package supporting it (assuming a suitable one exists).
- [Private algorithms](https://www.rfc-editor.org/rfc/rfc4034.html#appendix-A.1.1) (`253` and `254`).

## Alternatives considered

As surprising as it may sound, there's no (reliable) way to do DNSSEC verification in Node.js in 2022, so when you see a JS app or library that claims DNSSEC support, [chances are they're just blindly trusting a resolver like Cloudflare or Google](https://stackoverflow.com/a/38339760/129437) -- which, admittedly, is sufficient in many cases and even desirable for performance reasons.

[The Node.js team considered adding DNSSEC support](https://github.com/nodejs/node/issues/14475) but ruled it out due to [lack of support in their upstream DNS library](https://github.com/c-ares/c-ares/pull/20). As a consequence, two libraries have tried to fill the vacuum:

- [getdns-node](https://github.com/getdnsapi/getdns-node). Unfortunately, it was last updated in June 2021 and its dependency on an externally-managed C library has proven extremely problematic (see [#8](https://github.com/getdnsapi/getdns-node/issues/8), [#33](https://github.com/getdnsapi/getdns-node/issues/33), [#38](https://github.com/getdnsapi/getdns-node/issues/38), [#42](https://github.com/getdnsapi/getdns-node/issues/42), etc).
- [dnssecjs](https://github.com/netkicorp/dnssecjs). Unfortunately, it was abandoned shortly after it was (apparently) completed in 2017 and it was never published to NPM (so it's unlikely it was ever used). We decided not to fork it because we won't know how reliable/secure it is (assuming it works) until we spend significant time reviewing the code and testing it, and then we'd have to spend a lot more time to (1) rewrite it to match the tech and best practices available in 2022 (e.g., TypeScript) and (2) thoroughly unit test it (and it doesn't have a single test).

## Node.js version support

This library requires Node.js 16 or newer, but going forward we will follow the Node.js release schedule.

## Contributions

We love contributions! If you haven't contributed to a Relaycorp project before, please take a minute to [read our guidelines](https://github.com/relaycorp/.github/blob/master/CONTRIBUTING.md) first.
