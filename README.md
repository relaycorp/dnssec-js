# `@relaycorp/dnssec`

Resolver-agnostic DNSSEC library for Node.js.

## Alternatives considered

As surprising as it may sound, there's no (reliable) way to do DNSSEC verification in Node.js in 2022, so when you see a JS app or library that claims DNSSEC support, [chances are they're just blindly trusting a resolver like Cloudflare or Google](https://stackoverflow.com/a/38339760/129437) -- which, admittedly, is sufficient in many cases and even desirable for performance reasons.

[The Node.js team considered adding DNSSEC support](https://github.com/nodejs/node/issues/14475) but ruled it out due to [lack of support in their upstream DNS library](https://github.com/c-ares/c-ares/pull/20). As a consequence, two libraries have tried to fill the vacuum:

- [getdns-node](https://github.com/getdnsapi/getdns-node). Unfortunately, it was last updated in June 2021 and its dependency on an externally-managed C library has proven extremely problematic (see [#8](https://github.com/getdnsapi/getdns-node/issues/8), [#33](https://github.com/getdnsapi/getdns-node/issues/33), [#38](https://github.com/getdnsapi/getdns-node/issues/38), [#42](https://github.com/getdnsapi/getdns-node/issues/42), etc).
- [dnssecjs](https://github.com/netkicorp/dnssecjs). Unfortunately, it was abandoned shortly after it was (apparently) completed in 2017 and it was never published to NPM (so it's unlikely it was ever used). We decided not to fork it because we won't know how reliable/secure it is (assuming it works) until we spend significant time reviewing the code and testing it, and then we'd have to spend a lot more time to (1) rewrite it to match the tech and best practices available in 2022 (e.g., TypeScript) and (2) thoroughly unit test it (and it doesn't have a single test).

## Design decisions

Although this is a general-purpose DNSSEC library, some key design decisions stem from our need to build the library for the sole purpose of using it in [Vera](https://vera.domains).

### Resolver agnosticism

DNS resolution is a problem solved in Node.js -- there's just no shortage of reliable UDP-, TLS- or HTTPS-based resolvers on NPM. So we didn't want to create a new resolver or tie our DNSSEC implementation to any particular resolver.

### DNS message parsing (RFC 1035)

We decided to write a partial implementation of the DNS wire format (as specified in RFC 1035, Section 4) because the existing third-party implementations we found on NPM ([dns-packet](https://www.npmjs.com/package/dns-packet) and [dns2](https://www.npmjs.com/package/dns2)) parsed the entire message eagerly (all the way down to the RDATA fields) and didn't offer an option to keep the original byte stream.

This would've made it cumbersome to validate DNSSEC signatures, as we'd need to re-serialise the records that we just parsed. A re-serialisation would also introduce the possibility that the new byte stream would be functionally equivalent but not identical to the one that was originally signed (especially when re-serialising the RDATA field).

Fortunately, since we're only interested in the _answers_ section of the message, our implementation is very straightforward.

### Error handling

As this is primarily a DNSSEC library, we treat DNS and DNSSEC errors differently:

- Any input that violates DNS RFCs in ways from which we can't recover will result in errors.
- Any input that violates DNSSEC RFCs will result in one of the three failure _security statuses_ defined in [RFC 4035 (Section 4.3)](https://www.rfc-editor.org/rfc/rfc4035#section-4.3): insecure, bogus or indeterminate.

### Denial of Existence record support

We don't need DoE records in Vera, so [we won't be implementing that functionality ourselves](https://github.com/relaycorp/dnssec-js/issues/17), but PRs are welcomed.

### Signature production support

This library supports producing RRSig records simply for testing purposes: It makes it very easy to test valid and invalid signatures both internally and from any software using this library, without mocking anything.

### Cryptographic Algorithms support

We support all the _Zone Signing_ [DNSSEC algorithms](https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml#dns-sec-alg-numbers-1) as of 2022, except for:

- DSA (`3`) because [it's too insecure and hardly used](https://github.com/relaycorp/dnssec-js/issues/50).
- NSEC3 (`6` and `7`) because [we don't currently support Denial of Existence records](https://github.com/relaycorp/dnssec-js/issues/17).
- [GOST](https://en.wikipedia.org/wiki/GOST) (`12`) due to lack of support in Node.js, and its lack of popularity and security doesn't seem to justify integrating a third party NPM package supporting it (assuming a suitable one exists).
- Private algorithms (`253` and `254`) because we have no use for those, but we'd welcome PRs to implement them.
