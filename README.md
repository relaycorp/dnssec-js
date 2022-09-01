# `@relaycorp/dnssec-verifier`

Resolver-agnostic DNSSEC chain verification library for Node.js

## Design decisions

### Resolver agnosticism

### DNS message parsing (RFC 1035)

Why not: dns-packet, dns2, dns-node

## Alternatives considered

As surprising as it may sound, there's no (reliable) way to do DNSSEC verification in Node.js in 2022, so when you see a JS app or library that claims DNSSEC support, [chances are they're just blindly trusting a resolver like Cloudflare or Google](https://stackoverflow.com/a/38339760/129437) -- which, admittedly, is sufficient in many cases and even desirable for performance reasons.

[The Node.js team considered adding DNSSEC support](https://github.com/nodejs/node/issues/14475) but ruled it out due to [lack of support in their upstream DNS library](https://github.com/c-ares/c-ares/pull/20). As a consequence, two libraries have tried to fill the vacuum:

- [getdns-node](https://github.com/getdnsapi/getdns-node). Unfortunately, it was last updated in June 2021 and its dependency on an externally-managed C library has proven extremely problematic (see [#8](https://github.com/getdnsapi/getdns-node/issues/8), [#33](https://github.com/getdnsapi/getdns-node/issues/33), [#38](https://github.com/getdnsapi/getdns-node/issues/38), [#42](https://github.com/getdnsapi/getdns-node/issues/42), etc).
- [dnssecjs](https://github.com/netkicorp/dnssecjs). Unfortunately, it was abandoned shortly after it was (apparently) completed in 2017 and it was never published to NPM (so it's unlikely it was ever used). We decided not to fork it because we won't know how reliable/secure it is (assuming it works) until we spend significant time reviewing the code and testing it, and then we'd have to spend a lot more time to (1) rewrite it to match the tech and best practices available in 2022 (e.g., TypeScript) and (2) thoroughly unit test it (and it doesn't have a single test).

We also considered contributing our DNSSEC verification implementation to the [node-dns project](https://github.com/song940/node-dns/issues/3), but decided not to because we prefer an implementation that's agnostic of the DNS resolver. After all, we're only building this library so that we can do DNSSEC verification offline in [Vera](https://vera.domains).
