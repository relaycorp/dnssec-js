# `@relaycorp/dnssec-verifier`

Resolver-agnostic DNSSEC chain verification library for Node.js


## Alternatives considered

- https://github.com/getdnsapi/getdns-node, but:
  - Last activity June 2021.
  - Dependency on an externally-managed C library is just asking for way too much trouble, not only to get started but throughout the maintenance phase, as shown in the GitHub issues (#8, #33, #38, #42, etc).
- https://github.com/netkicorp/dnssecjs, but
  - It was abandoned shortly after it was (apparently) completed in 2017.
  - It wasn't published to NPM, so it's unlikely it was ever used.
  - Forking it seems unwise, since: we don't even know how reliable/secure it is (assuming it works at all) until we spend significant time reviewing the code and testing it, and then we'd have to spend a lot more time to (1) rewrite it to match the tech and best practices available in 2022 and (2) thoroughly unit test it (and it doesn't have a single test).
