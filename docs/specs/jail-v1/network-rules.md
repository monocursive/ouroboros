# Jail v1 network rules

Normative ruleset `ouro.jail.network/1`, referenced by [§10](../jail-v1.md#10-network-mediation).
The ruleset is frozen with the versioned data in
[network-addresses.json](network-addresses.json). Updating that data or IDNA
semantics requires a ruleset version change and conformance rerun; it is never
fetched at launch. The backend report records the implementation/version.

## Host parsing

Use [UTS 46 revision 35, Unicode 17.0.0](https://www.unicode.org/reports/tr46/tr46-35.html),
ToASCII with transitional processing off, UseSTD3ASCIIRules=true,
CheckHyphens=true, CheckBidi=true, CheckJoiners=true and VerifyDnsLength=true.
Reject all processing errors, invalid A-labels, empty interior labels, multiple
trailing dots, controls, percent escapes and IPv6 zone identifiers. Remove at
most one terminal dot after mapping; ASCII output is lowercase. Validate the
wildcard separately: only one whole leading `*.` label is allowed in a rule,
never in a request. It matches at least one label and excludes the apex.

Parse IPv4 only as four decimal octets, 0–255, without leading zeros except
the single digit 0. Reject legacy one/two/three-part, integer, hex and octal
forms rather than passing them to a resolver. Numeric-looking invalid IPv4
strings do not become DNS names. Parse IPv6 as an address, with brackets when
a port is present. Ports are decimal integers 1–65535. Apply normalization
identically to requests, grants and resolver answers.
If IDNA mapping produces a numeric address, apply the numeric parsing rules
again; it must not take a hostname-only path. Canonical allow rules always have
an explicit decimal port without leading zeroes. An omitted port expands to
two rules, port 80 and port 443. IPv6 uses RFC 5952 lowercase compressed form
in brackets; IPv4-mapped addresses use their normalized IPv4 form.

Normalize `::ffff:0:0/96` IPv4-mapped IPv6 to the embedded IPv4 before address
classification, matching an address grant, and choosing the numeric connection
target. Reject deprecated compatible `::/96` forms other than the ordinary
unspecified/loopback addresses (which are denied below by default). This is
conservative refusal, not a claim those obsolete forms are normally routable.

## Numeric destination policy

The checked-in prefix table is the union of the IANA IPv4/IPv6 special-purpose
registry allocations retrieved on 2026-09-21 and explicit conservative
additions. All listed prefixes are denied by default, including special-purpose
allocations that IANA marks globally reachable; this is an Ouroboros policy,
not an interpretation of IANA's reachability column. Mapped addresses are
classified after normalization. IPv6 outside 2000::/3 is also denied by default.
IPv4 multicast, IPv6 multicast and known cloud service addresses are included.

A hostname grant never overrides this table. Only an explicit numeric address
grant for that exact normalized address and port can override a default denial;
it grants no prefix. Hostname matching still applies to a hostname request.
Malformed representations cannot be granted. Mixed DNS sets refuse if any
answer fails the address check. No implicit second resolution is allowed.

Known translation ranges (including 64:ff9b::/96 and 64:ff9b:1::/48) are denied
as whole ranges by default, so encoded forbidden IPv4 cannot bypass the check.
Network-specific NAT64 prefixes must be supplied by the trusted host manifest
and merged into `network.translation_prefixes` before snapshot/digest creation;
project config cannot change them. Explicit address exceptions remain visible
operator authority. [RFC 6052](https://www.rfc-editor.org/rfc/rfc6052.html)
permits network-specific prefixes: the proxy cannot discover arbitrary host
translation/routing from an address alone. Its guarantee assumes the provisioned
host network describes those prefixes; it does not classify every service
behind an otherwise allowed public endpoint. No NAT64 discovery service is
introduced in v1.

## N03 fixtures

[network-cases.json](fixtures/network-cases.json) pins default classification
and representative normalization failures. The Linux proxy suite must also
exercise explicit numeric exceptions, nondefault ports, mixed answers,
rebinding, Host/absolute-URI disagreement and normalized wildcard matching.
IDNA cases include `BÜCHER.example.` → `xn--bcher-kva.example`, `faß.de` →
`xn--fa-hia.de`, invalid joiners, malformed A-labels, and repeated dots. Tests
use a controlled resolver; no public DNS request establishes conformance.
