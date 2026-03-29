---
artifact_id: SPEC-QUIC-PKT-PROT
artifact_type: specification
title: QUIC Packet Forms And Protection Context
domain: quic
capability: packet-form-and-protection-model
status: draft
owner: quic-maintainers
tags:
  - quic
  - packets
  - protection
  - classification
related_artifacts:
  - SPEC-QUIC-HDR
  - SPEC-QUIC-PKT-NUM
  - VER-QUIC-PKT-PROT-0001
---

# SPEC-QUIC-PKT-PROT - QUIC Packet Forms And Protection Context

## Purpose

This specification defines the Section 12 QUIC packet forms and the high-level protection posture attached to each form. The intended implementation surface is packet classification and higher-level protocol policy that can distinguish which packet forms exist and what confidentiality or integrity expectations apply before the repository takes on detailed QUIC-TLS algorithms.

## Scope

In scope are UDP-datagram carriage, long-header and short-header packet-form usage, the packet types enumerated by Section 12, and the packet-type-specific protection overview from RFC 9000 Section 12.1.

Out of scope are key derivation, AEAD construction, header-protection algorithms, and packet-number decoding details from QUIC-TLS and later packet-format sections.

## Context

Section 12 establishes the major packet forms that appear on the wire and summarizes how much protection each form receives. That overview is normative even though the actual cryptographic algorithms and key schedule are defined in QUIC-TLS.

## REQ-QUIC-PKT-PROT-0001 QUIC Packets Are Carried In UDP Datagrams
QUIC packets MUST be modeled as protocol units carried inside UDP datagrams.

Trace:
- Source Refs:
  - RFC 9000 Section 12
- Verified By:
  - VER-QUIC-PKT-PROT-0001

## REQ-QUIC-PKT-PROT-0002 Long Headers Are Used During Connection Establishment
This version of QUIC MUST use the long packet header during connection establishment.

Trace:
- Source Refs:
  - RFC 9000 Section 12
- Verified By:
  - VER-QUIC-PKT-PROT-0001

## REQ-QUIC-PKT-PROT-0003 Long-Header Packet Forms Are Enumerated
The long-header packet forms for this version of QUIC MUST be modeled as Initial, 0-RTT, Handshake, Retry, and Version Negotiation.

Trace:
- Source Refs:
  - RFC 9000 Section 12
- Verified By:
  - VER-QUIC-PKT-PROT-0001

Notes:
- Version Negotiation uses a version-independent long-header form.

## REQ-QUIC-PKT-PROT-0004 Short Headers Are Used After Establishment With 1-RTT Keys
Short-header packets MUST be modeled as the low-overhead packet form used after a connection is established and 1-RTT keys are available.

Trace:
- Source Refs:
  - RFC 9000 Section 12
- Verified By:
  - VER-QUIC-PKT-PROT-0001

## REQ-QUIC-PKT-PROT-0005 Packet Protection Depends On Packet Type
QUIC packets MUST be treated as having packet-type-dependent levels of cryptographic protection.

Trace:
- Source Refs:
  - RFC 9000 Section 12.1
- Verified By:
  - VER-QUIC-PKT-PROT-0001

## REQ-QUIC-PKT-PROT-0006 Version Negotiation Has No Cryptographic Protection
Version Negotiation packets MUST be treated as having no cryptographic protection.

Trace:
- Source Refs:
  - RFC 9000 Section 12.1
- Verified By:
  - VER-QUIC-PKT-PROT-0001

## REQ-QUIC-PKT-PROT-0007 Retry Packets Use AEAD Against Accidental Modification
Retry packets MUST be treated as using an AEAD function to protect against accidental modification.

Trace:
- Source Refs:
  - RFC 9000 Section 12.1
- Verified By:
  - VER-QUIC-PKT-PROT-0001

## REQ-QUIC-PKT-PROT-0008 Initial Packets Use Wire-Visible-Key AEAD And Lack Effective Confidentiality
Initial packets MUST be treated as protected with an AEAD function whose keys are derived from values visible on the wire, and therefore MUST be treated as lacking effective confidentiality protection.

Trace:
- Source Refs:
  - RFC 9000 Section 12.1
- Verified By:
  - VER-QUIC-PKT-PROT-0001

## REQ-QUIC-PKT-PROT-0009 Initial Protection Confirms Path Presence And Accidental-Modification Protection
Initial packet protection MUST be treated as existing to confirm that the sender is on the network path and to protect the packet against accidental modification.

Trace:
- Source Refs:
  - RFC 9000 Section 12.1
- Verified By:
  - VER-QUIC-PKT-PROT-0001

## REQ-QUIC-PKT-PROT-0010 Handshake-Derived Protection Applies To Handshake 0-RTT And 1-RTT
Handshake, 0-RTT, and 1-RTT packets MUST be treated as protected with keys derived from the cryptographic handshake.

Trace:
- Source Refs:
  - RFC 9000 Section 12.1
- Verified By:
  - VER-QUIC-PKT-PROT-0001

## REQ-QUIC-PKT-PROT-0011 0-RTT And 1-RTT Have Strong Confidentiality And Integrity
Packets protected with 0-RTT or 1-RTT keys MUST be treated as having strong confidentiality and integrity protection.

Trace:
- Source Refs:
  - RFC 9000 Section 12.1
- Verified By:
  - VER-QUIC-PKT-PROT-0001

## REQ-QUIC-PKT-PROT-0012 Packet Numbers Receive Header Protection When Present
When a packet type includes a Packet Number field, that field MUST be treated as receiving additional confidentiality protection through header protection.

Trace:
- Source Refs:
  - RFC 9000 Section 12.1
- Verified By:
  - VER-QUIC-PKT-PROT-0001

## Open Questions

- The concrete algorithms, key schedule, and unprotection procedure belong to QUIC-TLS and still need canonical repository requirements before cryptographic packet processing is implemented.
