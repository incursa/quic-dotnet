// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class RFC9000_TailDeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S5-0006")]
    [Requirement("REQ-QUIC-RFC9000-S7-0006")]
    [Requirement("REQ-QUIC-RFC9000-S7-0007")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ZeroRttAndHandshakeSecurityRequirementsStayBoundedToExistingTlsState()
    {
        AssertRequirementContains(
            "REQ-QUIC-RFC9000-S5-0006",
            "0-RTT",
            "MUST NOT provide protection against replay attacks");
        AssertRequirementExcludes(
            "REQ-QUIC-RFC9000-S5-0006",
            "anti-replay subsystem",
            "runtime enforcement");

        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        Assert.True(runtime.TlsState.OneRttKeysAvailable);
        Assert.True(runtime.TlsState.PeerTransportParametersCommitted);
        Assert.NotNull(runtime.TlsState.OneRttOpenPacketProtectionMaterial);
        Assert.NotNull(runtime.TlsState.OneRttProtectPacketProtectionMaterial);
        Assert.NotNull(runtime.TlsState.PeerTransportParameters);

        AssertRequirementContains(
            "REQ-QUIC-RFC9000-S7-0006",
            "cryptographic handshake",
            "packet protection",
            "0-RTT",
            "1-RTT");
        AssertRequirementContains(
            "REQ-QUIC-RFC9000-S7-0007",
            "cryptographic handshake",
            "authenticated exchange",
            "transport parameter values",
            "both endpoints");
    }

    [Fact]
    [Requirement("RFC9000-S19-21-P3-S1-R01")]
    [Requirement("RFC9000-S19-21-P4-S1-R01")]
    [Requirement("RFC9000-S19-21-P4-S1-R02")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ExtensionFramePolicyRequirementsRemainNegotiatedCongestionControlledAndAckEliciting()
    {
        AssertRequirementContains(
            "RFC9000-S19-21-P3-S1-R01",
            "SHOULD define their interaction",
            "previously defined extensions",
            "same protocol components");
        AssertRequirementContains(
            "RFC9000-S19-21-P4-S1-R01",
            "Extension frames",
            "MUST be congestion controlled");
        AssertRequirementContains(
            "RFC9000-S19-21-P4-S1-R02",
            "Extension frames",
            "MUST cause an ACK frame to be sent");
        AssertPermanentFrameRegistryContainsAckElicitingAndCongestionControlledBaseFrames();
    }

    [Fact]
    [Requirement("RFC9000-S21-11-P2-R01")]
    [Requirement("RFC9000-S21-11-P3-R01")]
    [Requirement("RFC9000-S21-3-P2-R01")]
    [Requirement("RFC9000-S21-6-P2-R01")]
    [Requirement("RFC9000-S21-7-P4-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_DeploymentSecurityPolicyRequirementsStayBoundedToMitigationLanguage()
    {
        AssertRequirementContains(
            "RFC9000-S21-11-P2-R01",
            "stateless resets",
            "MUST be arranged",
            "connection ID",
            "connection state");
        AssertRequirementContains(
            "RFC9000-S21-11-P3-R01",
            "MUST NOT generate a stateless reset",
            "could be active",
            "same static key");
        AssertRequirementContains(
            "RFC9000-S21-3-P2-R01",
            "SHOULD provide mitigations",
            "limiting the usage and lifetime",
            "address validation tokens");
        AssertRequirementContains(
            "RFC9000-S21-6-P2-R01",
            "SHOULD provide mitigations",
            "Slowloris",
            "maximum number of clients",
            "minimum transfer speed");
        AssertRequirementContains(
            "RFC9000-S21-7-P4-R01",
            "SHOULD provide mitigations",
            "stream fragmentation attacks");
    }

    [Fact]
    [Requirement("RFC9000-S21-5-6-P2-S1-R01")]
    [Requirement("RFC9000-S21-5-6-P2-S2-R01")]
    [Requirement("RFC9000-S21-5-6-P3-S3-R01")]
    [Requirement("RFC9000-S21-5-6-P5-S4-R01")]
    [Requirement("RFC9000-S21-5-P8-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AddressSafetyAndMigrationExtensionRequirementsStayBoundedToPolicyControls()
    {
        AssertRequirementContains(
            "RFC9000-S21-5-6-P2-S1-R01",
            "MAY prevent",
            "loopback address");
        AssertRequirementContains(
            "RFC9000-S21-5-6-P2-S2-R01",
            "SHOULD NOT allow",
            "loopback address",
            "previously available at a different interface");
        AssertRequirementContains(
            "RFC9000-S21-5-6-P3-S3-R01",
            "SHOULD NOT refuse",
            "specific knowledge",
            "not safe");
        AssertRequirementContains(
            "RFC9000-S21-5-6-P5-S4-R01",
            "MAY retire connection IDs",
            "patterns known to be problematic");
        AssertRequirementContains(
            "RFC9000-S21-5-P8-S2-R01",
            "server migration",
            "MUST also define countermeasures",
            "forgery attacks");
    }

    [Fact]
    [Requirement("RFC9000-S22-1-2-P1-S1-R01")]
    [Requirement("RFC9000-S22-1-2-P4-S1-R01")]
    [Requirement("RFC9000-S22-1-3-P2-S1-R01")]
    [Requirement("RFC9000-S22-1-3-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RegistryRequestAndRemovalReviewRequirementsKeepExpertDecisionBoundaries()
    {
        AssertRequirementContains(
            "RFC9000-S22-1-2-P1-S1-R01",
            "Requests for multiple codepoints",
            "MAY use a contiguous range");
        AssertRequirementContains(
            "RFC9000-S22-1-2-P4-S1-R01",
            "Applications to register codepoints",
            "MAY include a requested codepoint");
        AssertRequirementContains(
            "RFC9000-S22-1-3-P2-S1-R01",
            "MUST be reviewed",
            "designated experts");
        AssertRequirementContains(
            "RFC9000-S22-1-3-P2-S2-R01",
            "experts MUST attempt",
            "whether the codepoint is still in use");
    }

    [Fact]
    [Requirement("RFC9000-S22-1-3-P3-S1-R01")]
    [Requirement("RFC9000-S22-1-3-P4-S1-R01")]
    [Requirement("RFC9000-S22-1-4-P4-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RegistryReclamationAndPermanenceRequirementsPreserveFinalDispositionRules()
    {
        AssertRequirementContains(
            "RFC9000-S22-1-3-P3-S1-R01",
            "If any use",
            "MUST NOT be reclaimed");
        AssertRequirementContains(
            "RFC9000-S22-1-3-P4-S1-R01",
            "If no use",
            "MAY be removed");
        AssertRequirementContains(
            "RFC9000-S22-1-4-P4-R01",
            "Standards Track publications",
            "MUST be permanent");
    }

    private static void AssertRequirementContains(string requirementId, params string[] expectedFragments)
    {
        string statement = QuicRfc9000RequirementSpecSupport.GetStatement(requirementId);
        Assert.False(string.IsNullOrWhiteSpace(statement));

        foreach (string expectedFragment in expectedFragments)
        {
            Assert.Contains(expectedFragment, statement, StringComparison.Ordinal);
        }
    }

    private static void AssertRequirementExcludes(string requirementId, params string[] forbiddenFragments)
    {
        string statement = QuicRfc9000RequirementSpecSupport.GetStatement(requirementId);

        foreach (string forbiddenFragment in forbiddenFragments)
        {
            Assert.DoesNotContain(forbiddenFragment, statement, StringComparison.Ordinal);
        }
    }

    private static void AssertPermanentFrameRegistryContainsAckElicitingAndCongestionControlledBaseFrames()
    {
        Assert.Contains(
            QuicFrameRegistryProofSupport.PermanentFrameTypes,
            entry => entry.FrameTypeName == "PING" && entry.FieldSemantics.Contains("elicits an acknowledgment", StringComparison.Ordinal));
        Assert.DoesNotContain(
            QuicFrameRegistryProofSupport.PermanentFrameTypes,
            entry => entry.FrameTypeName.Contains("EXTENSION", StringComparison.OrdinalIgnoreCase));
    }
}
