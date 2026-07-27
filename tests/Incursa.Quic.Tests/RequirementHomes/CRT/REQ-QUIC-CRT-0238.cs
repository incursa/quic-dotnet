// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;

namespace Incursa.Quic.Tests.RequirementHomes.CRT;

[Requirement("REQ-QUIC-CRT-0238")]
public sealed partial class REQ_QUIC_CRT_0238
{
    private static readonly string[] ProofSlugs =
    [
        "oversized-single",
        "oversized-bounded",
        "queued-single",
    ];

    [Theory]
    [InlineData("oversized-single", "single_fragment", 1)]
    [InlineData("oversized-bounded", "bounded_multi_fragment", 2)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void OversizedCandidateCaptureMatchesTheProductionMechanism(
        string proofSlug,
        string expectedValue,
        int expectedQuantum)
    {
        using JsonDocument capture = ReadProofJson(
            proofSlug,
            "mechanism-capture.json");
        JsonElement positive = GetCaptureCase(
            capture.RootElement,
            "positive_actuation");
        QuicOversizedWriteAdmissionPolicyMode mode = expectedValue switch
        {
            "single_fragment" =>
                QuicOversizedWriteAdmissionPolicyMode.SingleFragment,
            "bounded_multi_fragment" =>
                QuicOversizedWriteAdmissionPolicyMode.BoundedMultiFragment,
            _ => throw new InvalidOperationException(),
        };
        int legacyQuantum = mode ==
            QuicOversizedWriteAdmissionPolicyMode.SingleFragment ? 2 : 1;
        QuicOversizedWriteAdmissionObservation observation =
            CreateOversizedObservation(legacyQuantum);

        QuicOversizedWriteAdmissionResolution resolution =
            QuicOversizedWriteAdmissionPolicy.Resolve(
                in observation,
                QuicOversizedWriteAdmissionObservationMode.ObserveOnly,
                hasForcedValue: true,
                mode);

        Assert.Equal(expectedValue, positive.GetProperty(
            "candidate_value").GetString());
        Assert.Equal(expectedValue, positive.GetProperty(
            "applied_value").GetString());
        Assert.Equal(expectedQuantum, positive.GetProperty(
            "applied_work_count").GetInt32());
        Assert.Equal(expectedQuantum, resolution.AppliedChunkQuantum);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1SelectionSource.Forced,
            resolution.Decision.SelectionSource);
        Assert.Equal(
            expectedQuantum == 1
                ? "mechanism_event.oversized_write.one_fragment_per_turn"
                : "mechanism_event.oversized_write.bounded_two_fragments_per_turn",
            positive.GetProperty("mechanism_event_id").GetString());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void QueuedCandidateCaptureMatchesTheProductionMechanism()
    {
        using JsonDocument capture = ReadProofJson(
            "queued-single",
            "mechanism-capture.json");
        JsonElement positive = GetCaptureCase(
            capture.RootElement,
            "positive_actuation");
        int legalCount = positive.GetProperty(
            "legal_work_count").GetInt32();
        QuicQueuedApplicationSendBudget legalBudget =
            QuicQueuedApplicationSendBudget.Allowed(
                legalCount,
                maxPayloadBytes: 1_480);
        QuicQueuedApplicationSendBudget applied =
            QuicQueuedSendBurstPolicy.Apply(
                QuicQueuedSendBurstPolicyMode.SingleDatagram,
                legalBudget);

        Assert.True(legalCount > 1);
        Assert.Equal(1, applied.MaxDatagrams);
        Assert.Equal(1, positive.GetProperty(
            "applied_work_count").GetInt32());
        Assert.Equal(
            "mechanism_event.queued_send.single_datagram_cap",
            positive.GetProperty("mechanism_event_id").GetString());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EveryCandidateRetainsFallbackShadowRollbackAndImmutableInputs()
    {
        foreach (string proofSlug in ProofSlugs)
        {
            using JsonDocument capture = ReadProofJson(
                proofSlug,
                "mechanism-capture.json");
            JsonElement fallback = GetCaptureCase(
                capture.RootElement,
                "safety_fallback");
            JsonElement shadow = GetCaptureCase(
                capture.RootElement,
                "shadow_neutrality");
            JsonElement rollback = GetCaptureCase(
                capture.RootElement,
                "rollback");

            Assert.Contains(
                fallback.GetProperty(
                    "operation_eligibility_result").GetString(),
                new[] { "clamped", "ineligible" });
            Assert.Equal(JsonValueKind.Null, shadow.GetProperty(
                "forced_value").ValueKind);
            Assert.Equal("legacy_current", shadow.GetProperty(
                "applied_value").GetString());
            Assert.Equal(JsonValueKind.Null, rollback.GetProperty(
                "forced_value").ValueKind);
            Assert.Equal("legacy_current", rollback.GetProperty(
                "applied_value").GetString());

            using JsonDocument proof = ReadProofJson(
                proofSlug,
                "proof-candidate.json");
            Assert.Equal("candidate", proof.RootElement.GetProperty(
                "review_status").GetString());
            Assert.Equal(JsonValueKind.Null, proof.RootElement.GetProperty(
                "review_outcome").ValueKind);
            Assert.False(proof.RootElement.GetProperty(
                "active_behavior_authorization").GetBoolean());
            Assert.False(proof.RootElement.GetProperty(
                "performance_acceptance_authorization").GetBoolean());

            string inputRoot = GetProofPath(proofSlug, "inputs");
            Assert.Equal(15, Directory.EnumerateFiles(
                inputRoot,
                "*.json",
                SearchOption.TopDirectoryOnly).Count());
        }
    }

    private static QuicOversizedWriteAdmissionObservation
        CreateOversizedObservation(int legacyQuantum)
        => new(
            LogicalWriteSequence: 1,
            CapturedAtTicks: 1,
            QuicOversizedWriteAdmissionObservation
                .CurrentObservationContractVersion,
            QuicOversizedWriteAdmissionObservation.CurrentRuleVersion,
            QuicOversizedWriteAdmissionSignalMask.None,
            QuicOversizedWriteAdmissionSignalMask.None,
            QuicOversizedWriteAdmissionCondition.None,
            QuicAdaptiveRuntimeLifecycle.None,
            LogicalWriteBytes: 65_536,
            LogicalRemainingBytes: 65_536,
            MaximumApplicationPayloadBytes: 32_768,
            MaximumFragmentBytes: 32_768,
            DistinctObservedStreams: legacyQuantum == 2
                ? (ushort)16
                : (ushort)4,
            QueuedApplicationWrites: 1,
            QueueDelayEwmaMicros: 0,
            ActorServiceTimeEwmaMicros: 0,
            BytesInFlight: 0,
            CongestionWindowBytes: 65_536,
            RetainedSendBuffers: 1,
            RetainedSendBytes: 65_536,
            ContinuationDispatcherAvailable: true,
            LegacySelectedChunkQuantum: legacyQuantum,
            LegalMaximumChunkQuantum: 2);

    private static JsonElement GetCaptureCase(
        JsonElement root,
        string captureCase)
        => root.GetProperty("operations")
            .EnumerateArray()
            .Single(operation => operation.GetProperty(
                "capture_case").GetString() == captureCase);

    private static JsonDocument ReadProofJson(
        string proofSlug,
        string relativePath)
        => JsonDocument.Parse(File.ReadAllText(
            GetProofPath(proofSlug, relativePath)));

    private static string GetProofPath(
        string proofSlug,
        string relativePath)
        => Path.Combine(
            GetRepositoryRoot(),
            "tests",
            "fixtures",
            "adaptive-runtime-factor-onboarding",
            "proofs",
            proofSlug,
            relativePath);

    private static string GetRepositoryRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "Incursa.Quic.slnx")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException(
            "The quic-dotnet repository root was not found.");
    }
}
