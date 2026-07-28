// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0248")]
public sealed class REQ_QUIC_CRT_0248
{
    private const string Hash =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string CampaignId =
        "campaign.send_admission_composition.performance.v1";
    private const string PackagePathManifestHash =
        "257b31f3f93c6a34e14066b2c5d77bfc15ab5f2cfe54603b8d9244eb93fb7fd9";
    private const string FamilyCatalogHash =
        "cfee17afcc28da35e657b2d1331bde68c752b5a3487f0af69087c12df6530b93";
    private const string RelationshipCatalogHash =
        "fd6dfa5b02b3423de16ab72c08f99b93c85d186218524c4025b8a47e1fa7b4fc";
    private const string ConstraintCatalogHash =
        "90c85812b46e2aaa639b05bd1d6583d03c9c6b9c0f0730fd67f9567d1210cc49";
    private const string BatchProofHash =
        "f40368b49bfdc8607d22449e7e80e6c1dda03a611da2362909907710a6d24b37";
    private const string BufferProofHash =
        "da60ba782cd646f6c285ff1ef6dda877bc30c984054644f2bc501025e6c02408";
    private const string OversizedProofHash =
        "2b444f8048d30a727a65d93b64bb25a138f9aca5e1b104c8b9900bf7a79df980";

    [Theory]
    [MemberData(nameof(ExactCells))]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ExactReviewedA0ThroughA7CellMayConfigureOnlyForOfflineMeasurement(
        string cellId,
        string cellHash,
        int oversizedModeValue,
        int batchModeValue,
        int bufferValueValue)
    {
        QuicOversizedWriteAdmissionPolicyMode oversizedMode =
            (QuicOversizedWriteAdmissionPolicyMode)oversizedModeValue;
        QuicApplicationSendBatchPolicyMode batchMode =
            (QuicApplicationSendBatchPolicyMode)batchModeValue;
        QuicBufferCopyPolicyValue bufferValue =
            (QuicBufferCopyPolicyValue)bufferValueValue;
        using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport
                .CreateFinishedClientRuntimeWithValidatedActivePath();

        QuicAdaptiveRuntimeAdmissionPerformanceAuthorization authorization =
            CreateAuthorization(
                cellId,
                cellHash,
                oversizedMode,
                batchMode,
                bufferValue);

        runtime.ConfigureAdaptiveRuntimePolicy(CreateOptions(
            authorization,
            oversizedMode,
            batchMode,
            bufferValue));

        Assert.Equal(cellId, authorization.CellId);
        Assert.Equal(cellHash, authorization.CellContentSha256);
        Assert.Equal(CampaignId, authorization.CampaignId);
        Assert.Equal(Hash, authorization.ManifestContentSha256);
        Assert.Equal("send_admission_composition", authorization.FamilyId);
        Assert.Equal(1, authorization.ContractVersion);
        Assert.Equal(batchMode, runtime.ApplicationSendBatchPolicyMode);
        Assert.True(authorization.OfflineMeasurementOnly);
        Assert.False(authorization.ActiveBehaviorAuthorization);
        Assert.False(authorization.PerformanceAcceptanceAuthorization);
    }

    [Theory]
    [MemberData(nameof(ReviewedPackagePathCells))]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ExactReviewedPackagePathCellMayConfigureOnlyForOfflineMeasurement(
        string cellId,
        string cellHash,
        int oversizedModeValue,
        int batchModeValue,
        int bufferValueValue)
    {
        QuicOversizedWriteAdmissionPolicyMode oversizedMode =
            (QuicOversizedWriteAdmissionPolicyMode)oversizedModeValue;
        QuicApplicationSendBatchPolicyMode batchMode =
            (QuicApplicationSendBatchPolicyMode)batchModeValue;
        QuicBufferCopyPolicyValue bufferValue =
            (QuicBufferCopyPolicyValue)bufferValueValue;

        QuicAdaptiveRuntimeAdmissionPerformanceAuthorization authorization =
            CreateReviewedPackagePathAuthorization(
                CampaignId,
                cellId,
                cellHash,
                oversizedMode,
                batchMode,
                bufferValue);

        using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport
                .CreateFinishedClientRuntimeWithValidatedActivePath();

        runtime.ConfigureAdaptiveRuntimePolicy(CreateOptions(
            authorization,
            oversizedMode,
            batchMode,
            bufferValue));

        Assert.Equal(cellId, authorization.CellId);
        Assert.Equal(cellHash, authorization.CellContentSha256);
        Assert.Equal(PackagePathManifestHash, authorization.ManifestContentSha256);
        Assert.Equal(CampaignId, authorization.CampaignId);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void BoundedMultiFragmentAndCellsOutsideA0ThroughA7AreRejected()
    {
        Assert.Throws<ArgumentException>(() => CreateAuthorization(
            "cell.send_admission_composition.correctness.a4",
            "99c02f1b21aaef38b13b996a8e25d31b1e78d1f6927433470dd743ddc3a37598",
            QuicOversizedWriteAdmissionPolicyMode.BoundedMultiFragment,
            QuicApplicationSendBatchPolicyMode.LegacyCurrent,
            QuicBufferCopyPolicyValue.LegacyCurrent));
        Assert.Throws<ArgumentException>(() => CreateAuthorization(
            "cell.send_admission_composition.correctness.a8",
            Hash,
            QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent,
            QuicApplicationSendBatchPolicyMode.LegacyCurrent,
            QuicBufferCopyPolicyValue.LegacyCurrent));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void StaleCatalogAndProofHashesAreRejected()
    {
        Assert.Throws<ArgumentException>(() =>
            CreateAuthorization(
                "cell.send_admission_composition.correctness.a0",
                "c9e070a0880872c9c9dce62f07e933a0de96c7590d343ce7f923f121278bba28",
                QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent,
                QuicApplicationSendBatchPolicyMode.LegacyCurrent,
                QuicBufferCopyPolicyValue.LegacyCurrent,
                familyCatalogHash: Hash));
        Assert.Throws<ArgumentException>(() =>
            CreateAuthorization(
                "cell.send_admission_composition.correctness.a0",
                "c9e070a0880872c9c9dce62f07e933a0de96c7590d343ce7f923f121278bba28",
                QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent,
                QuicApplicationSendBatchPolicyMode.LegacyCurrent,
                QuicBufferCopyPolicyValue.LegacyCurrent,
                oversizedProofHash: Hash));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CampaignAndManifestBindingsAreRejectedWhenStaleOrInvalid()
    {
        Assert.Throws<ArgumentException>(() =>
            QuicAdaptiveRuntimeAdmissionPerformanceAuthorization
                .CreateForReviewedManifest(
                    " ",
                    Hash,
                    "cell.send_admission_composition.correctness.a0",
                    "c9e070a0880872c9c9dce62f07e933a0de96c7590d343ce7f923f121278bba28",
                    FamilyCatalogHash,
                    RelationshipCatalogHash,
                    ConstraintCatalogHash,
                    BatchProofHash,
                    BufferProofHash,
                    OversizedProofHash,
                    QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent,
                    QuicApplicationSendBatchPolicyMode.LegacyCurrent,
                    QuicBufferCopyPolicyValue.LegacyCurrent));
        Assert.Throws<ArgumentException>(() =>
            QuicAdaptiveRuntimeAdmissionPerformanceAuthorization
                .CreateForReviewedManifest(
                    CampaignId,
                    "not-a-sha256",
                    "cell.send_admission_composition.correctness.a0",
                    "c9e070a0880872c9c9dce62f07e933a0de96c7590d343ce7f923f121278bba28",
                    FamilyCatalogHash,
                    RelationshipCatalogHash,
                    ConstraintCatalogHash,
                    BatchProofHash,
                    BufferProofHash,
                    OversizedProofHash,
                    QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent,
                    QuicApplicationSendBatchPolicyMode.LegacyCurrent,
                    QuicBufferCopyPolicyValue.LegacyCurrent));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PackagePathAuthorizationRejectsNonReviewedTuples()
    {
        Assert.Throws<ArgumentException>(() =>
            CreateReviewedPackagePathAuthorization(
                CampaignId,
                "cell.send_admission_composition.correctness.a1",
                "c41ed6674829898c3dc4e9af34cca11d159c07642c267a893b9d7097c3cc4f25",
                QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent,
                QuicApplicationSendBatchPolicyMode.LegacyCurrent,
                QuicBufferCopyPolicyValue.MemoryConservative));
        Assert.Throws<ArgumentException>(() =>
            CreateReviewedPackagePathAuthorization(
                CampaignId,
                "cell.send_admission_composition.correctness.a2",
                "68c4112be72f82a9eb11b8a6dcf0594542337960c85bcc5f7386d91a172341db",
                QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent,
                QuicApplicationSendBatchPolicyMode.SingleEligible,
                QuicBufferCopyPolicyValue.LegacyCurrent));
        Assert.Throws<ArgumentException>(() =>
            CreateReviewedPackagePathAuthorization(
                CampaignId,
                "cell.send_admission_composition.correctness.a5",
                "e3635faeb1b2435fc40487bd1cc5060f822624607c2c2202b78d1c1894041b2a",
                QuicOversizedWriteAdmissionPolicyMode.SingleFragment,
                QuicApplicationSendBatchPolicyMode.LegacyCurrent,
                QuicBufferCopyPolicyValue.MemoryConservative));
        Assert.Throws<ArgumentException>(() =>
            CreateReviewedPackagePathAuthorization(
                CampaignId,
                "cell.send_admission_composition.correctness.a6",
                "ac2a8d830612027da8f85d90d6bf9624c344078ae0067dd9fca3b8e7c6ae6fd1",
                QuicOversizedWriteAdmissionPolicyMode.SingleFragment,
                QuicApplicationSendBatchPolicyMode.SingleEligible,
                QuicBufferCopyPolicyValue.LegacyCurrent));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AuthorizationCannotCombineWithCorrectnessOrEarlierPerformanceAuthorizations()
    {
        QuicAdaptiveRuntimeAdmissionPerformanceAuthorization admission =
            CreateAuthorization(
                "cell.send_admission_composition.correctness.a7",
                "281b32fd62406993adbffb6c6717e8a73d8ced29524b8f0a82b2d470cbda409f",
                QuicOversizedWriteAdmissionPolicyMode.SingleFragment,
                QuicApplicationSendBatchPolicyMode.SingleEligible,
                QuicBufferCopyPolicyValue.MemoryConservative);
        QuicAdaptiveRuntimeCorrectnessInteractionAuthorization compositionCorrectness =
            QuicAdaptiveRuntimeCorrectnessInteractionAuthorization
                .CreateForReviewedManifest(
                    Hash,
                    "cell.send_composition.correctness.000",
                    Hash,
                    Hash);
        QuicAdaptiveRuntimePerformanceInteractionAuthorization compositionPerformance =
            QuicAdaptiveRuntimePerformanceInteractionAuthorization
                .CreateForReviewedManifest(
                    "campaign.send_composition.performance.v1",
                    Hash,
                    "cell.d",
                    Hash,
                    Hash,
                    QuicApplicationSendBatchPolicyMode.SingleEligible,
                    QuicBufferCopyPolicyValue.MemoryConservative);
        QuicClientConnectionOptions admissionOnly = CreateOptions(
            admission,
            QuicOversizedWriteAdmissionPolicyMode.SingleFragment,
            QuicApplicationSendBatchPolicyMode.SingleEligible,
            QuicBufferCopyPolicyValue.MemoryConservative);
        using QuicConnectionRuntime admissionRuntime =
            QuicS13ApplicationSendDelayTestSupport
                .CreateFinishedClientRuntimeWithValidatedActivePath();
        Assert.Throws<InvalidOperationException>(() =>
        {
            admissionOnly.SendAdmissionCorrectnessAuthorization =
                REQ_QUIC_CRT_0244.CreateAuthorization(
                    "cell.send_admission_composition.correctness.a7",
                    "281b32fd62406993adbffb6c6717e8a73d8ced29524b8f0a82b2d470cbda409f",
                    QuicOversizedWriteAdmissionPolicyMode.SingleFragment,
                    QuicApplicationSendBatchPolicyMode.SingleEligible,
                    QuicBufferCopyPolicyValue.MemoryConservative);
            admissionRuntime.ConfigureAdaptiveRuntimePolicy(admissionOnly);
        });

        using QuicConnectionRuntime performanceRuntime =
            QuicS13ApplicationSendDelayTestSupport
                .CreateFinishedClientRuntimeWithValidatedActivePath();
        Assert.Throws<InvalidOperationException>(() =>
        {
            QuicClientConnectionOptions options = CreateOptions(
                admission,
                QuicOversizedWriteAdmissionPolicyMode.SingleFragment,
                QuicApplicationSendBatchPolicyMode.SingleEligible,
                QuicBufferCopyPolicyValue.MemoryConservative);
            options.SendCompositionPerformanceAuthorization = compositionPerformance;
            performanceRuntime.ConfigureAdaptiveRuntimePolicy(options);
        });

        using QuicConnectionRuntime correctnessRuntime =
            QuicS13ApplicationSendDelayTestSupport
                .CreateFinishedClientRuntimeWithValidatedActivePath();
        Assert.Throws<InvalidOperationException>(() =>
        {
            QuicClientConnectionOptions options = CreateOptions(
                admission,
                QuicOversizedWriteAdmissionPolicyMode.SingleFragment,
                QuicApplicationSendBatchPolicyMode.SingleEligible,
                QuicBufferCopyPolicyValue.MemoryConservative);
            options.SendCompositionCorrectnessAuthorization =
                compositionCorrectness;
            correctnessRuntime.ConfigureAdaptiveRuntimePolicy(options);
        });
    }

    internal static
        QuicAdaptiveRuntimeAdmissionPerformanceAuthorization
        CreateReviewedPackagePathAuthorization(
            string campaignId,
            string cellId,
            string cellHash,
            QuicOversizedWriteAdmissionPolicyMode oversizedMode,
            QuicApplicationSendBatchPolicyMode batchMode,
            QuicBufferCopyPolicyValue bufferValue)
    {
        return QuicAdaptiveRuntimeAdmissionPerformanceAuthorization
            .CreateForReviewedPackagePath(
                campaignId,
                PackagePathManifestHash,
                cellId,
                cellHash,
                oversizedMode,
                batchMode,
                bufferValue);
    }

    public static TheoryData<
        string,
        string,
        int,
        int,
        int> ReviewedPackagePathCells =>
        new()
        {
            {
                "cell.send_admission_composition.correctness.a0",
                "c9e070a0880872c9c9dce62f07e933a0de96c7590d343ce7f923f121278bba28",
                (int)QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent,
                (int)QuicApplicationSendBatchPolicyMode.LegacyCurrent,
                (int)QuicBufferCopyPolicyValue.LegacyCurrent
            },
            {
                "cell.send_admission_composition.correctness.a3",
                "1b7b63f5d53d39416d999b4bda0cc0c80e8817a535ceed9bc91e36aa12bcc2b1",
                (int)QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent,
                (int)QuicApplicationSendBatchPolicyMode.SingleEligible,
                (int)QuicBufferCopyPolicyValue.MemoryConservative
            },
            {
                "cell.send_admission_composition.correctness.a4",
                "99c02f1b21aaef38b13b996a8e25d31b1e78d1f6927433470dd743ddc3a37598",
                (int)QuicOversizedWriteAdmissionPolicyMode.SingleFragment,
                (int)QuicApplicationSendBatchPolicyMode.LegacyCurrent,
                (int)QuicBufferCopyPolicyValue.LegacyCurrent
            },
            {
                "cell.send_admission_composition.correctness.a7",
                "281b32fd62406993adbffb6c6717e8a73d8ced29524b8f0a82b2d470cbda409f",
                (int)QuicOversizedWriteAdmissionPolicyMode.SingleFragment,
                (int)QuicApplicationSendBatchPolicyMode.SingleEligible,
                (int)QuicBufferCopyPolicyValue.MemoryConservative
            },
        };

    internal static
        QuicAdaptiveRuntimeAdmissionPerformanceAuthorization
        CreateAuthorization(
            string cellId,
            string cellHash,
            QuicOversizedWriteAdmissionPolicyMode oversizedMode,
            QuicApplicationSendBatchPolicyMode batchMode,
            QuicBufferCopyPolicyValue bufferValue,
            string familyCatalogHash = FamilyCatalogHash,
            string oversizedProofHash = OversizedProofHash)
    {
        return QuicAdaptiveRuntimeAdmissionPerformanceAuthorization
            .CreateForReviewedManifest(
                CampaignId,
                Hash,
                cellId,
                cellHash,
                familyCatalogHash,
                RelationshipCatalogHash,
                ConstraintCatalogHash,
                BatchProofHash,
                BufferProofHash,
                oversizedProofHash,
                oversizedMode,
                batchMode,
                bufferValue);
    }

    private static QuicClientConnectionOptions CreateOptions(
        QuicAdaptiveRuntimeAdmissionPerformanceAuthorization authorization,
        QuicOversizedWriteAdmissionPolicyMode oversizedMode,
        QuicApplicationSendBatchPolicyMode batchMode,
        QuicBufferCopyPolicyValue bufferValue)
    {
        return new()
        {
            ForcedReceiveCreditPolicyMode =
                QuicReceiveCreditPolicyMode.LegacyCurrent,
            ForcedApplicationSendTurnPolicyMode =
                QuicApplicationSendTurnPolicyMode.LegacyCurrent,
            ForcedQueuedSendBurstPolicyMode =
                QuicQueuedSendBurstPolicyMode.LegacyCurrent,
            ForcedOversizedWriteAdmissionPolicyMode = oversizedMode,
            ForcedApplicationSendBatchPolicyMode = batchMode,
            ForcedBufferCopyPolicyValue = bufferValue,
            SendAdmissionPerformanceAuthorization = authorization,
        };
    }

    public static TheoryData<
        string,
        string,
        int,
        int,
        int> ExactCells =>
        new()
        {
            {
                "cell.send_admission_composition.correctness.a0",
                "c9e070a0880872c9c9dce62f07e933a0de96c7590d343ce7f923f121278bba28",
                (int)QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent,
                (int)QuicApplicationSendBatchPolicyMode.LegacyCurrent,
                (int)QuicBufferCopyPolicyValue.LegacyCurrent
            },
            {
                "cell.send_admission_composition.correctness.a1",
                "c41ed6674829898c3dc4e9af34cca11d159c07642c267a893b9d7097c3cc4f25",
                (int)QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent,
                (int)QuicApplicationSendBatchPolicyMode.LegacyCurrent,
                (int)QuicBufferCopyPolicyValue.MemoryConservative
            },
            {
                "cell.send_admission_composition.correctness.a2",
                "68c4112be72f82a9eb11b8a6dcf0594542337960c85bcc5f7386d91a172341db",
                (int)QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent,
                (int)QuicApplicationSendBatchPolicyMode.SingleEligible,
                (int)QuicBufferCopyPolicyValue.LegacyCurrent
            },
            {
                "cell.send_admission_composition.correctness.a3",
                "1b7b63f5d53d39416d999b4bda0cc0c80e8817a535ceed9bc91e36aa12bcc2b1",
                (int)QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent,
                (int)QuicApplicationSendBatchPolicyMode.SingleEligible,
                (int)QuicBufferCopyPolicyValue.MemoryConservative
            },
            {
                "cell.send_admission_composition.correctness.a4",
                "99c02f1b21aaef38b13b996a8e25d31b1e78d1f6927433470dd743ddc3a37598",
                (int)QuicOversizedWriteAdmissionPolicyMode.SingleFragment,
                (int)QuicApplicationSendBatchPolicyMode.LegacyCurrent,
                (int)QuicBufferCopyPolicyValue.LegacyCurrent
            },
            {
                "cell.send_admission_composition.correctness.a5",
                "e3635faeb1b2435fc40487bd1cc5060f822624607c2c2202b78d1c1894041b2a",
                (int)QuicOversizedWriteAdmissionPolicyMode.SingleFragment,
                (int)QuicApplicationSendBatchPolicyMode.LegacyCurrent,
                (int)QuicBufferCopyPolicyValue.MemoryConservative
            },
            {
                "cell.send_admission_composition.correctness.a6",
                "ac2a8d830612027da8f85d90d6bf9624c344078ae0067dd9fca3b8e7c6ae6fd1",
                (int)QuicOversizedWriteAdmissionPolicyMode.SingleFragment,
                (int)QuicApplicationSendBatchPolicyMode.SingleEligible,
                (int)QuicBufferCopyPolicyValue.LegacyCurrent
            },
            {
                "cell.send_admission_composition.correctness.a7",
                "281b32fd62406993adbffb6c6717e8a73d8ced29524b8f0a82b2d470cbda409f",
                (int)QuicOversizedWriteAdmissionPolicyMode.SingleFragment,
                (int)QuicApplicationSendBatchPolicyMode.SingleEligible,
                (int)QuicBufferCopyPolicyValue.MemoryConservative
            },
        };
}
