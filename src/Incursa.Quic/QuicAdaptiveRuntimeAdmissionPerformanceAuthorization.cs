// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

/// <summary>
/// Carries the exact, finite authorization for the reviewed A0-A7
/// send-admission offline measurement campaign. It is internal test
/// infrastructure and does not authorize adaptive selection, performance
/// acceptance, or active production behavior.
/// </summary>
internal readonly record struct
    QuicAdaptiveRuntimeAdmissionPerformanceAuthorization
{
    internal const string AuthorizationId =
        "send_admission_composition_performance_v1";
    internal const string FamilyIdValue = "send_admission_composition";
    internal const int FamilyCatalogVersion = 5;
    internal const int RelationshipCatalogVersion = 3;
    internal const int ConstraintCatalogVersion = 2;

    private const string CampaignIdValue =
        "campaign.send_admission_composition.performance.v1";
    private const string PackagePathCampaignIdValue =
        "campaign.send_admission_composition.performance.v1";
    private const string PackagePathPilotManifestContentSha256 =
        "257b31f3f93c6a34e14066b2c5d77bfc15ab5f2cfe54603b8d9244eb93fb7fd9";
    private const string PackagePathBalancedManifestContentSha256 =
        "a172b8834f025c50a414dd7748b48cafcdae5e1b32e304d557780eb2cbc3d767";
    private const string FamilyCatalogSha256 =
        "cfee17afcc28da35e657b2d1331bde68c752b5a3487f0af69087c12df6530b93";
    private const string RelationshipCatalogSha256 =
        "fd6dfa5b02b3423de16ab72c08f99b93c85d186218524c4025b8a47e1fa7b4fc";
    private const string ConstraintCatalogSha256 =
        "90c85812b46e2aaa639b05bd1d6583d03c9c6b9c0f0730fd67f9567d1210cc49";
    private const string BatchProofReviewSha256 =
        "f40368b49bfdc8607d22449e7e80e6c1dda03a611da2362909907710a6d24b37";
    private const string BufferProofReviewSha256 =
        "da60ba782cd646f6c285ff1ef6dda877bc30c984054644f2bc501025e6c02408";
    private const string OversizedProofReviewSha256 =
        "2b444f8048d30a727a65d93b64bb25a138f9aca5e1b104c8b9900bf7a79df980";
    private const int CurrentContractVersion = 1;
    private const int Sha256HexLength = 64;

    private QuicAdaptiveRuntimeAdmissionPerformanceAuthorization(
        string campaignId,
        string manifestContentSha256,
        string cellId,
        string cellContentSha256,
        QuicOversizedWriteAdmissionPolicyMode oversizedMode,
        QuicApplicationSendBatchPolicyMode batchMode,
        QuicBufferCopyPolicyValue bufferValue)
    {
        CampaignId = campaignId;
        ManifestContentSha256 = manifestContentSha256;
        CellId = cellId;
        CellContentSha256 = cellContentSha256;
        OversizedMode = oversizedMode;
        BatchMode = batchMode;
        BufferValue = bufferValue;
        FamilyId = FamilyIdValue;
        ContractVersion = CurrentContractVersion;
        OfflineMeasurementOnly = true;
        ActiveBehaviorAuthorization = false;
        PerformanceAcceptanceAuthorization = false;
    }

    internal string CampaignId { get; }

    internal string ManifestContentSha256 { get; }

    internal string CellId { get; }

    internal string CellContentSha256 { get; }

    internal QuicOversizedWriteAdmissionPolicyMode OversizedMode { get; }

    internal QuicApplicationSendBatchPolicyMode BatchMode { get; }

    internal QuicBufferCopyPolicyValue BufferValue { get; }

    internal string FamilyId { get; }

    internal int ContractVersion { get; }

    internal bool OfflineMeasurementOnly { get; }

    internal bool ActiveBehaviorAuthorization { get; }

    internal bool PerformanceAcceptanceAuthorization { get; }

    internal static
        QuicAdaptiveRuntimeAdmissionPerformanceAuthorization
        CreateForReviewedPackagePath(
            string campaignId,
            string manifestContentSha256,
            string cellId,
            string cellContentSha256,
            QuicOversizedWriteAdmissionPolicyMode oversizedMode,
            QuicApplicationSendBatchPolicyMode batchMode,
            QuicBufferCopyPolicyValue bufferValue)
    {
        ValidateIdentifier(campaignId, nameof(campaignId));
        if (!string.Equals(
            campaignId,
            PackagePathCampaignIdValue,
            StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "Admission performance package-path authorization requires the reviewed campaign identifier.",
                nameof(campaignId));
        }

        ValidateHash(manifestContentSha256, nameof(manifestContentSha256));
        if (!string.Equals(
                manifestContentSha256,
                PackagePathPilotManifestContentSha256,
                StringComparison.Ordinal)
            && !string.Equals(
                manifestContentSha256,
                PackagePathBalancedManifestContentSha256,
                StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "Admission performance package-path authorization requires the reviewed manifest content hash.",
                nameof(manifestContentSha256));
        }

        ValidateIdentifier(cellId, nameof(cellId));
        if (!IsReviewedPackagePathCell(
            manifestContentSha256,
            cellId,
            cellContentSha256,
            oversizedMode,
            batchMode,
            bufferValue))
        {
            throw new ArgumentException(
                "Admission performance package-path authorization requires a cell reviewed for the selected manifest.",
                nameof(cellId));
        }

        return CreateForReviewedManifest(
            campaignId,
            manifestContentSha256,
            cellId,
            cellContentSha256,
            FamilyCatalogSha256,
            RelationshipCatalogSha256,
            ConstraintCatalogSha256,
            BatchProofReviewSha256,
            BufferProofReviewSha256,
            OversizedProofReviewSha256,
            oversizedMode,
            batchMode,
            bufferValue);
    }

    internal static
        QuicAdaptiveRuntimeAdmissionPerformanceAuthorization
        CreateForReviewedManifest(
            string campaignId,
            string manifestContentSha256,
            string cellId,
            string cellContentSha256,
            string familyCatalogSha256,
            string relationshipCatalogSha256,
            string constraintCatalogSha256,
            string batchProofReviewSha256,
            string bufferProofReviewSha256,
            string oversizedProofReviewSha256,
            QuicOversizedWriteAdmissionPolicyMode oversizedMode,
            QuicApplicationSendBatchPolicyMode batchMode,
            QuicBufferCopyPolicyValue bufferValue)
    {
        ValidateIdentifier(campaignId, nameof(campaignId));
        if (!string.Equals(
            campaignId,
            CampaignIdValue,
            StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "Admission performance authorization requires the current exact campaign identifier.",
                nameof(campaignId));
        }
        ValidateHash(manifestContentSha256, nameof(manifestContentSha256));
        ValidateIdentifier(cellId, nameof(cellId));
        ValidateExactHash(
            familyCatalogSha256,
            FamilyCatalogSha256,
            nameof(familyCatalogSha256));
        ValidateExactHash(
            relationshipCatalogSha256,
            RelationshipCatalogSha256,
            nameof(relationshipCatalogSha256));
        ValidateExactHash(
            constraintCatalogSha256,
            ConstraintCatalogSha256,
            nameof(constraintCatalogSha256));
        ValidateExactHash(
            batchProofReviewSha256,
            BatchProofReviewSha256,
            nameof(batchProofReviewSha256));
        ValidateExactHash(
            bufferProofReviewSha256,
            BufferProofReviewSha256,
            nameof(bufferProofReviewSha256));
        ValidateExactHash(
            oversizedProofReviewSha256,
            OversizedProofReviewSha256,
            nameof(oversizedProofReviewSha256));
        ValidateCell(
            cellId,
            cellContentSha256,
            oversizedMode,
            batchMode,
            bufferValue);

        return new(
            campaignId,
            manifestContentSha256,
            cellId,
            cellContentSha256,
            oversizedMode,
            batchMode,
            bufferValue);
    }

    internal bool Authorizes(
        QuicOversizedWriteAdmissionPolicyMode? oversizedMode,
        QuicApplicationSendBatchPolicyMode? batchMode,
        QuicBufferCopyPolicyValue? bufferValue,
        QuicReceiveCreditPolicyMode? receiveCreditMode,
        QuicApplicationSendTurnPolicyMode? sendTurnMode,
        QuicQueuedSendBurstPolicyMode? queuedBurstMode)
    {
        return OfflineMeasurementOnly
            && !ActiveBehaviorAuthorization
            && !PerformanceAcceptanceAuthorization
            && ContractVersion == CurrentContractVersion
            && string.Equals(FamilyId, FamilyIdValue, StringComparison.Ordinal)
            && string.Equals(CampaignId, CampaignIdValue, StringComparison.Ordinal)
            && oversizedMode == OversizedMode
            && batchMode == BatchMode
            && bufferValue == BufferValue
            && (receiveCreditMode is null
                or QuicReceiveCreditPolicyMode.LegacyCurrent)
            && (sendTurnMode is null
                or QuicApplicationSendTurnPolicyMode.LegacyCurrent)
            && (queuedBurstMode is null
                or QuicQueuedSendBurstPolicyMode.LegacyCurrent)
            && IsHash(ManifestContentSha256)
            && IsIdentifier(CampaignId)
            && IsExactCell(
                CellId,
                CellContentSha256,
                OversizedMode,
                BatchMode,
                BufferValue);
    }

    private static void ValidateCell(
        string cellId,
        string cellContentSha256,
        QuicOversizedWriteAdmissionPolicyMode oversizedMode,
        QuicApplicationSendBatchPolicyMode batchMode,
        QuicBufferCopyPolicyValue bufferValue)
    {
        ValidateHash(cellContentSha256, nameof(cellContentSha256));
        if (!IsExactCell(
            cellId,
            cellContentSha256,
            oversizedMode,
            batchMode,
            bufferValue))
        {
            throw new ArgumentException(
                "Admission performance authorization requires an exact A0-A7 cell identity, hash, and value tuple.",
                nameof(cellId));
        }
    }

    private static bool IsReviewedPackagePathCell(
        string manifestContentSha256,
        string cellId,
        string cellContentSha256,
        QuicOversizedWriteAdmissionPolicyMode oversizedMode,
        QuicApplicationSendBatchPolicyMode batchMode,
        QuicBufferCopyPolicyValue bufferValue)
    {
        if (!IsExactCell(
            cellId,
            cellContentSha256,
            oversizedMode,
            batchMode,
            bufferValue))
        {
            return false;
        }

        return string.Equals(
                manifestContentSha256,
                PackagePathBalancedManifestContentSha256,
                StringComparison.Ordinal)
            || string.Equals(
                manifestContentSha256,
                PackagePathPilotManifestContentSha256,
                StringComparison.Ordinal)
            && cellId is
                "cell.send_admission_composition.correctness.a0"
                or "cell.send_admission_composition.correctness.a3"
                or "cell.send_admission_composition.correctness.a4"
                or "cell.send_admission_composition.correctness.a7";
    }

    private static bool IsExactCell(
        string cellId,
        string cellContentSha256,
        QuicOversizedWriteAdmissionPolicyMode oversizedMode,
        QuicApplicationSendBatchPolicyMode batchMode,
        QuicBufferCopyPolicyValue bufferValue)
    {
        return (cellId, cellContentSha256, oversizedMode, batchMode, bufferValue)
            switch
            {
                (
                    "cell.send_admission_composition.correctness.a0",
                    "c9e070a0880872c9c9dce62f07e933a0de96c7590d343ce7f923f121278bba28",
                    QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent,
                    QuicApplicationSendBatchPolicyMode.LegacyCurrent,
                    QuicBufferCopyPolicyValue.LegacyCurrent) => true,
                (
                    "cell.send_admission_composition.correctness.a1",
                    "c41ed6674829898c3dc4e9af34cca11d159c07642c267a893b9d7097c3cc4f25",
                    QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent,
                    QuicApplicationSendBatchPolicyMode.LegacyCurrent,
                    QuicBufferCopyPolicyValue.MemoryConservative) => true,
                (
                    "cell.send_admission_composition.correctness.a2",
                    "68c4112be72f82a9eb11b8a6dcf0594542337960c85bcc5f7386d91a172341db",
                    QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent,
                    QuicApplicationSendBatchPolicyMode.SingleEligible,
                    QuicBufferCopyPolicyValue.LegacyCurrent) => true,
                (
                    "cell.send_admission_composition.correctness.a3",
                    "1b7b63f5d53d39416d999b4bda0cc0c80e8817a535ceed9bc91e36aa12bcc2b1",
                    QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent,
                    QuicApplicationSendBatchPolicyMode.SingleEligible,
                    QuicBufferCopyPolicyValue.MemoryConservative) => true,
                (
                    "cell.send_admission_composition.correctness.a4",
                    "99c02f1b21aaef38b13b996a8e25d31b1e78d1f6927433470dd743ddc3a37598",
                    QuicOversizedWriteAdmissionPolicyMode.SingleFragment,
                    QuicApplicationSendBatchPolicyMode.LegacyCurrent,
                    QuicBufferCopyPolicyValue.LegacyCurrent) => true,
                (
                    "cell.send_admission_composition.correctness.a5",
                    "e3635faeb1b2435fc40487bd1cc5060f822624607c2c2202b78d1c1894041b2a",
                    QuicOversizedWriteAdmissionPolicyMode.SingleFragment,
                    QuicApplicationSendBatchPolicyMode.LegacyCurrent,
                    QuicBufferCopyPolicyValue.MemoryConservative) => true,
                (
                    "cell.send_admission_composition.correctness.a6",
                    "ac2a8d830612027da8f85d90d6bf9624c344078ae0067dd9fca3b8e7c6ae6fd1",
                    QuicOversizedWriteAdmissionPolicyMode.SingleFragment,
                    QuicApplicationSendBatchPolicyMode.SingleEligible,
                    QuicBufferCopyPolicyValue.LegacyCurrent) => true,
                (
                    "cell.send_admission_composition.correctness.a7",
                    "281b32fd62406993adbffb6c6717e8a73d8ced29524b8f0a82b2d470cbda409f",
                    QuicOversizedWriteAdmissionPolicyMode.SingleFragment,
                    QuicApplicationSendBatchPolicyMode.SingleEligible,
                    QuicBufferCopyPolicyValue.MemoryConservative) => true,
                _ => false,
            };
    }

    private static void ValidateExactHash(
        string value,
        string expected,
        string parameterName)
    {
        ValidateHash(value, parameterName);
        if (!string.Equals(value, expected, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "Admission performance authorization requires the current exact reviewed hash.",
                parameterName);
        }
    }

    private static void ValidateHash(string value, string parameterName)
    {
        if (!IsHash(value))
        {
            throw new ArgumentException(
                "Admission performance authorization requires a lowercase SHA-256 value.",
                parameterName);
        }
    }

    private static bool IsHash(string? value)
    {
        return value is { Length: Sha256HexLength }
            && value.All(static character =>
                character is >= '0' and <= '9' or >= 'a' and <= 'f');
    }

    private static void ValidateIdentifier(string value, string parameterName)
    {
        if (!IsIdentifier(value))
        {
            throw new ArgumentException(
                "Admission performance authorization requires a stable identifier.",
                parameterName);
        }
    }

    private static bool IsIdentifier(string? value)
    {
        return value is { Length: > 0 }
            && value.All(static character =>
                char.IsAsciiLetterOrDigit(character)
                || character is '.' or '_' or '-');
    }
}
