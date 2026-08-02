// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

/// <summary>
/// Carries the exact, finite authorization for the reviewed queued-send
/// burst performance characterization slice. It is internal test
/// infrastructure and does not authorize adaptive selection, performance
/// acceptance, or active production behavior.
/// </summary>
internal readonly record struct
    QuicAdaptiveRuntimeQueuedSendPerformanceAuthorization
{
    internal const string AuthorizationId =
        "queued_send_burst_budget_performance_v1";
    internal const string FamilyIdValue = "queued_send_burst_budget";
    internal const int FamilyCatalogVersion = 5;
    internal const int RelationshipCatalogVersion = 3;
    internal const int ConstraintCatalogVersion = 2;

    private const string CampaignIdValue =
        "campaign.queued_send_burst_budget.performance.v1";
    private const string PackagePathManifestContentSha256 =
        "9233dfdf43d14236a15a55907832582b1d82a692da3b9f400fdebd76f23abd5d";
    private const string PackagePathQueuedSendQ0CellContentSha256 =
        "b2911df4e1782b6f1636d37bf50f0dd5e59dbbb9164ec3154b667034c43fb3e9";
    private const string PackagePathQueuedSendQ1CellContentSha256 =
        "2f4a7a36c0d52aeae801a979e91335347693db5ec8665715497d068fb02cdc2a";
    private const string FamilyCatalogSha256 =
        "cfee17afcc28da35e657b2d1331bde68c752b5a3487f0af69087c12df6530b93";
    private const string RelationshipCatalogSha256 =
        "fd6dfa5b02b3423de16ab72c08f99b93c85d186218524c4025b8a47e1fa7b4fc";
    private const string ConstraintCatalogSha256 =
        "90c85812b46e2aaa639b05bd1d6583d03c9c6b9c0f0730fd67f9567d1210cc49";
    private const string QueuedProofReviewSha256 =
        "00c8749a50fec9cc9392c65dcceb0575f303d2c68d771f01f2462f774706ea65";
    private const int CurrentContractVersion = 1;
    private const int Sha256HexLength = 64;

    private QuicAdaptiveRuntimeQueuedSendPerformanceAuthorization(
        string campaignId,
        string manifestContentSha256,
        string cellId,
        string cellContentSha256,
        QuicQueuedSendBurstPolicyMode queuedBurstMode)
    {
        CampaignId = campaignId;
        ManifestContentSha256 = manifestContentSha256;
        CellId = cellId;
        CellContentSha256 = cellContentSha256;
        QueuedBurstMode = queuedBurstMode;
        FamilyId = FamilyIdValue;
        ContractVersion = CurrentContractVersion;
        OfflineMeasurementOnly = true;
        ActiveBehaviorAuthorization = false;
        PerformanceAcceptanceAuthorization = false;
        AdaptiveRuleDerivationAuthorization = false;
        ProductionActivationAuthorization = false;
    }

    internal string CampaignId { get; }

    internal string ManifestContentSha256 { get; }

    internal string CellId { get; }

    internal string CellContentSha256 { get; }

    internal QuicQueuedSendBurstPolicyMode QueuedBurstMode { get; }

    internal string FamilyId { get; }

    internal int ContractVersion { get; }

    internal bool OfflineMeasurementOnly { get; }

    internal bool ActiveBehaviorAuthorization { get; }

    internal bool PerformanceAcceptanceAuthorization { get; }

    internal bool AdaptiveRuleDerivationAuthorization { get; }

    internal bool ProductionActivationAuthorization { get; }

    internal static
        QuicAdaptiveRuntimeQueuedSendPerformanceAuthorization
        CreateForReviewedPackagePath(
            string campaignId,
            string manifestContentSha256,
            string cellId,
            string cellContentSha256,
            QuicQueuedSendBurstPolicyMode queuedBurstMode)
    {
        ValidateIdentifier(campaignId, nameof(campaignId));
        if (!string.Equals(
            campaignId,
            CampaignIdValue,
            StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "Queued-send performance package-path authorization requires the reviewed campaign identifier.",
                nameof(campaignId));
        }

        ValidateHash(manifestContentSha256, nameof(manifestContentSha256));
        ValidateExactHash(
            manifestContentSha256,
            PackagePathManifestContentSha256,
            nameof(manifestContentSha256));
        ValidateIdentifier(cellId, nameof(cellId));
        ValidateCell(
            cellId,
            cellContentSha256,
            queuedBurstMode);

        return CreateForReviewedManifest(
            campaignId,
            manifestContentSha256,
            cellId,
            cellContentSha256,
            FamilyCatalogSha256,
            RelationshipCatalogSha256,
            ConstraintCatalogSha256,
            QueuedProofReviewSha256,
            queuedBurstMode);
    }

    internal static
        QuicAdaptiveRuntimeQueuedSendPerformanceAuthorization
        CreateForReviewedManifest(
            string campaignId,
            string manifestContentSha256,
            string cellId,
            string cellContentSha256,
            string familyCatalogSha256,
            string relationshipCatalogSha256,
            string constraintCatalogSha256,
            string queuedProofReviewSha256,
            QuicQueuedSendBurstPolicyMode queuedBurstMode)
    {
        ValidateIdentifier(campaignId, nameof(campaignId));
        if (!string.Equals(
            campaignId,
            CampaignIdValue,
            StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "Queued-send performance authorization requires the current exact campaign identifier.",
                nameof(campaignId));
        }

        ValidateHash(manifestContentSha256, nameof(manifestContentSha256));
        ValidateExactHash(
            manifestContentSha256,
            PackagePathManifestContentSha256,
            nameof(manifestContentSha256));
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
            queuedProofReviewSha256,
            QueuedProofReviewSha256,
            nameof(queuedProofReviewSha256));
        ValidateCell(
            cellId,
            cellContentSha256,
            queuedBurstMode);

        return new(
            campaignId,
            manifestContentSha256,
            cellId,
            cellContentSha256,
            queuedBurstMode);
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
            && !AdaptiveRuleDerivationAuthorization
            && !ProductionActivationAuthorization
            && ContractVersion == CurrentContractVersion
            && string.Equals(FamilyId, FamilyIdValue, StringComparison.Ordinal)
            && string.Equals(CampaignId, CampaignIdValue, StringComparison.Ordinal)
            && string.Equals(
                ManifestContentSha256,
                PackagePathManifestContentSha256,
                StringComparison.Ordinal)
            && oversizedMode is null
                or QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent
            && batchMode is null
                or QuicApplicationSendBatchPolicyMode.LegacyCurrent
            && bufferValue is null
                or QuicBufferCopyPolicyValue.LegacyCurrent
            && receiveCreditMode is null
                or QuicReceiveCreditPolicyMode.LegacyCurrent
            && sendTurnMode is null
                or QuicApplicationSendTurnPolicyMode.LegacyCurrent
            && queuedBurstMode == QueuedBurstMode
            && IsHash(ManifestContentSha256)
            && IsIdentifier(CampaignId)
            && IsExactCell(
                CellId,
                CellContentSha256,
                QueuedBurstMode);
    }

    private static void ValidateCell(
        string cellId,
        string cellContentSha256,
        QuicQueuedSendBurstPolicyMode queuedBurstMode)
    {
        ValidateHash(cellContentSha256, nameof(cellContentSha256));
        if (!IsExactCell(cellId, cellContentSha256, queuedBurstMode))
        {
            throw new ArgumentException(
                "Queued-send performance authorization requires an exact queued cell identity, hash, and value tuple.",
                nameof(cellId));
        }
    }

    private static bool IsExactCell(
        string cellId,
        string cellContentSha256,
        QuicQueuedSendBurstPolicyMode queuedBurstMode)
    {
        return (cellId, cellContentSha256, queuedBurstMode) switch
        {
            (
                "cell.queued_send_burst_budget.performance.q0",
                PackagePathQueuedSendQ0CellContentSha256,
                QuicQueuedSendBurstPolicyMode.LegacyCurrent) => true,
            (
                "cell.queued_send_burst_budget.performance.q1",
                PackagePathQueuedSendQ1CellContentSha256,
                QuicQueuedSendBurstPolicyMode.SingleDatagram) => true,
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
                "Queued-send performance authorization requires the current exact reviewed hash.",
                parameterName);
        }
    }

    private static void ValidateHash(string value, string parameterName)
    {
        if (!IsHash(value))
        {
            throw new ArgumentException(
                "Queued-send performance authorization requires a lowercase SHA-256 value.",
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
                "Queued-send performance authorization requires a stable identifier.",
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
