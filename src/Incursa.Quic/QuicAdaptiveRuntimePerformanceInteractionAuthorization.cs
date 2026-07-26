// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

/// <summary>
/// Carries one manifest-bound, offline-only send-composition measurement cell.
/// This fixed token is internal tooling infrastructure and is unavailable
/// through public production configuration.
/// </summary>
internal readonly record struct QuicAdaptiveRuntimePerformanceInteractionAuthorization
{
    private const string SendCompositionFamily = "send_composition";
    private const int CurrentContractVersion = 1;
    private const int Sha256HexLength = 64;

    private QuicAdaptiveRuntimePerformanceInteractionAuthorization(
        string campaignId,
        string manifestContentSha256,
        string cellId,
        string batchProofReviewSha256,
        string bufferProofReviewSha256,
        QuicApplicationSendBatchPolicyMode batchMode,
        QuicBufferCopyPolicyValue bufferValue)
    {
        CampaignId = campaignId;
        ManifestContentSha256 = manifestContentSha256;
        CellId = cellId;
        BatchProofReviewSha256 = batchProofReviewSha256;
        BufferProofReviewSha256 = bufferProofReviewSha256;
        BatchMode = batchMode;
        BufferValue = bufferValue;
        FamilyId = SendCompositionFamily;
        ContractVersion = CurrentContractVersion;
        OfflineMeasurementOnly = true;
        ActiveBehaviorAuthorization = false;
        PerformanceAcceptanceAuthorization = false;
    }

    internal string CampaignId { get; }
    internal string ManifestContentSha256 { get; }
    internal string CellId { get; }
    internal string BatchProofReviewSha256 { get; }
    internal string BufferProofReviewSha256 { get; }
    internal QuicApplicationSendBatchPolicyMode BatchMode { get; }
    internal QuicBufferCopyPolicyValue BufferValue { get; }
    internal string FamilyId { get; }
    internal int ContractVersion { get; }
    internal bool OfflineMeasurementOnly { get; }
    internal bool ActiveBehaviorAuthorization { get; }
    internal bool PerformanceAcceptanceAuthorization { get; }

    internal static QuicAdaptiveRuntimePerformanceInteractionAuthorization
        CreateForReviewedManifest(
            string campaignId,
            string manifestContentSha256,
            string cellId,
            string batchProofReviewSha256,
            string bufferProofReviewSha256,
            QuicApplicationSendBatchPolicyMode batchMode,
            QuicBufferCopyPolicyValue bufferValue)
    {
        ValidateIdentifier(campaignId, nameof(campaignId));
        ValidateHash(manifestContentSha256, nameof(manifestContentSha256));
        ValidateIdentifier(cellId, nameof(cellId));
        ValidateHash(batchProofReviewSha256, nameof(batchProofReviewSha256));
        ValidateHash(bufferProofReviewSha256, nameof(bufferProofReviewSha256));
        QuicApplicationSendBatchPolicy.ValidateMode(batchMode);
        QuicBufferCopyPolicy.ValidateValue(bufferValue);
        return new(
            campaignId,
            manifestContentSha256,
            cellId,
            batchProofReviewSha256,
            bufferProofReviewSha256,
            batchMode,
            bufferValue);
    }

    internal bool Authorizes(
        QuicApplicationSendBatchPolicyMode? batchMode,
        QuicBufferCopyPolicyValue? bufferValue)
    {
        return OfflineMeasurementOnly
            && !ActiveBehaviorAuthorization
            && !PerformanceAcceptanceAuthorization
            && ContractVersion == CurrentContractVersion
            && string.Equals(FamilyId, SendCompositionFamily, StringComparison.Ordinal)
            && batchMode == BatchMode
            && bufferValue == BufferValue
            && IsHash(ManifestContentSha256)
            && IsHash(BatchProofReviewSha256)
            && IsHash(BufferProofReviewSha256)
            && !string.IsNullOrWhiteSpace(CampaignId)
            && !string.IsNullOrWhiteSpace(CellId);
    }

    private static void ValidateHash(string value, string parameterName)
    {
        if (!IsHash(value))
        {
            throw new ArgumentException(
                "Offline measurement authorization requires a lowercase SHA-256 value.",
                parameterName);
        }
    }

    private static bool IsHash(string? value)
        => value is { Length: Sha256HexLength }
            && value.All(static character =>
                character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static void ValidateIdentifier(string value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value)
            || value.Any(static character =>
                !(char.IsAsciiLetterOrDigit(character)
                    || character is '.' or '_' or '-')))
        {
            throw new ArgumentException(
                "Offline measurement authorization requires a stable identifier.",
                parameterName);
        }
    }
}
