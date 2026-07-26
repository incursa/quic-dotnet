// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

/// <summary>
/// Carries the fixed, manifest-bound authorization for the reviewed
/// send-composition correctness cell. This is internal test infrastructure;
/// it is not reachable from public production configuration.
/// </summary>
internal readonly record struct QuicAdaptiveRuntimeCorrectnessInteractionAuthorization
{
    private const string SendCompositionFamily = "send_composition";
    private const int CurrentContractVersion = 2;
    private const int Sha256HexLength = 64;

    private QuicAdaptiveRuntimeCorrectnessInteractionAuthorization(
        string manifestContentSha256,
        string cellId,
        string batchProofReviewSha256,
        string bufferProofReviewSha256)
    {
        ManifestContentSha256 = manifestContentSha256;
        CellId = cellId;
        BatchProofReviewSha256 = batchProofReviewSha256;
        BufferProofReviewSha256 = bufferProofReviewSha256;
        FamilyId = SendCompositionFamily;
        ContractVersion = CurrentContractVersion;
        CorrectnessOnly = true;
        ActiveBehaviorAuthorization = false;
        PerformanceAcceptanceAuthorization = false;
    }

    internal string ManifestContentSha256 { get; }

    internal string CellId { get; }

    internal string BatchProofReviewSha256 { get; }

    internal string BufferProofReviewSha256 { get; }

    internal string FamilyId { get; }

    internal int ContractVersion { get; }

    internal bool CorrectnessOnly { get; }

    internal bool ActiveBehaviorAuthorization { get; }

    internal bool PerformanceAcceptanceAuthorization { get; }

    internal static QuicAdaptiveRuntimeCorrectnessInteractionAuthorization
        CreateForReviewedManifest(
            string manifestContentSha256,
            string cellId,
            string batchProofReviewSha256,
            string bufferProofReviewSha256)
    {
        ValidateHash(manifestContentSha256);
        ValidateIdentifier(cellId);
        ValidateHash(batchProofReviewSha256);
        ValidateHash(bufferProofReviewSha256);
        return new(
            manifestContentSha256,
            cellId,
            batchProofReviewSha256,
            bufferProofReviewSha256);
    }

    internal bool Authorizes(
        QuicApplicationSendBatchPolicyMode? batchMode,
        QuicBufferCopyPolicyValue? bufferValue)
    {
        return CorrectnessOnly
            && !ActiveBehaviorAuthorization
            && !PerformanceAcceptanceAuthorization
            && ContractVersion == CurrentContractVersion
            && string.Equals(FamilyId, SendCompositionFamily, StringComparison.Ordinal)
            && batchMode is QuicApplicationSendBatchPolicyMode.SingleEligible
            && bufferValue is QuicBufferCopyPolicyValue.MemoryConservative
            && IsHash(ManifestContentSha256)
            && IsHash(BatchProofReviewSha256)
            && IsHash(BufferProofReviewSha256)
            && !string.IsNullOrWhiteSpace(CellId);
    }

    private static void ValidateHash(string value)
    {
        if (!IsHash(value))
        {
            throw new ArgumentException(
                "Correctness interaction authorization requires a lowercase SHA-256 value.",
                nameof(value));
        }
    }

    private static bool IsHash(string? value)
    {
        return value is { Length: Sha256HexLength }
            && value.All(static character =>
                character is >= '0' and <= '9' or >= 'a' and <= 'f');
    }

    private static void ValidateIdentifier(string value)
    {
        if (string.IsNullOrWhiteSpace(value)
            || value.Any(static character =>
                !(char.IsAsciiLetterOrDigit(character)
                    || character is '.' or '_' or '-')))
        {
            throw new ArgumentException(
                "Correctness interaction authorization requires a stable cell ID.",
                nameof(value));
        }
    }
}
