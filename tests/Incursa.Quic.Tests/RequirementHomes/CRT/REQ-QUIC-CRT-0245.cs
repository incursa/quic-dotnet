// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0245")]
public sealed class REQ_QUIC_CRT_0245
{
    private const string CapturePathVariable =
        "INCURSA_ADAPTIVE_RUNTIME_ADMISSION_CAPTURE_PATH";
    private const string ManifestHashVariable =
        "INCURSA_ADAPTIVE_RUNTIME_ADMISSION_MANIFEST_HASH";
    private const string AuthorizationHashVariable =
        "INCURSA_ADAPTIVE_RUNTIME_ADMISSION_AUTHORIZATION_HASH";
    private const string SourceCommitVariable =
        "INCURSA_ADAPTIVE_RUNTIME_ADMISSION_SOURCE_COMMIT";
    private const string BinaryHashVariable =
        "INCURSA_ADAPTIVE_RUNTIME_ADMISSION_BINARY_SHA256";
    private const string HarnessHashVariable =
        "INCURSA_ADAPTIVE_RUNTIME_ADMISSION_HARNESS_SHA256";

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ExactEightCellsExerciseEveryConfiguredNonlegacyAxis()
    {
        List<object> cellCaptures = [];
        foreach (Cell cell in Cells)
        {
            QuicAdaptiveRuntimeAdmissionCorrectnessAuthorization
                authorization = REQ_QUIC_CRT_0244.CreateAuthorization(
                    cell.CellId,
                    cell.CellHash,
                    cell.OversizedMode,
                    cell.BatchMode,
                    cell.BufferValue);
            object oversized =
                await RequirementHomes.CRT.REQ_QUIC_CRT_0238
                    .CaptureAdmissionOversizedOperationAsync(
                        cell.OversizedMode,
                        cell.BatchMode,
                        cell.BufferValue,
                        authorization);
            object batch = REQ_QUIC_CRT_0219.CaptureBatchOperation(
                $"{cell.ConnectionKey}.batch",
                "cell_opportunity",
                planSequence: 10,
                QuicApplicationSendBatchObservationMode.ObserveOnly,
                hasForcedValue: true,
                cell.BatchMode,
                legalWriteBytes: [100, 101, 102, 103],
                result: "applied",
                fallbackReason: null);
            (object Operation, object Release) buffer =
                REQ_QUIC_CRT_0219.CaptureBufferRuntimeOperation(
                    $"{cell.ConnectionKey}.buffer",
                    "cell_opportunity",
                    QuicBufferCopyObservationMode.ObserveOnly,
                    cell.BufferValue,
                    legalSourceSegments: 4,
                    legalBytes: 400,
                    appliedBytes:
                        cell.BufferValue
                            is QuicBufferCopyPolicyValue.MemoryConservative
                                ? 200
                                : 400,
                    admissionAuthorization: authorization,
                    admissionOversizedMode: cell.OversizedMode,
                    admissionBatchMode: cell.BatchMode);

            Assert.Equal(
                Value(cell.OversizedMode),
                ReadString(oversized, "applied_value"));
            Assert.Equal(
                Value(cell.BatchMode),
                ReadString(batch, "applied_value"));
            Assert.Equal(
                Value(cell.BufferValue),
                ReadString(buffer.Operation, "applied_value"));
            Assert.Equal(
                1,
                ReadInt(buffer.Release, "release_count"));

            cellCaptures.Add(new
            {
                cell_id = cell.CellId,
                cell_content_sha256 = cell.CellHash,
                run_id = cell.RunId,
                connection_state_id = cell.ConnectionKey,
                configured_values = new
                {
                    oversized_write_admission_quantum =
                        Value(cell.OversizedMode),
                    application_send_batch_formation =
                        Value(cell.BatchMode),
                    buffer_copy_coalescing =
                        Value(cell.BufferValue),
                    application_send_turn_planning = "legacy_current",
                    queued_send_burst_budget = "legacy_current",
                },
                operations = new object[]
                {
                    new
                    {
                        axis_id = "oversized_write_admission_quantum",
                        operation_identity = $"{cell.RunId}|{cell.ConnectionKey}.oversized|1",
                        operation_local_noncoactivation = true,
                        evidence = oversized,
                    },
                    new
                    {
                        axis_id = "application_send_batch_formation",
                        operation_identity = $"{cell.RunId}|{cell.ConnectionKey}.batch|2",
                        operation_local_noncoactivation = false,
                        evidence = batch,
                    },
                    new
                    {
                        axis_id = "buffer_copy_coalescing",
                        operation_identity = $"{cell.RunId}|{cell.ConnectionKey}.buffer|3",
                        operation_local_noncoactivation = false,
                        evidence = buffer.Operation,
                    },
                },
                releases = new object[]
                {
                    new
                    {
                        axis_id = "buffer_copy_coalescing",
                        operation_identity = $"{cell.RunId}|{cell.ConnectionKey}.buffer|3",
                        evidence = buffer.Release,
                    },
                },
                active_behavior_authorization = false,
                performance_acceptance_authorization = false,
            });
        }

        Assert.Equal(8, cellCaptures.Count);
        string? capturePath = Environment.GetEnvironmentVariable(
            CapturePathVariable);
        if (!string.IsNullOrWhiteSpace(capturePath))
        {
            Directory.CreateDirectory(Path.GetDirectoryName(capturePath)!);
            File.WriteAllText(
                capturePath,
                JsonSerializer.Serialize(new
                {
                    schema_version =
                        "adaptive-runtime-send-admission-runtime-capture-v1",
                    document_id =
                        "runtime_capture.send_admission_composition.correctness_v1",
                    document_version = 1,
                    content_sha256 = new string('0', 64),
                    authorization_id =
                        "send_admission_composition_correctness_v1",
                    source_commit = GetBinding(
                        SourceCommitVariable,
                        new string('0', 40)),
                    binary_sha256 = GetBinding(
                        BinaryHashVariable,
                        new string('0', 64)),
                    harness_binary_sha256 = GetBinding(
                        HarnessHashVariable,
                        new string('0', 64)),
                    host_fingerprint_id =
                        $"host.{Convert.ToHexString(
                            System.Security.Cryptography.SHA256.HashData(
                                System.Text.Encoding.UTF8.GetBytes(
                                    Environment.MachineName)))
                            .ToLowerInvariant()}",
                    os_platform =
                        System.Runtime.InteropServices.RuntimeInformation
                            .OSDescription,
                    os_architecture =
                        System.Runtime.InteropServices.RuntimeInformation
                            .OSArchitecture.ToString().ToLowerInvariant(),
                    manifest_content_sha256 = GetBinding(
                        ManifestHashVariable,
                        new string('0', 64)),
                    authorization_content_sha256 = GetBinding(
                        AuthorizationHashVariable,
                        new string('0', 64)),
                    cells = cellCaptures,
                    active_behavior_authorization = false,
                    performance_acceptance_authorization = false,
                }));
        }
    }

    private static string ReadString(object value, string propertyName)
    {
        using JsonDocument document = JsonDocument.Parse(
            JsonSerializer.Serialize(value));
        return document.RootElement.GetProperty(propertyName).GetString()!;
    }

    private static int ReadInt(object value, string propertyName)
    {
        using JsonDocument document = JsonDocument.Parse(
            JsonSerializer.Serialize(value));
        return document.RootElement.GetProperty(propertyName).GetInt32();
    }

    private static string GetBinding(string variable, string fallback)
    {
        string? value = Environment.GetEnvironmentVariable(variable);
        return string.IsNullOrWhiteSpace(value) ? fallback : value;
    }

    private static string Value(
        QuicOversizedWriteAdmissionPolicyMode value)
        => value switch
        {
            QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent =>
                "legacy_current",
            QuicOversizedWriteAdmissionPolicyMode.SingleFragment =>
                "single_fragment",
            _ => throw new ArgumentOutOfRangeException(nameof(value)),
        };

    private static string Value(
        QuicApplicationSendBatchPolicyMode value)
        => value switch
        {
            QuicApplicationSendBatchPolicyMode.LegacyCurrent =>
                "legacy_current",
            QuicApplicationSendBatchPolicyMode.SingleEligible =>
                "single_eligible",
            _ => throw new ArgumentOutOfRangeException(nameof(value)),
        };

    private static string Value(QuicBufferCopyPolicyValue value)
        => value switch
        {
            QuicBufferCopyPolicyValue.LegacyCurrent => "legacy_current",
            QuicBufferCopyPolicyValue.MemoryConservative =>
                "memory_conservative",
            _ => throw new ArgumentOutOfRangeException(nameof(value)),
        };

    private static Cell[] Cells =>
    [
        new(
            "a0",
            "c9e070a0880872c9c9dce62f07e933a0de96c7590d343ce7f923f121278bba28",
            QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent,
            QuicApplicationSendBatchPolicyMode.LegacyCurrent,
            QuicBufferCopyPolicyValue.LegacyCurrent),
        new(
            "a1",
            "c41ed6674829898c3dc4e9af34cca11d159c07642c267a893b9d7097c3cc4f25",
            QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent,
            QuicApplicationSendBatchPolicyMode.LegacyCurrent,
            QuicBufferCopyPolicyValue.MemoryConservative),
        new(
            "a2",
            "68c4112be72f82a9eb11b8a6dcf0594542337960c85bcc5f7386d91a172341db",
            QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent,
            QuicApplicationSendBatchPolicyMode.SingleEligible,
            QuicBufferCopyPolicyValue.LegacyCurrent),
        new(
            "a3",
            "1b7b63f5d53d39416d999b4bda0cc0c80e8817a535ceed9bc91e36aa12bcc2b1",
            QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent,
            QuicApplicationSendBatchPolicyMode.SingleEligible,
            QuicBufferCopyPolicyValue.MemoryConservative),
        new(
            "a4",
            "99c02f1b21aaef38b13b996a8e25d31b1e78d1f6927433470dd743ddc3a37598",
            QuicOversizedWriteAdmissionPolicyMode.SingleFragment,
            QuicApplicationSendBatchPolicyMode.LegacyCurrent,
            QuicBufferCopyPolicyValue.LegacyCurrent),
        new(
            "a5",
            "e3635faeb1b2435fc40487bd1cc5060f822624607c2c2202b78d1c1894041b2a",
            QuicOversizedWriteAdmissionPolicyMode.SingleFragment,
            QuicApplicationSendBatchPolicyMode.LegacyCurrent,
            QuicBufferCopyPolicyValue.MemoryConservative),
        new(
            "a6",
            "ac2a8d830612027da8f85d90d6bf9624c344078ae0067dd9fca3b8e7c6ae6fd1",
            QuicOversizedWriteAdmissionPolicyMode.SingleFragment,
            QuicApplicationSendBatchPolicyMode.SingleEligible,
            QuicBufferCopyPolicyValue.LegacyCurrent),
        new(
            "a7",
            "281b32fd62406993adbffb6c6717e8a73d8ced29524b8f0a82b2d470cbda409f",
            QuicOversizedWriteAdmissionPolicyMode.SingleFragment,
            QuicApplicationSendBatchPolicyMode.SingleEligible,
            QuicBufferCopyPolicyValue.MemoryConservative),
    ];

    private sealed record Cell(
        string Suffix,
        string CellHash,
        QuicOversizedWriteAdmissionPolicyMode OversizedMode,
        QuicApplicationSendBatchPolicyMode BatchMode,
        QuicBufferCopyPolicyValue BufferValue)
    {
        internal string CellId =>
            $"cell.send_admission_composition.correctness.{Suffix}";

        internal string RunId =>
            $"run.send_admission_composition.correctness.{Suffix}";

        internal string ConnectionKey =>
            $"connection.send_admission_composition.correctness.{Suffix}";
    }
}
