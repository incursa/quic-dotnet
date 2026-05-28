// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S18P2-0016")]
public sealed class REQ_QUIC_RFC9000_S18P2_0016
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0016")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatTransportParameters_EmitsDisableActiveMigrationAsAnEmptyParameter()
    {
        QuicTransportParameters transportParameters = new()
        {
            DisableActiveMigration = true,
        };

        byte[] encoded = QuicS18P2DisableActiveMigrationTestSupport.FormatTransportParameters(
            transportParameters,
            QuicTransportParameterRole.Client);
        byte[] expected = QuicTransportParameterTestData.BuildTransportParameterTuple(
            QuicS18P2DisableActiveMigrationTestSupport.DisableActiveMigrationId,
            []);

        Assert.Equal(expected, encoded);
        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Server,
            out QuicTransportParameters parsed));
        Assert.True(parsed.DisableActiveMigration);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0016")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PeerTransportParameterCommitSetsTheDisableActiveMigrationTransportFlag()
    {
        QuicTransportParameters parsedTransportParameters =
            QuicS18P2DisableActiveMigrationTestSupport.ParsePeerTransportParameters(
                QuicS18P2DisableActiveMigrationTestSupport.CreateDisableActiveMigrationPeerTransportParameters());

        using QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(
            QuicS18P2DisableActiveMigrationTestSupport.OriginalPath);
        QuicS18P2DisableActiveMigrationTestSupport.CommitPeerTransportParametersThroughRuntime(
            runtime,
            parsedTransportParameters);

        Assert.True(runtime.TlsState.PeerTransportParameters!.DisableActiveMigration);
        Assert.True(runtime.TransportFlags.HasFlag(QuicConnectionTransportState.DisableActiveMigration));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0016")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseTransportParameters_RejectsNonEmptyDisableActiveMigrationValue()
    {
        byte[] encoded = QuicTransportParameterTestData.BuildTransportParameterTuple(
            QuicS18P2DisableActiveMigrationTestSupport.DisableActiveMigrationId,
            [0x00]);

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Client,
            out _));
    }
}
