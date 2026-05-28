// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class QuicTransportTlsBridgeStateUnitTests
{
    [Fact]
    public void TryCommitLocalTransportParameters_ClonesVersionInformationSnapshot()
    {
        QuicTransportTlsBridgeState state = new();
        uint[] availableVersions =
        [
            QuicVersionNegotiation.Version2,
            QuicVersionNegotiation.Version1,
        ];

        QuicTransportParameters parameters = new()
        {
            VersionInformation = new QuicVersionInformation
            {
                ChosenVersion = QuicVersionNegotiation.Version2,
                AvailableVersions = availableVersions,
            },
        };

        Assert.True(state.TryCommitLocalTransportParameters(parameters));

        parameters.VersionInformation!.ChosenVersion = QuicVersionNegotiation.Version1;
        parameters.VersionInformation.AvailableVersions[0] = 0x11223344;

        Assert.NotNull(state.LocalTransportParameters);
        Assert.NotNull(state.LocalTransportParameters!.VersionInformation);
        Assert.Equal(QuicVersionNegotiation.Version2, state.LocalTransportParameters!.VersionInformation!.ChosenVersion);
        Assert.Equal(QuicVersionNegotiation.Version2, state.LocalTransportParameters!.VersionInformation!.AvailableVersions[0]);
        Assert.Equal(QuicVersionNegotiation.Version1, state.LocalTransportParameters!.VersionInformation!.AvailableVersions[1]);
    }
}
