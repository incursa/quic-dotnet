// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Tests;

internal static class QuicS18P2DisableActiveMigrationTestSupport
{
    internal const ulong DisableActiveMigrationId = 0x0C;
    internal static readonly QuicConnectionPathIdentity OriginalPath = new(
        "203.0.113.30",
        LocalAddress: "198.51.100.1",
        RemotePort: 443,
        LocalPort: 61234);

    private static readonly byte[] InitialSourceConnectionId = [0x10, 0x11, 0x12, 0x13];
    private static readonly byte[] DedicatedAddressIpv4 = [198, 51, 100, 30];
    private static readonly byte[] PortOnlyAddressIpv4 = [203, 0, 113, 30];
    private static readonly byte[] PreferredConnectionId = [0x20, 0x21, 0x22, 0x23];
    private static readonly byte[] PreferredIpv6Address = [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x1E];
    private static readonly byte[] StatelessResetToken = [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F];

    internal static byte[] CreateDatagram() => new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

    internal static QuicConnectionPathIdentity CreatePeerRebindingPath()
    {
        return new QuicConnectionPathIdentity(
            "198.51.100.77",
            OriginalPath.LocalAddress,
            RemotePort: 443,
            OriginalPath.LocalPort);
    }

    internal static QuicConnectionPathIdentity CreateNewLocalAddressPath()
    {
        return new QuicConnectionPathIdentity(
            OriginalPath.RemoteAddress,
            LocalAddress: "198.51.100.2",
            OriginalPath.RemotePort,
            LocalPort: 61235);
    }

    internal static QuicConnectionPathIdentity CreatePreferredPath(QuicPreferredAddress preferredAddress)
    {
        return new QuicConnectionPathIdentity(
            new IPAddress(preferredAddress.IPv4Address).ToString(),
            OriginalPath.LocalAddress,
            RemotePort: preferredAddress.IPv4Port,
            OriginalPath.LocalPort);
    }

    internal static QuicTransportParameters CreateDisableActiveMigrationPeerTransportParameters()
    {
        return new QuicTransportParameters
        {
            InitialSourceConnectionId = InitialSourceConnectionId.ToArray(),
            DisableActiveMigration = true,
        };
    }

    internal static QuicTransportParameters CreatePreferredAddressPeerTransportParameters()
    {
        return CreatePreferredAddressPeerTransportParameters(DedicatedAddressIpv4, preferredIpv4Port: 9443);
    }

    internal static QuicTransportParameters CreatePortOnlyPreferredAddressPeerTransportParameters()
    {
        return CreatePreferredAddressPeerTransportParameters(PortOnlyAddressIpv4, preferredIpv4Port: 9443);
    }

    internal static QuicTransportParameters ParsePeerTransportParameters(QuicTransportParameters transportParameters)
    {
        byte[] encoded = FormatTransportParameters(transportParameters, QuicTransportParameterRole.Server);
        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsedTransportParameters));

        return parsedTransportParameters;
    }

    internal static byte[] FormatTransportParameters(
        QuicTransportParameters transportParameters,
        QuicTransportParameterRole senderRole)
    {
        byte[] destination = new byte[512];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            transportParameters,
            senderRole,
            destination,
            out int bytesWritten));

        return destination[..bytesWritten];
    }

    internal static QuicConnectionRuntime CreateRuntimeWithCommittedPeerTransportParameters(
        QuicTransportParameters peerTransportParameters)
    {
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(OriginalPath);
        CommitPeerTransportParametersThroughRuntime(runtime, peerTransportParameters);
        return runtime;
    }

    internal static void CommitPeerTransportParametersThroughRuntime(
        QuicConnectionRuntime runtime,
        QuicTransportParameters peerTransportParameters)
    {
        QuicPathMigrationRecoveryTestSupport.CommitPeerTransportParameters(runtime, peerTransportParameters);

        QuicConnectionTransitionResult commitResult = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 10,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.PeerTransportParametersCommitted,
                    TransportParameters: peerTransportParameters)),
            nowTicks: 10);

        Assert.True(commitResult.StateChanged);
        Assert.True(runtime.TransportFlags.HasFlag(QuicConnectionTransportState.PeerTransportParametersCommitted));
        Assert.Equal(
            peerTransportParameters.DisableActiveMigration,
            runtime.TransportFlags.HasFlag(QuicConnectionTransportState.DisableActiveMigration));
    }

    private static QuicTransportParameters CreatePreferredAddressPeerTransportParameters(
        byte[] preferredIpv4Address,
        ushort preferredIpv4Port)
    {
        return new QuicTransportParameters
        {
            InitialSourceConnectionId = InitialSourceConnectionId.ToArray(),
            DisableActiveMigration = true,
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = preferredIpv4Address.ToArray(),
                IPv4Port = preferredIpv4Port,
                IPv6Address = PreferredIpv6Address.ToArray(),
                IPv6Port = 9553,
                ConnectionId = PreferredConnectionId.ToArray(),
                StatelessResetToken = StatelessResetToken.ToArray(),
            },
        };
    }
}
