// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class RFC9000_S10P3P1P2_StatelessResetCheck_DeferredFuzzClosure
{
    [Fact]
    [Requirement("RFC9000-S10-3-1-P2-S2-R01")]
    [Requirement("RFC9000-S10-3-1-P2-S2-R02")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void StatelessResetCheckFuzz_SkipsAfterRoutedPacketAndChecksUnassociatedFirstPacket()
    {
        for (int routeLength = 1; routeLength <= 8; routeLength++)
        {
            using QuicConnectionRuntimeEndpoint endpoint = new(2);
            using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
            QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
            QuicConnectionPathIdentity pathIdentity = new($"203.0.113.{130 + routeLength}", RemotePort: 4000 + routeLength);
            byte[] routeConnectionId = QuicStatelessResetRequirementTestData.CreateConnectionId(
                start: (byte)(0x30 + routeLength),
                length: routeLength);
            byte[] token = QuicStatelessResetRequirementTestData.CreateToken((byte)(0x80 + routeLength));

            Assert.True(endpoint.TryRegisterConnection(handle, runtime));
            Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
            Assert.True(endpoint.TryRegisterConnectionId(
                handle,
                routeConnectionId,
                statelessResetConnectionId: 900UL + (ulong)routeLength));
            Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 900UL + (ulong)routeLength, token));

            byte[] routedFirstPacket = QuicStatelessResetEndpointHostTestSupport.CreateRetainedRouteShortHeaderDatagram(
                routeConnectionId,
                triggeringPacketLength: routeLength + 32 + routeLength);
            byte[] potentialResetTail = QuicStatelessResetRequirementTestData.FormatDatagram(
                token,
                QuicStatelessReset.MinimumDatagramLength + routeLength);
            byte[] coalescedDatagram = [.. routedFirstPacket, .. potentialResetTail];

            QuicConnectionIngressResult routedResult = endpoint.ReceiveDatagram(coalescedDatagram, pathIdentity);

            Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, routedResult.Disposition);
            Assert.Equal(QuicConnectionEndpointHandlingKind.None, routedResult.HandlingKind);
            Assert.Equal(handle, routedResult.Handle);

            byte[] unassociatedFirstPacket = QuicStatelessResetRequirementTestData.FormatDatagram(
                token,
                QuicStatelessReset.MinimumDatagramLength + 16 + routeLength);
            unassociatedFirstPacket[1] ^= 0x7F;

            QuicConnectionIngressResult resetResult = endpoint.ReceiveDatagram(unassociatedFirstPacket, pathIdentity);

            Assert.Equal(QuicConnectionIngressDisposition.EndpointHandling, resetResult.Disposition);
            Assert.Equal(QuicConnectionEndpointHandlingKind.StatelessReset, resetResult.HandlingKind);
            Assert.Equal(handle, resetResult.Handle);
        }
    }
}
