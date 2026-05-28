// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0152")]
public sealed class REQ_QUIC_CRT_0152
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerZeroRttAdmissionConsumesLiveTicketExactlyOnce()
    {
        QuicServerResumptionTicketStore ticketStore = new();
        QuicServerZeroRttAdmissionGate gate = new(ticketStore);
        long nowTicks = Stopwatch.GetTimestamp();
        byte[] ticketBytes = CreateSequentialBytes(0x21, 16);

        Assert.True(StoreTicket(ticketStore, ticketBytes, nowTicks));

        QuicServerZeroRttAdmissionDecision accepted = gate.TryAdmit(
            pskBinderValidated: true,
            ticketBytes,
            CreateRememberedTransportParameters(),
            CreateCurrentTransportParameters(),
            nowTicks,
            out QuicServerResumptionTicketRecord consumedTicket);

        try
        {
            Assert.True(accepted.CanAdmit);
            Assert.Equal(QuicServerZeroRttAdmissionFailure.None, accepted.Failure);
            Assert.Equal(ticketBytes, consumedTicket.TicketBytes);
            Assert.False(ticketStore.TryGetLiveTicket(ticketBytes, nowTicks, out _));

            QuicServerZeroRttAdmissionDecision replayed = gate.TryAdmit(
                pskBinderValidated: true,
                ticketBytes,
                CreateRememberedTransportParameters(),
                CreateCurrentTransportParameters(),
                nowTicks,
                out QuicServerResumptionTicketRecord replayTicket);

            Assert.False(replayed.CanAdmit);
            Assert.Equal(QuicServerZeroRttAdmissionFailure.ReplayOrUnknownTicket, replayed.Failure);
            Assert.Null(replayTicket);
        }
        finally
        {
            consumedTicket?.Clear();
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerZeroRttAdmissionFailsClosedBeforeConsumingWhenPskOrParametersAreInvalid()
    {
        long nowTicks = Stopwatch.GetTimestamp();

        QuicServerResumptionTicketStore pskTicketStore = new();
        QuicServerZeroRttAdmissionGate pskGate = new(pskTicketStore);
        byte[] pskRejectedTicket = CreateSequentialBytes(0x31, 16);
        Assert.True(StoreTicket(pskTicketStore, pskRejectedTicket, nowTicks));

        QuicServerZeroRttAdmissionDecision pskRejected = pskGate.TryAdmit(
            pskBinderValidated: false,
            pskRejectedTicket,
            CreateRememberedTransportParameters(),
            CreateCurrentTransportParameters(),
            nowTicks,
            out QuicServerResumptionTicketRecord pskRejectedConsumedTicket);

        Assert.False(pskRejected.CanAdmit);
        Assert.Equal(QuicServerZeroRttAdmissionFailure.PskNotValidated, pskRejected.Failure);
        Assert.Null(pskRejectedConsumedTicket);
        Assert.True(pskTicketStore.TryGetLiveTicket(pskRejectedTicket, nowTicks, out _));
        pskTicketStore.Clear();

        QuicServerResumptionTicketStore parameterTicketStore = new();
        QuicServerZeroRttAdmissionGate parameterGate = new(parameterTicketStore);
        byte[] parameterRejectedTicket = CreateSequentialBytes(0x41, 16);
        Assert.True(StoreTicket(parameterTicketStore, parameterRejectedTicket, nowTicks));
        QuicTransportParameters reducedCurrentParameters = CreateCurrentTransportParameters();
        reducedCurrentParameters.InitialMaxData = 1;

        QuicServerZeroRttAdmissionDecision parameterRejected = parameterGate.TryAdmit(
            pskBinderValidated: true,
            parameterRejectedTicket,
            CreateRememberedTransportParameters(),
            reducedCurrentParameters,
            nowTicks,
            out QuicServerResumptionTicketRecord parameterRejectedConsumedTicket);

        Assert.False(parameterRejected.CanAdmit);
        Assert.Equal(QuicServerZeroRttAdmissionFailure.TransportParametersRejected, parameterRejected.Failure);
        Assert.Equal(
            QuicZeroRttTransportParameterAcceptanceFailure.ReducedRequiredLimit,
            parameterRejected.TransportParameterFailure);
        Assert.Equal("initial_max_data", parameterRejected.ParameterName);
        Assert.Null(parameterRejectedConsumedTicket);
        Assert.True(parameterTicketStore.TryGetLiveTicket(parameterRejectedTicket, nowTicks, out _));
        parameterTicketStore.Clear();
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ExpiredServerZeroRttAdmissionTicketIsRejectedAndRemoved()
    {
        QuicServerResumptionTicketStore ticketStore = new();
        QuicServerZeroRttAdmissionGate gate = new(ticketStore);
        long nowTicks = Stopwatch.GetTimestamp();
        long expiredIssuedAtTicks = nowTicks - (Stopwatch.Frequency * 2L);
        byte[] ticketBytes = CreateSequentialBytes(0x51, 16);

        Assert.True(StoreTicket(
            ticketStore,
            ticketBytes,
            expiredIssuedAtTicks,
            ticketLifetimeSeconds: 1));

        QuicServerZeroRttAdmissionDecision decision = gate.TryAdmit(
            pskBinderValidated: true,
            ticketBytes,
            CreateRememberedTransportParameters(),
            CreateCurrentTransportParameters(),
            nowTicks,
            out QuicServerResumptionTicketRecord consumedTicket);

        Assert.False(decision.CanAdmit);
        Assert.Equal(QuicServerZeroRttAdmissionFailure.ReplayOrUnknownTicket, decision.Failure);
        Assert.Null(consumedTicket);
        Assert.False(ticketStore.TryGetLiveTicket(ticketBytes, nowTicks, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void FuzzServerZeroRttAdmissionAllowsOnlyOneConsumePerTicketIdentity()
    {
        long nowTicks = Stopwatch.GetTimestamp();
        for (byte seed = 0; seed < 32; seed++)
        {
            QuicServerResumptionTicketStore ticketStore = new();
            QuicServerZeroRttAdmissionGate gate = new(ticketStore);
            byte[] ticketBytes = CreateSequentialBytes((byte)(0x61 + seed), 8 + (seed % 16));
            Assert.True(StoreTicket(ticketStore, ticketBytes, nowTicks));

            int acceptedCount = 0;
            for (int attempt = 0; attempt < 3; attempt++)
            {
                QuicServerZeroRttAdmissionDecision decision = gate.TryAdmit(
                    pskBinderValidated: true,
                    ticketBytes,
                    CreateRememberedTransportParameters(),
                    CreateCurrentTransportParameters(),
                    nowTicks,
                    out QuicServerResumptionTicketRecord consumedTicket);

                if (decision.CanAdmit)
                {
                    acceptedCount++;
                    consumedTicket.Clear();
                }
                else
                {
                    Assert.Equal(QuicServerZeroRttAdmissionFailure.ReplayOrUnknownTicket, decision.Failure);
                    Assert.Null(consumedTicket);
                }
            }

            Assert.Equal(1, acceptedCount);
            Assert.False(ticketStore.TryGetLiveTicket(ticketBytes, nowTicks, out _));
        }
    }

    private static bool StoreTicket(
        QuicServerResumptionTicketStore ticketStore,
        byte[] ticketBytes,
        long issuedAtTicks,
        uint ticketLifetimeSeconds = 600)
        => ticketStore.TryStoreIssuedTicket(
            ticketBytes,
            CreateSequentialBytes(0x81, 8),
            ticketAgeAdd: 0x01020304,
            ticketLifetimeSeconds,
            CreateSequentialBytes(0x91, 32),
            issuedAtTicks);

    private static QuicTransportParameters CreateRememberedTransportParameters()
        => new()
        {
            MaxIdleTimeout = 30_000,
            MaxUdpPayloadSize = 1200,
            InitialMaxData = 16_384,
            InitialMaxStreamDataBidiLocal = 4_096,
            InitialMaxStreamDataBidiRemote = 4_096,
            InitialMaxStreamDataUni = 4_096,
            InitialMaxStreamsBidi = 4,
            InitialMaxStreamsUni = 4,
            ActiveConnectionIdLimit = 2,
        };

    private static QuicTransportParameters CreateCurrentTransportParameters()
        => new()
        {
            MaxIdleTimeout = 30_000,
            MaxUdpPayloadSize = 1200,
            InitialMaxData = 16_384,
            InitialMaxStreamDataBidiLocal = 4_096,
            InitialMaxStreamDataBidiRemote = 4_096,
            InitialMaxStreamDataUni = 4_096,
            InitialMaxStreamsBidi = 4,
            InitialMaxStreamsUni = 4,
            ActiveConnectionIdLimit = 2,
        };

    private static byte[] CreateSequentialBytes(byte startValue, int length)
    {
        byte[] bytes = new byte[length];
        for (int index = 0; index < bytes.Length; index++)
        {
            bytes[index] = unchecked((byte)(startValue + index));
        }

        return bytes;
    }
}
