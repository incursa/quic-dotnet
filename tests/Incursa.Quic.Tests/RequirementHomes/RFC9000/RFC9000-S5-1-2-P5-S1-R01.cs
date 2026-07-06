// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S5-1-2-P5-S1-R01")]
public sealed class RFC9000_S5_1_2_P5_S1_R01
{
    [Fact]
    /// <workbench-requirements generated="true" source="manual">
    ///   <workbench-requirement requirementId="RFC9000-S5-1-2-P5-S1-R01">Upon receipt of an increased Retire Prior To field, the peer MUST stop using the corresponding connection IDs and retire them with RETIRE_CONNECTION_ID frames before adding the newly provided connection ID to the set of active connection IDs.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("RFC9000-S5-1-2-P5-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void NewConnectionIdFrame_WithIncreasedRetirePriorToRetiresLowerSequencesBeforeUsingTheNewConnectionId()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();

        Assert.True(QuicConnectionIdLifecycleTestSupport.ProcessNewConnectionIdFrame(
            runtime,
            sequenceNumber: 1UL,
            retirePriorTo: 0UL,
            connectionId: [0x10, 0x11, 0x12],
            observedAtTicks: 9,
            statelessResetTokenStart: 0x20).StateChanged);

        QuicConnectionTransitionResult result = QuicConnectionIdLifecycleTestSupport.ProcessNewConnectionIdFrame(
            runtime,
            sequenceNumber: 2UL,
            retirePriorTo: 1UL,
            connectionId: [0x20, 0x21, 0x22],
            observedAtTicks: 10,
            statelessResetTokenStart: 0x30);

        Assert.True(result.StateChanged);
        Assert.Equal([0UL], QuicConnectionIdLifecycleTestSupport.GetRetiredSequenceNumbers(runtime, result));
        Assert.Equal([0x20, 0x21, 0x22], runtime.CurrentPeerDestinationConnectionId.ToArray());
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
    }

    [Fact]
    /// <workbench-requirements generated="true" source="manual">
    ///   <workbench-requirement requirementId="RFC9000-S5-1-2-P5-S1-R01">Upon receipt of an increased Retire Prior To field, the peer MUST stop using the corresponding connection IDs and retire them with RETIRE_CONNECTION_ID frames before adding the newly provided connection ID to the set of active connection IDs.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("RFC9000-S5-1-2-P5-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryAcceptNewConnectionId_WithoutAnIncreasedRetirePriorToKeepsEarlierPeerConnectionIdsActive()
    {
        QuicConnectionPeerConnectionIdState state = new();

        Assert.True(state.TryAcceptNewConnectionId(
            new QuicNewConnectionIdFrame(
                1UL,
                0UL,
                [0x30, 0x31, 0x32],
                QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x40)),
            requiresZeroLengthDestinationConnectionId: false,
            activeConnectionIdLimit: 3UL,
            initialDestinationConnectionId: [0x01, 0x02, 0x03],
            out QuicTransportErrorCode errorCode,
            out _,
            out ulong[] retiredSequenceNumbers));
        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.Empty(retiredSequenceNumbers);

        Assert.True(state.TryAcceptNewConnectionId(
            new QuicNewConnectionIdFrame(
                2UL,
                0UL,
                [0x40, 0x41, 0x42],
                QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x50)),
            requiresZeroLengthDestinationConnectionId: false,
            activeConnectionIdLimit: 3UL,
            initialDestinationConnectionId: [0x01, 0x02, 0x03],
            out errorCode,
            out _,
            out retiredSequenceNumbers));

        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.Empty(retiredSequenceNumbers);
        Assert.Equal(3, state.ActiveConnectionIdCount);
    }

    [Fact]
    /// <workbench-requirements generated="true" source="manual">
    ///   <workbench-requirement requirementId="RFC9000-S5-1-2-P5-S1-R01">Upon receipt of an increased Retire Prior To field, the peer MUST stop using the corresponding connection IDs and retire them with RETIRE_CONNECTION_ID frames before adding the newly provided connection ID to the set of active connection IDs.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("RFC9000-S5-1-2-P5-S1-R01")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryAcceptNewConnectionId_WithRetirePriorToEqualToSequenceRetiresAllLowerSequencesBeforeAddingTheNewConnectionId()
    {
        QuicConnectionPeerConnectionIdState state = new();

        Assert.True(state.TryAcceptNewConnectionId(
            new QuicNewConnectionIdFrame(
                1UL,
                0UL,
                [0x50, 0x51, 0x52],
                QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x60)),
            requiresZeroLengthDestinationConnectionId: false,
            activeConnectionIdLimit: 2UL,
            initialDestinationConnectionId: [0x01, 0x02, 0x03],
            out QuicTransportErrorCode errorCode,
            out _,
            out _));
        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);

        Assert.True(state.TryAcceptNewConnectionId(
            new QuicNewConnectionIdFrame(
                2UL,
                2UL,
                [0x60, 0x61, 0x62],
                QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x70)),
            requiresZeroLengthDestinationConnectionId: false,
            activeConnectionIdLimit: 2UL,
            initialDestinationConnectionId: [0x01, 0x02, 0x03],
            out errorCode,
            out bool destinationConnectionIdChanged,
            out ulong[] retiredSequenceNumbers));

        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.True(destinationConnectionIdChanged);
        Assert.Equal([0UL, 1UL], retiredSequenceNumbers.Order().ToArray());
        Assert.Equal(1, state.ActiveConnectionIdCount);
        Assert.Equal(2UL, state.CurrentDestinationConnectionIdSequence);
        Assert.Equal([0x60, 0x61, 0x62], state.CurrentDestinationConnectionId.ToArray());
    }

    [Fact]
    /// <workbench-requirements generated="true" source="manual">
    ///   <workbench-requirement requirementId="RFC9000-S5-1-2-P5-S1-R01">Upon receipt of an increased Retire Prior To field, the peer MUST stop using the corresponding connection IDs and retire them with RETIRE_CONNECTION_ID frames before adding the newly provided connection ID to the set of active connection IDs.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("RFC9000-S5-1-2-P5-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void TryAcceptNewConnectionIdFuzz_RetiresLowerSequencesBeforeAddingTheNewConnectionId()
    {
        for (ulong targetSequenceNumber = 2; targetSequenceNumber <= 5; targetSequenceNumber++)
        {
            QuicConnectionPeerConnectionIdState state = new();
            ulong activeConnectionIdLimit = targetSequenceNumber + 2;

            for (ulong sequenceNumber = 1; sequenceNumber < targetSequenceNumber; sequenceNumber++)
            {
                Assert.True(state.TryAcceptNewConnectionId(
                    new QuicNewConnectionIdFrame(
                        sequenceNumber,
                        0UL,
                        [(byte)sequenceNumber, 0x30, 0x31],
                        QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken((byte)(0x40 + sequenceNumber))),
                    requiresZeroLengthDestinationConnectionId: false,
                    activeConnectionIdLimit,
                    initialDestinationConnectionId: [0x01, 0x02, 0x03],
                    out QuicTransportErrorCode errorCode,
                    out _,
                    out ulong[] retiredSequenceNumbers));
                Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
                Assert.Empty(retiredSequenceNumbers);
            }

            Assert.True(state.TryAcceptNewConnectionId(
                new QuicNewConnectionIdFrame(
                    targetSequenceNumber,
                    targetSequenceNumber,
                    [(byte)targetSequenceNumber, 0x60, 0x61],
                    QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken((byte)(0x70 + targetSequenceNumber))),
                requiresZeroLengthDestinationConnectionId: false,
                activeConnectionIdLimit,
                initialDestinationConnectionId: [0x01, 0x02, 0x03],
                out QuicTransportErrorCode finalErrorCode,
                out bool destinationConnectionIdChanged,
                out ulong[] finalRetiredSequenceNumbers));

            Assert.Equal(QuicTransportErrorCode.NoError, finalErrorCode);
            Assert.True(destinationConnectionIdChanged);
            Assert.Equal(Enumerable.Range(0, (int)targetSequenceNumber).Select(value => (ulong)value), finalRetiredSequenceNumbers.Order());
            Assert.Equal(1, state.ActiveConnectionIdCount);
            Assert.Equal(targetSequenceNumber, state.CurrentDestinationConnectionIdSequence);
            Assert.Equal([(byte)targetSequenceNumber, 0x60, 0x61], state.CurrentDestinationConnectionId.ToArray());
        }
    }
}
