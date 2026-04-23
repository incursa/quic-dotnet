namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S14P3-0004")]
public sealed class REQ_QUIC_RFC9000_S14P3_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AcknowledgedProbeUpdatesOnlyTheMatchingAddressPairMaximumPacketSize()
    {
        QuicDplpmtudState state = new();
        QuicConnectionPathIdentity pathA = new("203.0.113.13", "192.0.2.10", 443, 55555);
        QuicConnectionPathIdentity pathB = new("203.0.113.14", "192.0.2.10", 443, 55555);

        Assert.True(state.TryTrackProbe(pathA, packetNumber: 30, probeSizeBytes: 1_300));
        Assert.True(state.TryTrackProbe(pathB, packetNumber: 40, probeSizeBytes: 1_450));
        Assert.True(state.TryRegisterProbeAcknowledged(pathA, packetNumber: 30));

        Assert.Equal(1_300UL, state.GetPathSnapshot(pathA).MaximumPacketSizeBytes);
        Assert.Equal(QuicDplpmtudState.BasePlpmtuBytes, state.GetPathSnapshot(pathB).MaximumPacketSizeBytes);
        Assert.Equal(1, state.GetPathSnapshot(pathB).OutstandingProbeCount);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ProbeOutcomeOnOneAddressPairDoesNotMatchAnotherAddressPair()
    {
        QuicDplpmtudState state = new();
        QuicConnectionPathIdentity pathA = new("203.0.113.13", "192.0.2.10", 443, 55555);
        QuicConnectionPathIdentity pathB = new("203.0.113.14", "192.0.2.10", 443, 55555);

        Assert.True(state.TryTrackProbe(pathA, packetNumber: 30, probeSizeBytes: 1_300));

        Assert.False(state.TryRegisterProbeAcknowledged(pathB, packetNumber: 30));
        Assert.Equal(QuicDplpmtudState.BasePlpmtuBytes, state.GetPathSnapshot(pathA).MaximumPacketSizeBytes);
        Assert.Equal(1, state.GetPathSnapshot(pathA).OutstandingProbeCount);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryTrackProbe_RejectsProbeSizesThatDoNotExceedTheCurrentPathMaximumPacketSize()
    {
        QuicDplpmtudState state = new();
        QuicConnectionPathIdentity path = new("203.0.113.13", "192.0.2.10", 443, 55555);

        Assert.False(state.TryTrackProbe(path, packetNumber: 30, probeSizeBytes: QuicDplpmtudState.BasePlpmtuBytes));
        Assert.True(state.TryTrackProbe(path, packetNumber: 31, probeSizeBytes: QuicDplpmtudState.BasePlpmtuBytes + 1));
        Assert.True(state.TryRegisterProbeAcknowledged(path, packetNumber: 31));
        Assert.False(state.TryTrackProbe(path, packetNumber: 32, probeSizeBytes: QuicDplpmtudState.BasePlpmtuBytes + 1));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void FuzzProbeOutcomesRemainIsolatedPerAddressPair()
    {
        Random random = new(0x514D_5455);
        QuicDplpmtudState state = new();
        QuicConnectionPathIdentity[] paths =
        [
            new("203.0.113.13", "192.0.2.10", 443, 55555),
            new("203.0.113.14", "192.0.2.10", 443, 55555),
            new("203.0.113.15", "192.0.2.11", 443, 55556),
        ];

        ulong[] expectedMaximumPacketSizes =
        [
            QuicDplpmtudState.BasePlpmtuBytes,
            QuicDplpmtudState.BasePlpmtuBytes,
            QuicDplpmtudState.BasePlpmtuBytes,
        ];

        for (int i = 0; i < 128; i++)
        {
            int pathIndex = random.Next(paths.Length);
            QuicConnectionPathIdentity path = paths[pathIndex];
            ulong probeSizeBytes = expectedMaximumPacketSizes[pathIndex] + (ulong)random.Next(1, 256);
            ulong packetNumber = (ulong)(i + 1);

            Assert.True(state.TryTrackProbe(path, packetNumber, probeSizeBytes));

            if (random.Next(2) == 0)
            {
                Assert.True(state.TryRegisterProbeAcknowledged(path, packetNumber));
                expectedMaximumPacketSizes[pathIndex] = probeSizeBytes;
            }
            else
            {
                Assert.True(state.TryRegisterProbeLost(path, packetNumber));
            }

            for (int j = 0; j < paths.Length; j++)
            {
                Assert.Equal(expectedMaximumPacketSizes[j], state.GetPathSnapshot(paths[j]).MaximumPacketSizeBytes);
            }
        }
    }
}
