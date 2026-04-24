using System.Collections.Concurrent;
using System.Reflection;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6P6-0007">When the stateless-reset helper cannot format a response because the token length, datagram length, destination space, or version-profile snapshot is invalid, it MUST fail the formatting attempt and callers MUST suppress emission rather than inventing a stateless-reset datagram.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6P6-0007")]
public sealed class REQ_QUIC_RFC9001_S6P6_0007
{
    public static TheoryData<int, int> UndersizedFormatCases => new()
    {
        { QuicStatelessReset.MinimumDatagramLength - 1, QuicStatelessReset.MinimumDatagramLength },
        { QuicStatelessReset.MinimumDatagramLength, QuicStatelessReset.MinimumDatagramLength - 1 },
    };

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatStatelessResetDatagram_WritesTheMinimumLengthDatagramAndKeepsTheTokenAtTheTail()
    {
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x77);
        byte[] datagram = new byte[QuicStatelessReset.MinimumDatagramLength];

        Assert.True(QuicStatelessReset.TryFormatStatelessResetDatagram(token, datagram.Length, datagram, out int bytesWritten));
        Assert.Equal(datagram.Length, bytesWritten);
        QuicStatelessResetRequirementTestData.AssertShortHeaderLayout(datagram);
        QuicStatelessResetRequirementTestData.AssertTailTokenMatches(datagram, token);
    }

    [Theory]
    [MemberData(nameof(UndersizedFormatCases))]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryFormatStatelessResetDatagram_RejectsUndersizedDestinationOrDatagramLength(
        int destinationLength,
        int datagramLength)
    {
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x78);
        byte[] destination = new byte[destinationLength];

        Assert.False(QuicStatelessReset.TryFormatStatelessResetDatagram(token, datagramLength, destination, out int bytesWritten));
        Assert.Equal(0, bytesWritten);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryFormatStatelessResetDatagram_RejectsEmptyVersionProfileSnapshots()
    {
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x79);
        byte[] destination = new byte[QuicStatelessReset.MinimumDatagramLength];

        Assert.False(QuicStatelessReset.TryFormatStatelessResetDatagram(
            token,
            ReadOnlySpan<uint>.Empty,
            destination.Length,
            destination,
            out int bytesWritten));
        Assert.Equal(0, bytesWritten);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryCreateStatelessResetDatagram_ReturnsFormatFailedWhenRetainedVersionProfileIsEmpty()
    {
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            new FakeMonotonicClock(0));
        using QuicConnectionRuntimeEndpoint endpoint = new(1, new FakeMonotonicClock(0));
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.80");
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x7a);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        ForceEmptyVersionProfile(endpoint, handle);
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 80UL, token));

        QuicConnectionStatelessResetEmissionResult result = endpoint.TryCreateStatelessResetDatagram(
            handle,
            80UL,
            QuicStatelessReset.MinimumDatagramLength + 1,
            hasLoopPreventionState: true);

        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.FormatFailed, result.Disposition);
        Assert.False(result.Emitted);
        Assert.Equal(pathIdentity, result.PathIdentity);
        Assert.True(result.Datagram.IsEmpty);
    }

    private static void ForceEmptyVersionProfile(QuicConnectionRuntimeEndpoint endpoint, QuicConnectionHandle handle)
    {
        FieldInfo field = typeof(QuicConnectionRuntimeEndpoint).GetField(
            "versionProfilesByHandle",
            BindingFlags.Instance | BindingFlags.NonPublic)!;
        ConcurrentDictionary<QuicConnectionHandle, QuicConnectionVersionProfile> versionProfiles =
            (ConcurrentDictionary<QuicConnectionHandle, QuicConnectionVersionProfile>)field.GetValue(endpoint)!;

        versionProfiles[handle] = new QuicConnectionVersionProfile(ReadOnlyMemory<uint>.Empty);
    }
}
