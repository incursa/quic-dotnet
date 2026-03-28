using FsCheck.Xunit;

namespace Incursa.Quic.Tests;

public sealed class QuicHeaderPropertyTests
{
    [Property(Arbitrary = new[] { typeof(QuicHeaderPropertyGenerators) })]
    [Trait("Requirement", "REQ-QUIC-HDR-0001")]
    [Trait("Category", "Property")]
    public void TryClassifyHeaderForm_UsesTheFirstByteHighBit(HeaderFormPacket packet)
    {
        Assert.True(QuicPacketParser.TryClassifyHeaderForm(packet.Bytes, out QuicHeaderForm headerForm));

        QuicHeaderForm expectedForm = (packet.Bytes[0] & 0x80) == 0
            ? QuicHeaderForm.Short
            : QuicHeaderForm.Long;

        Assert.Equal(expectedForm, headerForm);
    }

    [Property(Arbitrary = new[] { typeof(QuicHeaderPropertyGenerators) })]
    [Trait("Requirement", "REQ-QUIC-HDR-0002")]
    [Trait("Requirement", "REQ-QUIC-HDR-0003")]
    [Trait("Requirement", "REQ-QUIC-HDR-0005")]
    [Trait("Requirement", "REQ-QUIC-HDR-0006")]
    [Trait("Category", "Property")]
    public void TryParseLongHeader_RoundTripsHeaderFields(LongHeaderScenario scenario)
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            scenario.HeaderControlBits,
            scenario.Version,
            scenario.DestinationConnectionId,
            scenario.SourceConnectionId,
            scenario.VersionSpecificData);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((byte)(scenario.HeaderControlBits & 0x7F), header.HeaderControlBits);
        Assert.Equal(scenario.Version, header.Version);
        Assert.Equal(scenario.Version == 0, header.IsVersionNegotiation);
        Assert.True(scenario.DestinationConnectionId.AsSpan().SequenceEqual(header.DestinationConnectionId));
        Assert.True(scenario.SourceConnectionId.AsSpan().SequenceEqual(header.SourceConnectionId));
        Assert.True(scenario.VersionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));
    }

    [Property(Arbitrary = new[] { typeof(QuicHeaderPropertyGenerators) })]
    [Trait("Requirement", "REQ-QUIC-HDR-0007")]
    [Trait("Category", "Property")]
    public void TryParseShortHeader_PreservesOpaqueRemainder(ShortHeaderScenario scenario)
    {
        byte[] packet = QuicHeaderTestData.BuildShortHeader(scenario.HeaderControlBits, scenario.Remainder);

        Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket header));
        Assert.Equal(QuicHeaderForm.Short, header.HeaderForm);
        Assert.Equal(scenario.HeaderControlBits, header.HeaderControlBits);
        Assert.True(scenario.Remainder.AsSpan().SequenceEqual(header.Remainder));
    }

    [Property(Arbitrary = new[] { typeof(QuicHeaderPropertyGenerators) })]
    [Trait("Requirement", "REQ-QUIC-HDR-0008")]
    [Trait("Requirement", "REQ-QUIC-HDR-0009")]
    [Trait("Requirement", "REQ-QUIC-HDR-0010")]
    [Trait("Category", "Property")]
    public void TryParseVersionNegotiation_RoundTripsSupportedVersions(VersionNegotiationScenario scenario)
    {
        byte[] packet = QuicHeaderTestData.BuildVersionNegotiation(
            scenario.HeaderControlBits,
            scenario.DestinationConnectionId,
            scenario.SourceConnectionId,
            scenario.SupportedVersions);

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(packet, out QuicVersionNegotiationPacket header));
        Assert.Equal(QuicHeaderForm.Long, header.HeaderForm);
        Assert.Equal((byte)(scenario.HeaderControlBits & 0x7F), header.HeaderControlBits);
        Assert.True(header.IsVersionNegotiation);
        Assert.Equal((uint)0, header.Version);
        Assert.Equal(scenario.DestinationConnectionId.Length, header.DestinationConnectionIdLength);
        Assert.True(scenario.DestinationConnectionId.AsSpan().SequenceEqual(header.DestinationConnectionId));
        Assert.Equal(scenario.SourceConnectionId.Length, header.SourceConnectionIdLength);
        Assert.True(scenario.SourceConnectionId.AsSpan().SequenceEqual(header.SourceConnectionId));
        Assert.Equal(scenario.SupportedVersions.Length, header.SupportedVersionCount);

        for (int index = 0; index < scenario.SupportedVersions.Length; index++)
        {
            Assert.Equal(scenario.SupportedVersions[index], header.GetSupportedVersion(index));
        }
    }
}
