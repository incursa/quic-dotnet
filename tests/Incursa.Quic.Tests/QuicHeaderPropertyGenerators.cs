using FsCheck;
using FsCheck.Fluent;

namespace Incursa.Quic.Tests;

public sealed record HeaderFormPacket(byte[] Bytes);

public sealed record LongHeaderScenario(
    byte HeaderControlBits,
    uint Version,
    byte[] DestinationConnectionId,
    byte[] SourceConnectionId,
    byte[] VersionSpecificData);

public sealed record ShortHeaderScenario(byte HeaderControlBits, byte[] Remainder);

public sealed record VersionNegotiationScenario(
    byte HeaderControlBits,
    byte[] DestinationConnectionId,
    byte[] SourceConnectionId,
    uint[] SupportedVersions);

internal static class QuicHeaderPropertyGenerators
{
    public static Arbitrary<HeaderFormPacket> HeaderFormPacket()
    {
        return Arb.ToArbitrary(
            GenerateBytes(1, 64).Select(bytes => new HeaderFormPacket(bytes)));
    }

    public static Arbitrary<LongHeaderScenario> LongHeaderScenario()
    {
        return Arb.ToArbitrary(
            from headerControlBits in GenerateHeaderControlBits()
            from version in GenerateUInt32()
            from destinationConnectionId in GenerateBytes(0, 8)
            from sourceConnectionId in GenerateBytes(0, 8)
            from versionSpecificData in GenerateBytes(0, 16)
            select new LongHeaderScenario(
                headerControlBits,
                version,
                destinationConnectionId,
                sourceConnectionId,
                versionSpecificData));
    }

    public static Arbitrary<ShortHeaderScenario> ShortHeaderScenario()
    {
        return Arb.ToArbitrary(
            from headerControlBits in GenerateHeaderControlBits()
            from remainder in GenerateBytes(0, 32)
            select new ShortHeaderScenario(headerControlBits, remainder));
    }

    public static Arbitrary<VersionNegotiationScenario> VersionNegotiationScenario()
    {
        return Arb.ToArbitrary(
            from headerControlBits in GenerateHeaderControlBits()
            from destinationConnectionId in GenerateBytes(0, 8)
            from sourceConnectionId in GenerateBytes(0, 8)
            from supportedVersions in GenerateSupportedVersions(1, 4)
            select new VersionNegotiationScenario(
                headerControlBits,
                destinationConnectionId,
                sourceConnectionId,
                supportedVersions));
    }

    private static Gen<byte> GenerateHeaderControlBits()
    {
        return GenerateByte().Select(value => (byte)(value & 0x7F));
    }

    private static Gen<byte[]> GenerateBytes(int minLength, int maxLength)
    {
        return
            from length in Gen.Choose(minLength, maxLength)
            from bytes in Gen.ArrayOf(GenerateByte(), length)
            select bytes;
    }

    private static Gen<uint> GenerateNonZeroVersion()
    {
        return Gen.Choose(1, int.MaxValue).Select(value => (uint)value);
    }

    private static Gen<uint> GenerateUInt32()
    {
        return Gen.Choose(int.MinValue, int.MaxValue).Select(value => unchecked((uint)value));
    }

    private static Gen<uint[]> GenerateSupportedVersions(int minLength, int maxLength)
    {
        return
            from length in Gen.Choose(minLength, maxLength)
            from versions in Gen.ArrayOf(GenerateNonZeroVersion(), length)
            select versions;
    }

    private static Gen<byte> GenerateByte()
    {
        return Gen.Choose(byte.MinValue, byte.MaxValue).Select(value => (byte)value);
    }
}
