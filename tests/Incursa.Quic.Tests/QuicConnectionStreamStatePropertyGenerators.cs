using FsCheck;
using FsCheck.Fluent;

namespace Incursa.Quic.Tests;

public sealed record OrderedReceiveScenario(byte[] Head, byte[] Tail);

internal static class QuicConnectionStreamStatePropertyGenerators
{
    public static Arbitrary<OrderedReceiveScenario> OrderedReceiveScenario()
    {
        return Arb.ToArbitrary(
            from headLength in Gen.Choose(1, 8)
            from tailLength in Gen.Choose(1, 8)
            from head in Gen.ArrayOf(GenerateByte(), headLength)
            from tail in Gen.ArrayOf(GenerateByte(), tailLength)
            select new OrderedReceiveScenario(head, tail));
    }

    private static Gen<byte> GenerateByte()
    {
        return Gen.Choose(byte.MinValue, byte.MaxValue).Select(value => (byte)value);
    }
}
