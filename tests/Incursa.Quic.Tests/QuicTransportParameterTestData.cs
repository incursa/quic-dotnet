using System.Buffers.Binary;

namespace Incursa.Quic.Tests;

internal static class QuicTransportParameterTestData
{
    public static byte[] BuildTransportParameterTuple(ulong id, ReadOnlySpan<byte> value)
    {
        byte[] idBytes = QuicVarintTestData.EncodeMinimal(id);
        byte[] lengthBytes = QuicVarintTestData.EncodeMinimal((ulong)value.Length);

        byte[] tuple = new byte[idBytes.Length + lengthBytes.Length + value.Length];
        int index = 0;

        idBytes.CopyTo(tuple.AsSpan(index));
        index += idBytes.Length;

        lengthBytes.CopyTo(tuple.AsSpan(index));
        index += lengthBytes.Length;

        value.CopyTo(tuple.AsSpan(index));
        return tuple;
    }

    public static byte[] BuildTransportParameterBlock(params byte[][] tuples)
    {
        int length = 0;
        for (int i = 0; i < tuples.Length; i++)
        {
            length += tuples[i].Length;
        }

        byte[] block = new byte[length];
        int index = 0;
        for (int i = 0; i < tuples.Length; i++)
        {
            tuples[i].CopyTo(block.AsSpan(index));
            index += tuples[i].Length;
        }

        return block;
    }

    public static byte[] BuildPreferredAddressValue(
        ReadOnlySpan<byte> ipv4Address,
        ushort ipv4Port,
        ReadOnlySpan<byte> ipv6Address,
        ushort ipv6Port,
        ReadOnlySpan<byte> connectionId,
        ReadOnlySpan<byte> statelessResetToken)
    {
        byte[] value = new byte[4 + 2 + 16 + 2 + 1 + connectionId.Length + 16];
        int index = 0;

        ipv4Address.CopyTo(value.AsSpan(index, 4));
        index += 4;

        BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(index, 2), ipv4Port);
        index += 2;

        ipv6Address.CopyTo(value.AsSpan(index, 16));
        index += 16;

        BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(index, 2), ipv6Port);
        index += 2;

        value[index++] = (byte)connectionId.Length;
        connectionId.CopyTo(value.AsSpan(index, connectionId.Length));
        index += connectionId.Length;

        statelessResetToken.CopyTo(value.AsSpan(index, 16));
        return value;
    }
}
