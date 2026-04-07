using System.Buffers.Binary;

namespace Incursa.Quic.Tests;

internal static class QuicTransportParameterTestData
{
    public static IEnumerable<object[]> MatchingConnectionIdBindingCases()
    {
        yield return new object[]
        {
            QuicTransportParameterRole.Client,
            new byte[] { 0x10, 0x11 },
            new byte[] { 0x20, 0x21 },
            false,
            Array.Empty<byte>(),
            new QuicTransportParameters
            {
                OriginalDestinationConnectionId = new byte[] { 0x10, 0x11 },
                InitialSourceConnectionId = new byte[] { 0x20, 0x21 },
            },
        };

        yield return new object[]
        {
            QuicTransportParameterRole.Client,
            new byte[] { 0x10, 0x11 },
            new byte[] { 0x20, 0x21 },
            true,
            new byte[] { 0x30 },
            new QuicTransportParameters
            {
                OriginalDestinationConnectionId = new byte[] { 0x10, 0x11 },
                InitialSourceConnectionId = new byte[] { 0x20, 0x21 },
                RetrySourceConnectionId = new byte[] { 0x30 },
            },
        };

        yield return new object[]
        {
            QuicTransportParameterRole.Server,
            Array.Empty<byte>(),
            new byte[] { 0x20, 0x21 },
            false,
            Array.Empty<byte>(),
            new QuicTransportParameters
            {
                InitialSourceConnectionId = new byte[] { 0x20, 0x21 },
            },
        };
    }

    public static IEnumerable<object[]> MissingConnectionIdBindingCases()
    {
        yield return new object[]
        {
            QuicTransportParameterRole.Client,
            new byte[] { 0x10, 0x11 },
            new byte[] { 0x20, 0x21 },
            false,
            Array.Empty<byte>(),
            new QuicTransportParameters
            {
                InitialSourceConnectionId = new byte[] { 0x20, 0x21 },
            },
            QuicConnectionIdBindingValidationError.MissingOriginalDestinationConnectionId,
        };

        yield return new object[]
        {
            QuicTransportParameterRole.Client,
            new byte[] { 0x10, 0x11 },
            new byte[] { 0x20, 0x21 },
            false,
            Array.Empty<byte>(),
            new QuicTransportParameters
            {
                OriginalDestinationConnectionId = new byte[] { 0x10, 0x11 },
            },
            QuicConnectionIdBindingValidationError.MissingInitialSourceConnectionId,
        };

        yield return new object[]
        {
            QuicTransportParameterRole.Client,
            new byte[] { 0x10, 0x11 },
            new byte[] { 0x20, 0x21 },
            true,
            Array.Empty<byte>(),
            new QuicTransportParameters
            {
                OriginalDestinationConnectionId = new byte[] { 0x10, 0x11 },
                InitialSourceConnectionId = new byte[] { 0x20, 0x21 },
            },
            QuicConnectionIdBindingValidationError.MissingRetrySourceConnectionId,
        };

        yield return new object[]
        {
            QuicTransportParameterRole.Server,
            Array.Empty<byte>(),
            new byte[] { 0x20, 0x21 },
            false,
            Array.Empty<byte>(),
            new QuicTransportParameters(),
            QuicConnectionIdBindingValidationError.MissingInitialSourceConnectionId,
        };
    }

    public static IEnumerable<object[]> MismatchedConnectionIdBindingCases()
    {
        yield return new object[]
        {
            QuicTransportParameterRole.Client,
            new byte[] { 0x10, 0x11 },
            new byte[] { 0x20, 0x21 },
            false,
            Array.Empty<byte>(),
            new QuicTransportParameters
            {
                OriginalDestinationConnectionId = new byte[] { 0x99 },
                InitialSourceConnectionId = new byte[] { 0x20, 0x21 },
            },
            QuicConnectionIdBindingValidationError.OriginalDestinationConnectionIdMismatch,
        };

        yield return new object[]
        {
            QuicTransportParameterRole.Client,
            new byte[] { 0x10, 0x11 },
            new byte[] { 0x20, 0x21 },
            false,
            Array.Empty<byte>(),
            new QuicTransportParameters
            {
                OriginalDestinationConnectionId = new byte[] { 0x10, 0x11 },
                InitialSourceConnectionId = new byte[] { 0x99 },
            },
            QuicConnectionIdBindingValidationError.InitialSourceConnectionIdMismatch,
        };

        yield return new object[]
        {
            QuicTransportParameterRole.Client,
            new byte[] { 0x10, 0x11 },
            new byte[] { 0x20, 0x21 },
            true,
            new byte[] { 0x30 },
            new QuicTransportParameters
            {
                OriginalDestinationConnectionId = new byte[] { 0x10, 0x11 },
                InitialSourceConnectionId = new byte[] { 0x20, 0x21 },
                RetrySourceConnectionId = new byte[] { 0x99 },
            },
            QuicConnectionIdBindingValidationError.RetrySourceConnectionIdMismatch,
        };

        yield return new object[]
        {
            QuicTransportParameterRole.Client,
            new byte[] { 0x10, 0x11 },
            new byte[] { 0x20, 0x21 },
            false,
            Array.Empty<byte>(),
            new QuicTransportParameters
            {
                OriginalDestinationConnectionId = new byte[] { 0x10, 0x11 },
                InitialSourceConnectionId = new byte[] { 0x20, 0x21 },
                RetrySourceConnectionId = new byte[] { 0x30 },
            },
            QuicConnectionIdBindingValidationError.UnexpectedRetrySourceConnectionId,
        };

        yield return new object[]
        {
            QuicTransportParameterRole.Server,
            Array.Empty<byte>(),
            new byte[] { 0x20, 0x21 },
            false,
            Array.Empty<byte>(),
            new QuicTransportParameters
            {
                InitialSourceConnectionId = new byte[] { 0x99 },
            },
            QuicConnectionIdBindingValidationError.InitialSourceConnectionIdMismatch,
        };
    }

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
