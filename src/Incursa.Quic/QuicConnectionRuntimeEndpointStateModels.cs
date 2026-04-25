using System.Buffers.Binary;
using System.Runtime.CompilerServices;

namespace Incursa.Quic;

internal enum QuicConnectionIngressDisposition
{
    RoutedToConnection = 0,
    EndpointHandling = 1,
    Unroutable = 2,
    Malformed = 3,
}

internal enum QuicConnectionEndpointHandlingKind
{
    None = 0,
    VersionNegotiation = 1,
    Retry = 2,
    StatelessReset = 3,
}

internal readonly record struct QuicConnectionIngressResult(
    QuicConnectionIngressDisposition Disposition,
    QuicConnectionEndpointHandlingKind HandlingKind,
    QuicConnectionHandle? Handle)
{
    public bool RoutedToConnection => Disposition == QuicConnectionIngressDisposition.RoutedToConnection;
}

internal sealed record QuicConnectionStatelessResetBinding(
    QuicConnectionHandle Handle,
    ulong ConnectionId,
    QuicConnectionPathIdentity PathIdentity,
    byte[] Token,
    QuicConnectionVersionProfile VersionProfile);

internal readonly record struct QuicConnectionVersionProfile(
    ReadOnlyMemory<uint> SupportedVersions)
{
    internal uint SelectedVersion => SupportedVersions.Span[0];
}

internal enum QuicConnectionStatelessResetEmissionDisposition
{
    Emitted = 0,
    TokenUnavailable = 1,
    RateLimited = 2,
    LoopOrAmplificationPrevented = 3,
    FormatFailed = 4,
    StatelessResetLoopSuppressed = 5,
}

internal readonly record struct QuicConnectionStatelessResetEmissionResult(
    QuicConnectionStatelessResetEmissionDisposition Disposition,
    QuicConnectionPathIdentity? PathIdentity,
    ReadOnlyMemory<byte> Datagram)
{
    public bool Emitted => Disposition == QuicConnectionStatelessResetEmissionDisposition.Emitted;
}

internal readonly record struct QuicConnectionIdKey(
    ulong Part0,
    ulong Part1,
    uint Part2,
    byte Length)
{
    private const int ULongByteLength = sizeof(ulong);
    private const int UIntByteLength = sizeof(uint);
    private const int DoubleULongByteLength = ULongByteLength * 2;
    internal const int MaximumLength = DoubleULongByteLength + UIntByteLength;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static bool TryCreate(ReadOnlySpan<byte> connectionId, out QuicConnectionIdKey key)
    {
        if (connectionId.Length > MaximumLength)
        {
            key = default;
            return false;
        }

        key = new QuicConnectionIdKey(
            Pack64(connectionId),
            connectionId.Length > ULongByteLength ? Pack64(connectionId[ULongByteLength..]) : 0UL,
            connectionId.Length > DoubleULongByteLength ? Pack32(connectionId[DoubleULongByteLength..]) : 0U,
            (byte)connectionId.Length);
        return true;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong Pack64(ReadOnlySpan<byte> bytes)
    {
        Span<byte> buffer = stackalloc byte[ULongByteLength];
        int length = Math.Min(bytes.Length, ULongByteLength);
        bytes[..length].CopyTo(buffer);
        return BinaryPrimitives.ReadUInt64LittleEndian(buffer);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint Pack32(ReadOnlySpan<byte> bytes)
    {
        Span<byte> buffer = stackalloc byte[UIntByteLength];
        int length = Math.Min(bytes.Length, UIntByteLength);
        bytes[..length].CopyTo(buffer);
        return BinaryPrimitives.ReadUInt32LittleEndian(buffer);
    }
}

internal readonly record struct QuicConnectionStatelessResetTokenKey(
    ulong Part0,
    ulong Part1)
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static bool TryCreate(ReadOnlySpan<byte> token, out QuicConnectionStatelessResetTokenKey key)
    {
        if (token.Length != QuicStatelessReset.StatelessResetTokenLength)
        {
            key = default;
            return false;
        }

        key = new QuicConnectionStatelessResetTokenKey(
            BinaryPrimitives.ReadUInt64LittleEndian(token[..sizeof(ulong)]),
            BinaryPrimitives.ReadUInt64LittleEndian(token[sizeof(ulong)..]));
        return true;
    }
}

internal readonly record struct QuicConnectionStatelessResetMatchKey(
    string RemoteAddress,
    QuicConnectionStatelessResetTokenKey TokenKey);
