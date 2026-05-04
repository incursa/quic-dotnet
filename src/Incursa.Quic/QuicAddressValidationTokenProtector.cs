using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;

namespace Incursa.Quic;

internal enum QuicAddressValidationTokenValidationResult
{
    Valid = 0,
    Malformed = 1,
    IntegrityFailure = 2,
    Expired = 3,
    Replayed = 4,
}

internal sealed class QuicAddressValidationTokenProtector
{
    internal const int SecretLength = 32;
    internal const int TokenLength = 70;

    private static readonly TimeSpan DefaultTokenLifetime = TimeSpan.FromMinutes(10);
    private static ReadOnlySpan<byte> Magic => "IQAT"u8;

    private const byte FormatVersion = 1;
    private const byte NewTokenSource = 1;
    private const int VersionOffset = 4;
    private const int SourceOffset = 5;
    private const int NonceOffset = 6;
    private const int NonceLength = 16;
    private const int IssuedAtOffset = NonceOffset + NonceLength;
    private const int ExpiresAtOffset = IssuedAtOffset + sizeof(long);
    private const int TagOffset = ExpiresAtOffset + sizeof(long);
    private const int TagLength = 32;

    private readonly byte[] secret;
    private readonly TimeSpan tokenLifetime;

    internal QuicAddressValidationTokenProtector(
        ReadOnlySpan<byte> secret,
        TimeSpan? tokenLifetime = null)
    {
        if (secret.Length < SecretLength)
        {
            throw new ArgumentException("Address-validation token secrets must contain at least 256 bits.", nameof(secret));
        }

        TimeSpan effectiveLifetime = tokenLifetime ?? DefaultTokenLifetime;
        if (effectiveLifetime <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(tokenLifetime));
        }

        this.secret = secret[..SecretLength].ToArray();
        this.tokenLifetime = effectiveLifetime;
    }

    internal static QuicAddressValidationTokenProtector CreateEphemeral(TimeSpan? tokenLifetime = null)
    {
        byte[] secret = new byte[SecretLength];
        RandomNumberGenerator.Fill(secret);
        return new QuicAddressValidationTokenProtector(secret, tokenLifetime);
    }

    internal byte[] IssueNewToken(string remoteAddress)
    {
        return IssueNewToken(remoteAddress, DateTimeOffset.UtcNow);
    }

    internal byte[] IssueNewToken(string remoteAddress, DateTimeOffset issuedAt)
    {
        if (!TryNormalizeRemoteAddress(remoteAddress, out byte[] remoteAddressBytes))
        {
            throw new ArgumentException("The remote address is not a valid IP address.", nameof(remoteAddress));
        }

        byte[] token = new byte[TokenLength];
        Magic.CopyTo(token);
        token[VersionOffset] = FormatVersion;
        token[SourceOffset] = NewTokenSource;
        RandomNumberGenerator.Fill(token.AsSpan(NonceOffset, NonceLength));

        BinaryPrimitives.WriteInt64BigEndian(token.AsSpan(IssuedAtOffset, sizeof(long)), issuedAt.ToUnixTimeSeconds());
        BinaryPrimitives.WriteInt64BigEndian(
            token.AsSpan(ExpiresAtOffset, sizeof(long)),
            issuedAt.Add(tokenLifetime).ToUnixTimeSeconds());

        byte[] tag = ComputeTag(token.AsSpan(0, TagOffset), remoteAddressBytes);
        tag.CopyTo(token.AsSpan(TagOffset, TagLength));
        return token;
    }

    internal QuicAddressValidationTokenValidationResult ValidateNewToken(
        ReadOnlySpan<byte> token,
        string remoteAddress)
    {
        return ValidateNewToken(token, remoteAddress, DateTimeOffset.UtcNow);
    }

    internal QuicAddressValidationTokenValidationResult ValidateNewToken(
        ReadOnlySpan<byte> token,
        string remoteAddress,
        DateTimeOffset now)
    {
        if (token.Length != TokenLength
            || !token[..Magic.Length].SequenceEqual(Magic)
            || token[VersionOffset] != FormatVersion
            || token[SourceOffset] != NewTokenSource
            || !TryNormalizeRemoteAddress(remoteAddress, out byte[] remoteAddressBytes))
        {
            return QuicAddressValidationTokenValidationResult.Malformed;
        }

        long issuedAtSeconds = BinaryPrimitives.ReadInt64BigEndian(token.Slice(IssuedAtOffset, sizeof(long)));
        long expiresAtSeconds = BinaryPrimitives.ReadInt64BigEndian(token.Slice(ExpiresAtOffset, sizeof(long)));
        if (expiresAtSeconds <= issuedAtSeconds)
        {
            return QuicAddressValidationTokenValidationResult.Malformed;
        }

        byte[] expectedTag = ComputeTag(token[..TagOffset], remoteAddressBytes);
        if (!CryptographicOperations.FixedTimeEquals(expectedTag, token.Slice(TagOffset, TagLength)))
        {
            return QuicAddressValidationTokenValidationResult.IntegrityFailure;
        }

        return now.ToUnixTimeSeconds() > expiresAtSeconds
            ? QuicAddressValidationTokenValidationResult.Expired
            : QuicAddressValidationTokenValidationResult.Valid;
    }

    internal static bool TryIdentifyTokenSource(
        ReadOnlySpan<byte> token,
        out QuicAddressValidationTokenSource source)
    {
        source = default;

        if (token.Length != TokenLength
            || !token[..Magic.Length].SequenceEqual(Magic)
            || token[VersionOffset] != FormatVersion
            || token[SourceOffset] != NewTokenSource)
        {
            return false;
        }

        source = QuicAddressValidationTokenSource.NewToken;
        return true;
    }

    internal static bool TryGetNewTokenExpiration(ReadOnlySpan<byte> token, out DateTimeOffset expiresAt)
    {
        expiresAt = default;

        if (token.Length != TokenLength
            || !token[..Magic.Length].SequenceEqual(Magic)
            || token[VersionOffset] != FormatVersion
            || token[SourceOffset] != NewTokenSource)
        {
            return false;
        }

        long issuedAtSeconds = BinaryPrimitives.ReadInt64BigEndian(token.Slice(IssuedAtOffset, sizeof(long)));
        long expiresAtSeconds = BinaryPrimitives.ReadInt64BigEndian(token.Slice(ExpiresAtOffset, sizeof(long)));
        if (expiresAtSeconds <= issuedAtSeconds)
        {
            return false;
        }

        try
        {
            expiresAt = DateTimeOffset.FromUnixTimeSeconds(expiresAtSeconds);
            return true;
        }
        catch (ArgumentOutOfRangeException)
        {
            return false;
        }
    }

    private byte[] ComputeTag(ReadOnlySpan<byte> tokenPrefix, ReadOnlySpan<byte> remoteAddressBytes)
    {
        byte[] macInput = new byte[tokenPrefix.Length + 1 + remoteAddressBytes.Length];
        tokenPrefix.CopyTo(macInput);
        macInput[tokenPrefix.Length] = (byte)remoteAddressBytes.Length;
        remoteAddressBytes.CopyTo(macInput.AsSpan(tokenPrefix.Length + 1));
        return HMACSHA256.HashData(secret, macInput);
    }

    private static bool TryNormalizeRemoteAddress(string remoteAddress, out byte[] addressBytes)
    {
        addressBytes = [];

        if (!IPAddress.TryParse(remoteAddress, out IPAddress? address))
        {
            return false;
        }

        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        addressBytes = address.GetAddressBytes();
        return true;
    }
}
