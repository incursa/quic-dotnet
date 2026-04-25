using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks the stateless-reset token generation, formatting, and matching helpers.
/// </summary>
[MemoryDiagnoser]
public class QuicStatelessResetBenchmarks
{
    private const int LargerFlattenedTokenCount = 8;
    private const int LargerDatagramLength = QuicStatelessReset.MinimumDatagramLength + 32;
    private const ulong RetainedRouteConnectionId = 6605UL;

    private byte[] secretKey = [];
    private byte[] connectionId = [];
    private byte[] alternateConnectionId = [];
    private uint[] supportedVersions = [];
    private byte[] statelessResetToken = [];
    private byte[] matchingFlattenedTokens = [];
    private byte[] missingFlattenedTokens = [];
    private byte[] largerFlattenedTokens = [];
    private byte[] formattedDatagram = [];
    private byte[] largerFormattedDatagram = [];
    private byte[] destination = [];
    private byte[] largerDestination = [];
    private QuicConnectionRuntimeEndpoint retainedRouteEndpoint = null!;
    private QuicConnectionRuntime retainedRouteRuntime = null!;
    private QuicConnectionPathIdentity retainedRoutePath;
    private byte[] retainedRouteDatagram = [];
    private byte[] retainedRouteMissDatagram = [];
    private byte[] retainedRouteKnownResetDatagram = [];
    private QuicConnectionRuntimeEndpoint missingTokenEndpoint = null!;
    private QuicConnectionRuntime missingTokenRuntime = null!;
    private byte[] missingTokenRetainedRouteDatagram = [];

    /// <summary>
    /// Prepares representative stateless-reset inputs and output buffers.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        secretKey = [0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97];
        connectionId = [0x10, 0x11, 0x12, 0x13];
        alternateConnectionId =
        [
            0x20, 0x21, 0x22, 0x23,
            0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x2A, 0x2B,
        ];
        supportedVersions =
        [
            QuicVersionNegotiation.Version1,
            0x11223344u,
        ];
        statelessResetToken = new byte[QuicStatelessReset.StatelessResetTokenLength];
        destination = new byte[QuicStatelessReset.MinimumDatagramLength];
        largerDestination = new byte[LargerDatagramLength];

        if (!QuicStatelessReset.TryGenerateStatelessResetToken(connectionId, secretKey, statelessResetToken, out _))
        {
            throw new InvalidOperationException("Failed to generate a representative stateless reset token.");
        }

        if (!QuicStatelessReset.TryFormatStatelessResetDatagram(
            statelessResetToken,
            QuicStatelessReset.MinimumDatagramLength,
            destination,
            out int bytesWritten))
        {
            throw new InvalidOperationException("Failed to format a representative stateless reset datagram.");
        }

        formattedDatagram = destination[..bytesWritten].ToArray();

        if (!QuicStatelessReset.TryFormatStatelessResetDatagram(
            statelessResetToken,
            LargerDatagramLength,
            largerDestination,
            out bytesWritten))
        {
            throw new InvalidOperationException("Failed to format a larger representative stateless reset datagram.");
        }

        largerFormattedDatagram = largerDestination[..bytesWritten].ToArray();
        matchingFlattenedTokens = BuildFlattenedTokenSet(statelessResetToken, 2);

        byte[] missingToken = statelessResetToken.ToArray();
        missingToken[^1] ^= 0xFF;
        missingFlattenedTokens = BuildFlattenedTokenSet(missingToken, 2);
        largerFlattenedTokens = BuildFlattenedTokenSetWithMatchAtEnd(
            missingToken,
            statelessResetToken,
            LargerFlattenedTokenCount);

        retainedRoutePath = new QuicConnectionPathIdentity(
            "203.0.113.66",
            "198.51.100.66",
            RemotePort: 6605,
            LocalPort: 4433);
        retainedRouteDatagram = BuildShortHeaderDatagram(connectionId, LargerDatagramLength);
        retainedRouteMissDatagram = BuildShortHeaderDatagram(alternateConnectionId, LargerDatagramLength);
        retainedRouteKnownResetDatagram = retainedRouteDatagram.ToArray();
        statelessResetToken.CopyTo(retainedRouteKnownResetDatagram.AsSpan(
            retainedRouteKnownResetDatagram.Length - QuicStatelessReset.StatelessResetTokenLength));
        retainedRouteEndpoint = new QuicConnectionRuntimeEndpoint(
            1,
            maximumStatelessResetEmissionsPerRemoteAddress: int.MaxValue);
        retainedRouteRuntime = new QuicConnectionRuntime(CreateStreamState());
        QuicConnectionHandle handle = retainedRouteEndpoint.AllocateConnectionHandle();
        if (!retainedRouteEndpoint.TryRegisterConnection(handle, retainedRouteRuntime)
            || !retainedRouteEndpoint.TryRegisterConnectionId(handle, connectionId, RetainedRouteConnectionId)
            || !retainedRouteEndpoint.TryUpdateEndpointBinding(handle, retainedRoutePath)
            || !retainedRouteEndpoint.TryRegisterStatelessResetToken(handle, RetainedRouteConnectionId, statelessResetToken)
            || !retainedRouteEndpoint.TryApplyEffect(handle, new QuicConnectionDiscardConnectionStateEffect(CreateAeadLimitTerminalState())))
        {
            throw new InvalidOperationException("Failed to configure retained-route stateless reset benchmark state.");
        }

        missingTokenRetainedRouteDatagram = BuildShortHeaderDatagram(alternateConnectionId, LargerDatagramLength);
        missingTokenEndpoint = new QuicConnectionRuntimeEndpoint(
            1,
            maximumStatelessResetEmissionsPerRemoteAddress: int.MaxValue);
        missingTokenRuntime = new QuicConnectionRuntime(CreateStreamState());
        QuicConnectionHandle missingTokenHandle = missingTokenEndpoint.AllocateConnectionHandle();
        if (!missingTokenEndpoint.TryRegisterConnection(missingTokenHandle, missingTokenRuntime)
            || !missingTokenEndpoint.TryRegisterConnectionId(missingTokenHandle, alternateConnectionId, RetainedRouteConnectionId + 1)
            || !missingTokenEndpoint.TryUpdateEndpointBinding(missingTokenHandle, retainedRoutePath)
            || !missingTokenEndpoint.TryApplyEffect(missingTokenHandle, new QuicConnectionDiscardConnectionStateEffect(CreateAeadLimitTerminalState())))
        {
            throw new InvalidOperationException("Failed to configure missing-token retained-route stateless reset benchmark state.");
        }
    }

    /// <summary>
    /// Cleans up the retained endpoint state used by route-level benchmarks.
    /// </summary>
    [GlobalCleanup]
    public void GlobalCleanup()
    {
        retainedRouteEndpoint.Dispose();
        retainedRouteRuntime.Dispose();
        missingTokenEndpoint.Dispose();
        missingTokenRuntime.Dispose();
    }

    /// <summary>
    /// Measures stateless-reset token generation.
    /// </summary>
    [Benchmark]
    public int GenerateStatelessResetToken()
    {
        Span<byte> token = stackalloc byte[QuicStatelessReset.StatelessResetTokenLength];
        return QuicStatelessReset.TryGenerateStatelessResetToken(connectionId, secretKey, token, out int bytesWritten)
            ? bytesWritten
            : -1;
    }

    /// <summary>
    /// Measures Stateless Reset token generation with a longer connection ID.
    /// </summary>
    [Benchmark]
    public int GenerateStatelessResetTokenWithAlternateConnectionIdLength()
    {
        Span<byte> token = stackalloc byte[QuicStatelessReset.StatelessResetTokenLength];
        return QuicStatelessReset.TryGenerateStatelessResetToken(alternateConnectionId, secretKey, token, out int bytesWritten)
            ? bytesWritten
            : -1;
    }

    /// <summary>
    /// Measures Stateless Reset formatting.
    /// </summary>
    [Benchmark]
    public int FormatStatelessResetDatagram()
    {
        return QuicStatelessReset.TryFormatStatelessResetDatagram(
            statelessResetToken,
            QuicStatelessReset.MinimumDatagramLength,
            destination,
            out int bytesWritten)
            ? bytesWritten
            : -1;
    }

    /// <summary>
    /// Measures Stateless Reset formatting for a larger datagram.
    /// </summary>
    [Benchmark]
    public int FormatLargerStatelessResetDatagram()
    {
        return QuicStatelessReset.TryFormatStatelessResetDatagram(
            statelessResetToken,
            LargerDatagramLength,
            largerDestination,
            out int bytesWritten)
            ? bytesWritten
            : -1;
    }

    /// <summary>
    /// Measures Stateless Reset formatting when the retained version-profile snapshot is threaded through the helper.
    /// </summary>
    [Benchmark]
    public int FormatStatelessResetDatagramWithRetainedVersionProfile()
    {
        return QuicStatelessReset.TryFormatStatelessResetDatagram(
            statelessResetToken,
            supportedVersions,
            QuicStatelessReset.MinimumDatagramLength,
            destination,
            out int bytesWritten)
            ? bytesWritten
            : -1;
    }

    /// <summary>
    /// Measures trailing-token matching across a small token set when the token is present.
    /// </summary>
    [Benchmark]
    public int MatchStatelessResetTokenHit()
    {
        return QuicStatelessReset.MatchesAnyStatelessResetToken(formattedDatagram, matchingFlattenedTokens)
            ? formattedDatagram.Length
            : -1;
    }

    /// <summary>
    /// Measures trailing-token matching across a small token set when the token is absent.
    /// </summary>
    [Benchmark]
    public int MatchStatelessResetTokenMiss()
    {
        return QuicStatelessReset.MatchesAnyStatelessResetToken(formattedDatagram, missingFlattenedTokens)
            ? formattedDatagram.Length
            : -1;
    }

    /// <summary>
    /// Measures trailing-token matching against a larger flattened token set.
    /// </summary>
    [Benchmark]
    public int MatchStatelessResetTokenAgainstLargerFlattenedTokenSet()
    {
        return QuicStatelessReset.MatchesAnyStatelessResetToken(largerFormattedDatagram, largerFlattenedTokens)
            ? largerFormattedDatagram.Length
            : -1;
    }

    /// <summary>
    /// Measures retained-route lookup and reset formatting for a post-discard packet that matches a retained CID.
    /// </summary>
    [Benchmark]
    public int CreateRetainedRouteStatelessResetDatagramHit()
    {
        QuicConnectionStatelessResetEmissionResult result = retainedRouteEndpoint.TryCreateStatelessResetDatagramForPacket(
            retainedRouteDatagram,
            retainedRoutePath,
            hasLoopPreventionState: true);

        return result.Emitted ? result.Datagram.Length : -1;
    }

    /// <summary>
    /// Measures retained-route lookup for a post-discard packet that does not match a retained CID.
    /// </summary>
    [Benchmark]
    public int CreateRetainedRouteStatelessResetDatagramMiss()
    {
        QuicConnectionStatelessResetEmissionResult result = retainedRouteEndpoint.TryCreateStatelessResetDatagramForPacket(
            retainedRouteMissDatagram,
            retainedRoutePath,
            hasLoopPreventionState: true);

        return result.Emitted ? result.Datagram.Length : -1;
    }

    /// <summary>
    /// Measures retained-route suppression after discard when the route had no remembered token.
    /// </summary>
    [Benchmark]
    public int CreateRetainedRouteStatelessResetDatagramWithoutRememberedToken()
    {
        QuicConnectionStatelessResetEmissionResult result = missingTokenEndpoint.TryCreateStatelessResetDatagramForPacket(
            missingTokenRetainedRouteDatagram,
            retainedRoutePath,
            hasLoopPreventionState: true);

        return result.Disposition == QuicConnectionStatelessResetEmissionDisposition.TokenUnavailable
            ? missingTokenRetainedRouteDatagram.Length
            : -1;
    }

    /// <summary>
    /// Measures retained-route suppression when the triggering packet is a known Stateless Reset.
    /// </summary>
    [Benchmark]
    public int SuppressRetainedRouteKnownStatelessResetResponse()
    {
        QuicConnectionStatelessResetEmissionResult result = retainedRouteEndpoint.TryCreateStatelessResetDatagramForPacket(
            retainedRouteKnownResetDatagram,
            retainedRoutePath,
            hasLoopPreventionState: true);

        return result.Disposition == QuicConnectionStatelessResetEmissionDisposition.StatelessResetLoopSuppressed
            ? retainedRouteKnownResetDatagram.Length
            : -1;
    }

    private static byte[] BuildFlattenedTokenSet(ReadOnlySpan<byte> token, int tokenCount)
    {
        byte[] flattenedTokens = new byte[tokenCount * QuicStatelessReset.StatelessResetTokenLength];

        for (int index = 0; index < tokenCount; index++)
        {
            token.CopyTo(flattenedTokens.AsSpan(index * QuicStatelessReset.StatelessResetTokenLength));
        }

        return flattenedTokens;
    }

    private static byte[] BuildFlattenedTokenSetWithMatchAtEnd(
        ReadOnlySpan<byte> missToken,
        ReadOnlySpan<byte> matchToken,
        int tokenCount)
    {
        byte[] flattenedTokens = BuildFlattenedTokenSet(missToken, tokenCount);
        matchToken.CopyTo(flattenedTokens.AsSpan((tokenCount - 1) * QuicStatelessReset.StatelessResetTokenLength));
        return flattenedTokens;
    }

    private static byte[] BuildShortHeaderDatagram(ReadOnlySpan<byte> destinationConnectionId, int datagramLength)
    {
        byte[] datagram = new byte[datagramLength];
        datagram[0] = QuicPacketHeaderBits.FixedBitMask;
        destinationConnectionId.CopyTo(datagram.AsSpan(1));
        for (int offset = 1 + destinationConnectionId.Length; offset < datagram.Length; offset++)
        {
            datagram[offset] = unchecked((byte)(0xA0 + offset));
        }

        return datagram;
    }

    private static QuicConnectionStreamState CreateStreamState()
    {
        return new QuicConnectionStreamState(new QuicConnectionStreamStateOptions(
            IsServer: false,
            InitialConnectionReceiveLimit: 65_536,
            InitialConnectionSendLimit: 65_536,
            InitialIncomingBidirectionalStreamLimit: 1,
            InitialIncomingUnidirectionalStreamLimit: 1,
            InitialPeerBidirectionalStreamLimit: 1,
            InitialPeerUnidirectionalStreamLimit: 1,
            InitialLocalBidirectionalReceiveLimit: 65_536,
            InitialPeerBidirectionalReceiveLimit: 65_536,
            InitialPeerUnidirectionalReceiveLimit: 65_536,
            InitialLocalBidirectionalSendLimit: 65_536,
            InitialLocalUnidirectionalSendLimit: 65_536,
            InitialPeerBidirectionalSendLimit: 65_536));
    }

    private static QuicConnectionTerminalState CreateAeadLimitTerminalState()
    {
        return new QuicConnectionTerminalState(
            QuicConnectionPhase.Discarded,
            QuicConnectionCloseOrigin.Local,
            new QuicConnectionCloseMetadata(
                QuicTransportErrorCode.AeadLimitReached,
                ApplicationErrorCode: null,
                TriggeringFrameType: null,
                ReasonPhrase: "The connection reached the AEAD limit."),
            EnteredAtTicks: 0);
    }
}
