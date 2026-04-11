namespace Incursa.Quic;

/// <summary>
/// A parsed or constructed CONNECTION_CLOSE frame.
/// </summary>
internal readonly ref struct QuicConnectionCloseFrame
{
    /// <summary>
    /// RFC 9000 CONNECTION_CLOSE frame type for transport errors.
    /// </summary>
    private const byte TransportConnectionCloseFrameType = 0x1C;

    /// <summary>
    /// RFC 9000 CONNECTION_CLOSE frame type for application errors.
    /// </summary>
    private const byte ApplicationConnectionCloseFrameType = 0x1D;

    private readonly bool isApplicationError;
    private readonly ulong errorCode;
    private readonly ulong triggeringFrameType;
    private readonly ReadOnlySpan<byte> reasonPhrase;

    /// <summary>
    /// Initializes an application CONNECTION_CLOSE frame view.
    /// </summary>
    internal QuicConnectionCloseFrame(ulong errorCode, ReadOnlySpan<byte> reasonPhrase)
        : this(isApplicationError: true, errorCode, triggeringFrameType: default, reasonPhrase)
    {
    }

    /// <summary>
    /// Initializes a transport CONNECTION_CLOSE frame view.
    /// </summary>
    internal QuicConnectionCloseFrame(ulong errorCode, ulong triggeringFrameType, ReadOnlySpan<byte> reasonPhrase)
        : this(isApplicationError: false, errorCode, triggeringFrameType, reasonPhrase)
    {
    }

    /// <summary>
    /// Initializes a transport CONNECTION_CLOSE frame view using a known QUIC transport error code.
    /// </summary>
    internal QuicConnectionCloseFrame(QuicTransportErrorCode errorCode, ulong triggeringFrameType, ReadOnlySpan<byte> reasonPhrase)
        : this(isApplicationError: false, (ulong)errorCode, triggeringFrameType, reasonPhrase)
    {
    }

    /// <summary>
    /// Initializes a CONNECTION_CLOSE frame view.
    /// </summary>
    private QuicConnectionCloseFrame(
        bool isApplicationError,
        ulong errorCode,
        ulong triggeringFrameType,
        ReadOnlySpan<byte> reasonPhrase)
    {
        this.isApplicationError = isApplicationError;
        this.errorCode = errorCode;
        this.triggeringFrameType = triggeringFrameType;
        this.reasonPhrase = reasonPhrase;
    }

    /// <summary>
    /// Gets whether the close frame is application-specific.
    /// </summary>
    internal bool IsApplicationError => isApplicationError;

    /// <summary>
    /// Gets the frame type carried on the wire.
    /// </summary>
    internal byte FrameType => isApplicationError ? ApplicationConnectionCloseFrameType : TransportConnectionCloseFrameType;

    /// <summary>
    /// Gets the error code.
    /// </summary>
    internal ulong ErrorCode => errorCode;

    /// <summary>
    /// Gets whether the transport close includes a triggering frame type.
    /// </summary>
    internal bool HasTriggeringFrameType => !isApplicationError;

    /// <summary>
    /// Gets the triggering frame type for transport close frames.
    /// </summary>
    internal ulong TriggeringFrameType => triggeringFrameType;

    /// <summary>
    /// Gets the UTF-8 reason phrase bytes.
    /// </summary>
    internal ReadOnlySpan<byte> ReasonPhrase => reasonPhrase;
}

