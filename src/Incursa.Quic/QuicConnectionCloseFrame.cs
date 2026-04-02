namespace Incursa.Quic;

/// <summary>
/// A parsed or constructed CONNECTION_CLOSE frame.
/// </summary>
public readonly ref struct QuicConnectionCloseFrame
{
    private readonly bool isApplicationError;
    private readonly ulong errorCode;
    private readonly ulong triggeringFrameType;
    private readonly ReadOnlySpan<byte> reasonPhrase;

    /// <summary>
    /// Initializes an application CONNECTION_CLOSE frame view.
    /// </summary>
    public QuicConnectionCloseFrame(ulong errorCode, ReadOnlySpan<byte> reasonPhrase)
        : this(isApplicationError: true, errorCode, triggeringFrameType: default, reasonPhrase)
    {
    }

    /// <summary>
    /// Initializes a transport CONNECTION_CLOSE frame view.
    /// </summary>
    public QuicConnectionCloseFrame(ulong errorCode, ulong triggeringFrameType, ReadOnlySpan<byte> reasonPhrase)
        : this(isApplicationError: false, errorCode, triggeringFrameType, reasonPhrase)
    {
    }

    /// <summary>
    /// Initializes a transport CONNECTION_CLOSE frame view using a known QUIC transport error code.
    /// </summary>
    public QuicConnectionCloseFrame(QuicTransportErrorCode errorCode, ulong triggeringFrameType, ReadOnlySpan<byte> reasonPhrase)
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
    public bool IsApplicationError => isApplicationError;

    /// <summary>
    /// Gets the frame type carried on the wire.
    /// </summary>
    public byte FrameType => isApplicationError ? (byte)0x1D : (byte)0x1C;

    /// <summary>
    /// Gets the error code.
    /// </summary>
    public ulong ErrorCode => errorCode;

    /// <summary>
    /// Gets whether the transport close includes a triggering frame type.
    /// </summary>
    public bool HasTriggeringFrameType => !isApplicationError;

    /// <summary>
    /// Gets the triggering frame type for transport close frames.
    /// </summary>
    public ulong TriggeringFrameType => triggeringFrameType;

    /// <summary>
    /// Gets the UTF-8 reason phrase bytes.
    /// </summary>
    public ReadOnlySpan<byte> ReasonPhrase => reasonPhrase;
}
