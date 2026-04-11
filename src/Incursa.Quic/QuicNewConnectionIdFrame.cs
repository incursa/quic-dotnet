namespace Incursa.Quic;

/// <summary>
/// A parsed or constructed NEW_CONNECTION_ID frame.
/// </summary>
internal readonly ref struct QuicNewConnectionIdFrame
{
    private readonly ulong sequenceNumber;
    private readonly ulong retirePriorTo;
    private readonly ReadOnlySpan<byte> connectionId;
    private readonly ReadOnlySpan<byte> statelessResetToken;

    /// <summary>
    /// Initializes a NEW_CONNECTION_ID frame view.
    /// </summary>
    internal QuicNewConnectionIdFrame(
        ulong sequenceNumber,
        ulong retirePriorTo,
        ReadOnlySpan<byte> connectionId,
        ReadOnlySpan<byte> statelessResetToken)
    {
        this.sequenceNumber = sequenceNumber;
        this.retirePriorTo = retirePriorTo;
        this.connectionId = connectionId;
        this.statelessResetToken = statelessResetToken;
    }

    /// <summary>
    /// Gets the frame sequence number.
    /// </summary>
    internal ulong SequenceNumber => sequenceNumber;

    /// <summary>
    /// Gets the Retire Prior To value.
    /// </summary>
    internal ulong RetirePriorTo => retirePriorTo;

    /// <summary>
    /// Gets the connection ID bytes.
    /// </summary>
    internal ReadOnlySpan<byte> ConnectionId => connectionId;

    /// <summary>
    /// Gets the stateless reset token bytes.
    /// </summary>
    internal ReadOnlySpan<byte> StatelessResetToken => statelessResetToken;
}

