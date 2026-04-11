namespace Incursa.Quic;

/// <summary>
/// Specifies which side of a stream should be aborted.
/// </summary>
[Flags]
public enum QuicAbortDirection
{
    /// <summary>
    /// Abort the read side of the stream.
    /// </summary>
    Read = 1,

    /// <summary>
    /// Abort the write side of the stream.
    /// </summary>
    Write = 2,

    /// <summary>
    /// Abort both sides of the stream.
    /// </summary>
    Both = Read | Write,
}

