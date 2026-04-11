namespace Incursa.Quic;

/// <summary>
/// Identifies the direction of a QUIC stream.
/// </summary>
public enum QuicStreamType : byte
{
    /// <summary>
    /// A unidirectional stream.
    /// </summary>
    Unidirectional = 0,

    /// <summary>
    /// A bidirectional stream.
    /// </summary>
    Bidirectional = 1,
}

