namespace Incursa.Quic;

/// <summary>
/// Identifies the four QUIC stream type combinations.
/// </summary>
public enum QuicStreamType : byte
{
    /// <summary>
    /// A client-initiated bidirectional stream.
    /// </summary>
    ClientInitiatedBidirectional = 0,
    /// <summary>
    /// A server-initiated bidirectional stream.
    /// </summary>
    ServerInitiatedBidirectional = 1,
    /// <summary>
    /// A client-initiated unidirectional stream.
    /// </summary>
    ClientInitiatedUnidirectional = 2,
    /// <summary>
    /// A server-initiated unidirectional stream.
    /// </summary>
    ServerInitiatedUnidirectional = 3,
}
