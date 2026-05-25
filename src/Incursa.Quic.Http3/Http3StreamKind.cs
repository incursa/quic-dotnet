namespace Incursa.Quic.Http3;

/// <summary>
/// Identifies the HTTP/3 role assigned to a QUIC stream.
/// </summary>
public enum Http3StreamKind
{
    /// <summary>
    /// A bidirectional request stream.
    /// </summary>
    Request,

    /// <summary>
    /// A unidirectional control stream.
    /// </summary>
    Control,

    /// <summary>
    /// A unidirectional QPACK encoder stream.
    /// </summary>
    QPackEncoder,

    /// <summary>
    /// A unidirectional QPACK decoder stream.
    /// </summary>
    QPackDecoder,

    /// <summary>
    /// A unidirectional push stream.
    /// </summary>
    Push,

    /// <summary>
    /// A unidirectional stream with an unknown stream type.
    /// </summary>
    Unknown,

    /// <summary>
    /// A unidirectional stream with a reserved stream type.
    /// </summary>
    Reserved,
}
