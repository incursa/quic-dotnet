namespace Incursa.Quic.Http3;

/// <summary>
/// Represents an HTTP/3 SETTINGS parameter.
/// </summary>
public readonly record struct Http3Setting(ulong Identifier, ulong Value);
