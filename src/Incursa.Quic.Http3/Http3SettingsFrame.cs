namespace Incursa.Quic.Http3;

/// <summary>
/// Represents an HTTP/3 SETTINGS frame.
/// </summary>
public sealed class Http3SettingsFrame : Http3Frame
{
    /// <summary>
    /// Initializes a new instance of the <see cref="Http3SettingsFrame" /> class.
    /// </summary>
    public Http3SettingsFrame(IReadOnlyList<Http3Setting> settings, byte[] payload, Http3Settings values)
        : base((ulong)Http3FrameType.Settings, payload)
    {
        Settings = settings;
        Values = values;
    }

    /// <summary>
    /// Gets the parsed settings.
    /// </summary>
    public IReadOnlyList<Http3Setting> Settings { get; }

    /// <summary>
    /// Gets typed known SETTINGS values.
    /// </summary>
    public Http3Settings Values { get; }
}
