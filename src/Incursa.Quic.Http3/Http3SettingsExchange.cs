// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Tracks local SETTINGS emission and peer SETTINGS receipt.
/// </summary>
public sealed class Http3SettingsExchange
{
    private readonly Http3Settings localSettings;
    private bool initialSettingsWritten;

    /// <summary>
    /// Initializes a new instance of the <see cref="Http3SettingsExchange" /> class.
    /// </summary>
    public Http3SettingsExchange(Http3Settings localSettings)
    {
        this.localSettings = localSettings ?? throw new ArgumentNullException(nameof(localSettings));
    }

    /// <summary>
    /// Gets the parsed peer settings after they have been received.
    /// </summary>
    public Http3Settings? PeerSettings { get; private set; }

    /// <summary>
    /// Gets a value indicating whether local SETTINGS have already been emitted.
    /// </summary>
    public bool InitialSettingsWritten => initialSettingsWritten;

    /// <summary>
    /// Emits the local control-stream preface and SETTINGS exactly once when the transport is ready.
    /// </summary>
    public bool TryWriteInitialSettings(out byte[] controlStreamBytes)
    {
        if (initialSettingsWritten)
        {
            controlStreamBytes = [];
            return false;
        }

        controlStreamBytes = Http3SettingsWriter.WriteInitialControlStream(localSettings);
        initialSettingsWritten = true;
        return true;
    }

    /// <summary>
    /// Captures peer SETTINGS from a validated SETTINGS frame.
    /// </summary>
    public void ReceivePeerSettings(Http3SettingsFrame settingsFrame)
    {
        ArgumentNullException.ThrowIfNull(settingsFrame);
        if (PeerSettings is not null)
        {
            throw new Http3Exception(Http3ErrorCode.FrameUnexpected, "HTTP/3 peer SETTINGS were received more than once.");
        }

        PeerSettings = settingsFrame.Values;
    }
}
