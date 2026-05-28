// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Writes HTTP/3 SETTINGS frames and initial control-stream bytes.
/// </summary>
public static class Http3SettingsWriter
{
    /// <summary>
    /// Writes a SETTINGS frame from typed settings.
    /// </summary>
    public static byte[] WriteSettingsFrame(Http3Settings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        return Http3FrameWriter.WriteSettings(settings.ToSettingList());
    }

    /// <summary>
    /// Writes the initial bytes for a newly created HTTP/3 control stream: stream type followed by SETTINGS.
    /// </summary>
    public static byte[] WriteInitialControlStream(Http3Settings settings)
    {
        byte[] settingsFrame = WriteSettingsFrame(settings);
        byte[] result = new byte[settingsFrame.Length + 1];
        result[0] = (byte)Http3StreamType.Control;
        settingsFrame.CopyTo(result.AsSpan(1));
        return result;
    }
}
