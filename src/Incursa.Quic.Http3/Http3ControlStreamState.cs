// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Validates frame sequencing on an HTTP/3 control stream.
/// </summary>
public sealed class Http3ControlStreamState
{
    /// <summary>
    /// Gets a value indicating whether the first SETTINGS frame has been received.
    /// </summary>
    public bool SettingsReceived { get; private set; }

    /// <summary>
    /// Gets the peer SETTINGS received on this control stream.
    /// </summary>
    public Http3Settings? PeerSettings { get; private set; }

    /// <summary>
    /// Processes a control-stream frame.
    /// </summary>
    public void ReceiveFrame(Http3Frame frame)
    {
        ArgumentNullException.ThrowIfNull(frame);

        if (!IsAllowedControlFrame(frame))
        {
            throw new Http3Exception(Http3ErrorCode.FrameUnexpected, "The HTTP/3 frame is not allowed on the control stream.");
        }

        if (!SettingsReceived)
        {
            if (frame is not Http3SettingsFrame)
            {
                throw new Http3Exception(Http3ErrorCode.MissingSettings, "The first HTTP/3 control-stream frame must be SETTINGS.");
            }

            Http3SettingsFrame settingsFrame = (Http3SettingsFrame)frame;
            PeerSettings = settingsFrame.Values;
            SettingsReceived = true;
            return;
        }

        if (frame is Http3SettingsFrame)
        {
            throw new Http3Exception(Http3ErrorCode.FrameUnexpected, "Only one HTTP/3 SETTINGS frame is allowed on a control stream.");
        }
    }

    internal static bool IsAllowedControlFrame(Http3Frame frame)
    {
        return frame is Http3SettingsFrame
            or Http3CancelPushFrame
            or Http3GoAwayFrame
            or Http3MaxPushIdFrame
            or Http3UnknownFrame;
    }
}
