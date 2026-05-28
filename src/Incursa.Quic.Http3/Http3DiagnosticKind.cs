// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Identifies HTTP/3 diagnostic events that can be adapted to qlog or other debug sinks.
/// </summary>
public enum Http3DiagnosticKind
{
    /// <summary>
    /// An HTTP/3 connection started.
    /// </summary>
    ConnectionStarted,

    /// <summary>
    /// An HTTP/3 connection closed.
    /// </summary>
    ConnectionClosed,

    /// <summary>
    /// SETTINGS was sent.
    /// </summary>
    SettingsSent,

    /// <summary>
    /// SETTINGS was received.
    /// </summary>
    SettingsReceived,

    /// <summary>
    /// An HTTP/3 stream opened.
    /// </summary>
    StreamOpened,

    /// <summary>
    /// An HTTP/3 stream closed.
    /// </summary>
    StreamClosed,

    /// <summary>
    /// An HTTP/3 frame was sent.
    /// </summary>
    FrameSent,

    /// <summary>
    /// An HTTP/3 frame was received.
    /// </summary>
    FrameReceived,

    /// <summary>
    /// A QPACK instruction was sent.
    /// </summary>
    QPackInstructionSent,

    /// <summary>
    /// A QPACK instruction was received.
    /// </summary>
    QPackInstructionReceived,

    /// <summary>
    /// A request lifecycle started.
    /// </summary>
    RequestStarted,

    /// <summary>
    /// A request lifecycle completed.
    /// </summary>
    RequestCompleted,

    /// <summary>
    /// A response lifecycle started.
    /// </summary>
    ResponseStarted,

    /// <summary>
    /// A response lifecycle completed.
    /// </summary>
    ResponseCompleted,

    /// <summary>
    /// An HTTP/3 or QPACK error was observed.
    /// </summary>
    Error,
}
