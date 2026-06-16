// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Describes how an Extended CONNECT tunnel closure maps to an HTTP/3 stream action.
/// </summary>
public readonly struct Http3ExtendedConnectClosure
{
    internal Http3ExtendedConnectClosure(bool finishStream, Http3ErrorCode? resetErrorCode)
    {
        FinishStream = finishStream;
        ResetErrorCode = resetErrorCode;
    }

    /// <summary>
    /// Gets whether the stream should be finished with FIN.
    /// </summary>
    public bool FinishStream { get; }

    /// <summary>
    /// Gets the stream reset error code, when the closure is abnormal.
    /// </summary>
    public Http3ErrorCode? ResetErrorCode { get; }
}
