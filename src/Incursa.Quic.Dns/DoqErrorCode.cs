// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// DNS over QUIC application error codes registered by RFC 9250.
/// </summary>
public enum DoqErrorCode : long
{
    /// <summary>
    /// No error occurred.
    /// </summary>
    NoError = 0x0,

    /// <summary>
    /// The endpoint encountered an internal error and cannot continue the transaction or connection.
    /// </summary>
    InternalError = 0x1,

    /// <summary>
    /// The endpoint encountered a DoQ protocol error and is aborting the connection.
    /// </summary>
    ProtocolError = 0x2,

    /// <summary>
    /// The client cancelled an outstanding transaction.
    /// </summary>
    RequestCancelled = 0x3,

    /// <summary>
    /// The endpoint is closing the connection because of excessive load.
    /// </summary>
    ExcessiveLoad = 0x4,

    /// <summary>
    /// No more specific DoQ error code applies.
    /// </summary>
    UnspecifiedError = 0x5,

    /// <summary>
    /// Reserved value available for tests.
    /// </summary>
    ErrorReserved = 0xd098ea5e,
}

/// <summary>
/// Provides DoQ error code utilities.
/// </summary>
public static class DoqErrorCodeExtensions
{
    /// <summary>
    /// Normalizes a received application error code for DoQ protocol handling.
    /// Unknown codes and codes used in unexpected contexts are mapped to <see cref="DoqErrorCode.UnspecifiedError"/>.
    /// </summary>
    /// <remarks>
    /// Per RFC 9250 Section 8.4, a DoQ client MAY use a more specific error code registered
    /// according to the IANA registry. The receiver MUST treat such registered codes as
    /// equivalent to the corresponding standard code (<see cref="DoqErrorCode.UnspecifiedError"/>
    /// for unrecognized values). This helper performs the normalization.
    /// </remarks>
    public static DoqErrorCode NormalizeReceivedErrorCode(long applicationErrorCode)
    {
        if (!Enum.IsDefined(typeof(DoqErrorCode), applicationErrorCode))
        {
            return DoqErrorCode.UnspecifiedError;
        }

        return (DoqErrorCode)applicationErrorCode;
    }
}
