// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Provides RFC 9297 HTTP Datagram lifecycle policy decisions.
/// </summary>
public static class Http3DatagramLifecycle
{
    /// <summary>
    /// Selects the action for sending an HTTP/3 Datagram.
    /// </summary>
    public static Http3DatagramLifecycleDecision SelectSendAction(
        bool requestSupportsHttpDatagrams,
        bool sendSideOpen,
        bool extensionOverridesHttpDatagramRequirements = false)
    {
        if (!sendSideOpen)
        {
            return new Http3DatagramLifecycleDecision(Http3DatagramLifecycleAction.DropSilently);
        }

        if (requestSupportsHttpDatagrams || extensionOverridesHttpDatagramRequirements)
        {
            return new Http3DatagramLifecycleDecision(Http3DatagramLifecycleAction.Send);
        }

        return new Http3DatagramLifecycleDecision(Http3DatagramLifecycleAction.AbortRequestStream, Http3ErrorCode.DatagramError);
    }

    /// <summary>
    /// Selects the action for a received HTTP/3 Datagram.
    /// </summary>
    public static Http3DatagramLifecycleDecision SelectReceiveAction(
        bool requestSupportsHttpDatagrams,
        bool receiveSideOpen,
        bool associatedStreamCreated,
        bool associatedStreamCanBeCreated,
        bool extensionOverridesHttpDatagramRequirements = false,
        bool bufferUncreatedStreams = false)
    {
        if (!receiveSideOpen)
        {
            return new Http3DatagramLifecycleDecision(Http3DatagramLifecycleAction.DropSilently);
        }

        if (!associatedStreamCreated)
        {
            if (!associatedStreamCanBeCreated)
            {
                return new Http3DatagramLifecycleDecision(Http3DatagramLifecycleAction.AbortRequestStream, Http3ErrorCode.IdError);
            }

            return new Http3DatagramLifecycleDecision(
                bufferUncreatedStreams ? Http3DatagramLifecycleAction.BufferTemporarily : Http3DatagramLifecycleAction.DropSilently);
        }

        if (requestSupportsHttpDatagrams || extensionOverridesHttpDatagramRequirements)
        {
            return new Http3DatagramLifecycleDecision(Http3DatagramLifecycleAction.Accept);
        }

        return new Http3DatagramLifecycleDecision(Http3DatagramLifecycleAction.AbortRequestStream, Http3ErrorCode.DatagramError);
    }

    /// <summary>
    /// Returns true when an HTTP/1.x request can start the Capsule Protocol.
    /// </summary>
    public static bool CanStartCapsuleProtocolOnHttp1(bool isLastRequestOnConnection)
    {
        return isLastRequestOnConnection;
    }

    /// <summary>
    /// Returns true when a data stream is subject to the underlying flow-control layers.
    /// </summary>
    public static bool DataStreamUsesUnderlyingFlowControl(bool connectionFlowControlEnabled, bool streamFlowControlEnabled)
    {
        return connectionFlowControlEnabled && streamFlowControlEnabled;
    }
}
