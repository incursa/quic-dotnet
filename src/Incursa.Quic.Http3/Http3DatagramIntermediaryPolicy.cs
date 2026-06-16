// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Provides RFC 9297 DATAGRAM Capsule intermediary and buffering policy.
/// </summary>
public static class Http3DatagramIntermediaryPolicy
{
    /// <summary>
    /// Returns true when implementations should stream Capsule Values instead of buffering complete values before handling.
    /// </summary>
    public static bool ShouldAvoidFullCapsuleValueBuffering => true;

    /// <summary>
    /// Returns true when implementations should avoid accumulating a complete DATAGRAM Capsule before re-encoding it.
    /// </summary>
    public static bool ShouldAvoidFullDatagramCapsuleAccumulation => true;

    /// <summary>
    /// Selects an intermediary forwarding action for an HTTP Datagram or DATAGRAM Capsule.
    /// </summary>
    public static Http3DatagramIntermediaryAction SelectForwardingAction(
        bool capsuleProtocolIdentified,
        bool incomingDatagramFrame,
        bool outgoingSupportsDatagramFrames,
        bool datagramFitsOutgoingFrame,
        bool extensionLimitsAllowPayload)
    {
        if (!capsuleProtocolIdentified)
        {
            return Http3DatagramIntermediaryAction.RequireCapsuleProtocolIdentification;
        }

        if (!extensionLimitsAllowPayload)
        {
            return Http3DatagramIntermediaryAction.Drop;
        }

        if (outgoingSupportsDatagramFrames)
        {
            if (!datagramFitsOutgoingFrame)
            {
                return Http3DatagramIntermediaryAction.Drop;
            }

            return incomingDatagramFrame
                ? Http3DatagramIntermediaryAction.ForwardAsDatagramFrame
                : Http3DatagramIntermediaryAction.ReencodeAsDatagramFrame;
        }

        return Http3DatagramIntermediaryAction.ReencodeAsDatagramCapsule;
    }

    /// <summary>
    /// Validates that a Capsule payload has the declared fields and redundant length values agree.
    /// </summary>
    public static void ValidateCapsulePayloadLength(ulong declaredLength, ulong actualLength, ulong? redundantLength = null)
    {
        if (declaredLength != actualLength)
        {
            throw Malformed("The Capsule payload length does not match the fields defined by the Capsule type.");
        }

        if (redundantLength.HasValue && redundantLength.Value != actualLength)
        {
            throw Malformed("The Capsule payload redundant length encoding is not self-consistent.");
        }
    }

    /// <summary>
    /// Parses a DATAGRAM Capsule payload with HTTP Datagram semantics.
    /// </summary>
    public static Http3Datagram ParseDatagramCapsulePayload(ReadOnlySpan<byte> payload)
    {
        return Http3Datagram.Parse(payload);
    }

    /// <summary>
    /// Returns true when a DATAGRAM Capsule length is known to be unusable for the extension.
    /// </summary>
    public static bool IsKnownUnusableDatagramCapsuleLength(ulong capsuleLength, ulong maximumExtensionPayloadLength)
    {
        return capsuleLength > maximumExtensionPayloadLength;
    }

    /// <summary>
    /// Returns true when new HTTP extensions that use HTTP Datagrams should use the Capsule Protocol.
    /// </summary>
    public static bool NewHttpExtensionShouldUseCapsuleProtocol(bool usesHttpDatagrams)
    {
        return usesHttpDatagrams;
    }

    private static Http3Exception Malformed(string message)
    {
        return new Http3Exception(Http3ErrorCode.MessageError, message);
    }
}
