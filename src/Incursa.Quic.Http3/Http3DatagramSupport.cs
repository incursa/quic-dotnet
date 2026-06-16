// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Provides RFC 9297 HTTP Datagram negotiation and stream-limit helpers.
/// </summary>
public static class Http3DatagramSupport
{
    private const ulong StreamIdLowBitsMask = 0x03;

    /// <summary>
    /// Gets the maximum legal SETTINGS_H3_DATAGRAM value.
    /// </summary>
    public const ulong MaximumSettingsH3DatagramValue = 1;

    /// <summary>
    /// Gets the default SETTINGS_H3_DATAGRAM value.
    /// </summary>
    public const ulong DefaultSettingsH3DatagramValue = 0;

    /// <summary>
    /// Returns true when both endpoints have enabled HTTP/3 Datagrams.
    /// </summary>
    public static bool CanSendDatagram(Http3Settings localSettings, Http3Settings peerSettings)
    {
        ArgumentNullException.ThrowIfNull(localSettings);
        ArgumentNullException.ThrowIfNull(peerSettings);

        return localSettings.H3Datagram == 1 && peerSettings.H3Datagram == 1;
    }

    /// <summary>
    /// Validates that accepted 0-RTT SETTINGS_H3_DATAGRAM did not decrease from the stored value.
    /// </summary>
    public static void ValidateZeroRttSettings(ulong storedSettingsH3Datagram, ulong acceptedSettingsH3Datagram)
    {
        ValidateSettingsValue(storedSettingsH3Datagram);
        ValidateSettingsValue(acceptedSettingsH3Datagram);
        if (acceptedSettingsH3Datagram < storedSettingsH3Datagram)
        {
            throw new Http3Exception(Http3ErrorCode.SettingsError, "Accepted 0-RTT SETTINGS_H3_DATAGRAM must not decrease from the stored value.");
        }
    }

    /// <summary>
    /// Validates that an associated stream ID is within the peer's client-initiated bidirectional stream limit.
    /// </summary>
    public static void ValidateAssociatedStreamLimit(ulong associatedStreamId, ulong maximumClientInitiatedBidirectionalStreamId)
    {
        if ((associatedStreamId & StreamIdLowBitsMask) != 0 || associatedStreamId > maximumClientInitiatedBidirectionalStreamId)
        {
            throw new Http3Exception(Http3ErrorCode.IdError, "The HTTP Datagram maps to a stream that cannot be created.");
        }
    }

    private static void ValidateSettingsValue(ulong settingsH3Datagram)
    {
        if (settingsH3Datagram > MaximumSettingsH3DatagramValue)
        {
            throw new Http3Exception(Http3ErrorCode.SettingsError, "SETTINGS_H3_DATAGRAM must be 0 or 1.");
        }
    }
}
