// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Parses and validates HTTP/3 SETTINGS payload entries.
/// </summary>
public static class Http3SettingsParser
{
    private const ulong ReservedHttp3SettingsIdentifier = 0x00;
    private const ulong ReservedHttp2EnablePushIdentifier = 0x02;
    private const ulong ReservedHttp2MaxConcurrentStreamsIdentifier = 0x03;
    private const ulong ReservedHttp2InitialWindowSizeIdentifier = 0x04;
    private const ulong ReservedHttp2MaxFrameSizeIdentifier = 0x05;

    /// <summary>
    /// Parses SETTINGS entries into typed known values while ignoring unknown allowed settings.
    /// </summary>
    public static Http3Settings Parse(IEnumerable<Http3Setting> settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        HashSet<ulong> identifiers = [];
        ulong qpackMaxTableCapacity = 0;
        ulong qpackBlockedStreams = 0;
        ulong? maxFieldSectionSize = null;
        ulong enableConnectProtocol = 0;
        ulong h3Datagram = 0;

        foreach (Http3Setting setting in settings)
        {
            ValidateIdentifier(setting.Identifier);
            if (!identifiers.Add(setting.Identifier))
            {
                throw new Http3Exception(Http3ErrorCode.SettingsError, "The HTTP/3 SETTINGS frame contains a duplicate identifier.");
            }

            switch (setting.Identifier)
            {
                case (ulong)Http3SettingIdentifier.QPackMaxTableCapacity:
                    qpackMaxTableCapacity = setting.Value;
                    break;
                case (ulong)Http3SettingIdentifier.MaxFieldSectionSize:
                    maxFieldSectionSize = setting.Value;
                    break;
                case (ulong)Http3SettingIdentifier.QPackBlockedStreams:
                    qpackBlockedStreams = setting.Value;
                    break;
                case (ulong)Http3SettingIdentifier.EnableConnectProtocol:
                    enableConnectProtocol = setting.Value;
                    break;
                case (ulong)Http3SettingIdentifier.H3Datagram:
                    if (setting.Value > Http3DatagramSupport.MaximumSettingsH3DatagramValue)
                    {
                        throw new Http3Exception(Http3ErrorCode.SettingsError, "SETTINGS_H3_DATAGRAM must be 0 or 1.");
                    }

                    h3Datagram = setting.Value;
                    break;
            }
        }

        return new Http3Settings(qpackMaxTableCapacity, qpackBlockedStreams, maxFieldSectionSize, enableConnectProtocol, h3Datagram);
    }

    /// <summary>
    /// Validates that a SETTINGS identifier can appear on HTTP/3.
    /// </summary>
    public static void ValidateIdentifier(ulong identifier)
    {
        if (identifier is ReservedHttp3SettingsIdentifier
            or ReservedHttp2EnablePushIdentifier
            or ReservedHttp2MaxConcurrentStreamsIdentifier
            or ReservedHttp2InitialWindowSizeIdentifier
            or ReservedHttp2MaxFrameSizeIdentifier)
        {
            throw new Http3Exception(Http3ErrorCode.SettingsError, "The HTTP/3 SETTINGS identifier is reserved or forbidden.");
        }
    }
}
