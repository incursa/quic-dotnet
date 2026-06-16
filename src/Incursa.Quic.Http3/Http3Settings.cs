// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Represents typed HTTP/3 SETTINGS values.
/// </summary>
public sealed class Http3Settings
{
    /// <summary>
    /// Initializes a new instance of the <see cref="Http3Settings" /> class.
    /// </summary>
    public Http3Settings(
        ulong qpackMaxTableCapacity = 0,
        ulong qpackBlockedStreams = 0,
        ulong? maxFieldSectionSize = null,
        ulong enableConnectProtocol = 0)
    {
        QPackMaxTableCapacity = qpackMaxTableCapacity;
        QPackBlockedStreams = qpackBlockedStreams;
        MaxFieldSectionSize = maxFieldSectionSize;
        EnableConnectProtocol = enableConnectProtocol;
    }

    /// <summary>
    /// Gets SETTINGS_QPACK_MAX_TABLE_CAPACITY. The default is zero.
    /// </summary>
    public ulong QPackMaxTableCapacity { get; }

    /// <summary>
    /// Gets SETTINGS_QPACK_BLOCKED_STREAMS. The default is zero.
    /// </summary>
    public ulong QPackBlockedStreams { get; }

    /// <summary>
    /// Gets SETTINGS_MAX_FIELD_SECTION_SIZE. A null value means unlimited.
    /// </summary>
    public ulong? MaxFieldSectionSize { get; }

    /// <summary>
    /// Gets SETTINGS_ENABLE_CONNECT_PROTOCOL. The default is zero.
    /// </summary>
    public ulong EnableConnectProtocol { get; }

    /// <summary>
    /// Validates a field section size against SETTINGS_MAX_FIELD_SECTION_SIZE when it is present.
    /// </summary>
    public void ValidateFieldSectionSize(ulong fieldSectionSize)
    {
        if (MaxFieldSectionSize.HasValue && fieldSectionSize > MaxFieldSectionSize.Value)
        {
            throw new Http3Exception(Http3ErrorCode.ExcessiveLoad, "The HTTP/3 field section exceeds SETTINGS_MAX_FIELD_SECTION_SIZE.");
        }
    }

    internal IReadOnlyList<Http3Setting> ToSettingList()
    {
        List<Http3Setting> settings = [];
        if (QPackMaxTableCapacity != 0)
        {
            settings.Add(new Http3Setting((ulong)Http3SettingIdentifier.QPackMaxTableCapacity, QPackMaxTableCapacity));
        }

        if (MaxFieldSectionSize.HasValue)
        {
            settings.Add(new Http3Setting((ulong)Http3SettingIdentifier.MaxFieldSectionSize, MaxFieldSectionSize.Value));
        }

        if (QPackBlockedStreams != 0)
        {
            settings.Add(new Http3Setting((ulong)Http3SettingIdentifier.QPackBlockedStreams, QPackBlockedStreams));
        }

        if (EnableConnectProtocol != 0)
        {
            settings.Add(new Http3Setting((ulong)Http3SettingIdentifier.EnableConnectProtocol, EnableConnectProtocol));
        }

        return settings;
    }
}
