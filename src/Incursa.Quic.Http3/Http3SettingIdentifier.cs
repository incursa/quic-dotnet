// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Known HTTP/3 SETTINGS identifiers.
/// </summary>
public enum Http3SettingIdentifier : long
{
    /// <summary>
    /// SETTINGS_QPACK_MAX_TABLE_CAPACITY.
    /// </summary>
    QPackMaxTableCapacity = 0x01,

    /// <summary>
    /// SETTINGS_MAX_FIELD_SECTION_SIZE.
    /// </summary>
    MaxFieldSectionSize = 0x06,

    /// <summary>
    /// SETTINGS_QPACK_BLOCKED_STREAMS.
    /// </summary>
    QPackBlockedStreams = 0x07,

    /// <summary>
    /// SETTINGS_ENABLE_CONNECT_PROTOCOL.
    /// </summary>
    EnableConnectProtocol = 0x08,
}
