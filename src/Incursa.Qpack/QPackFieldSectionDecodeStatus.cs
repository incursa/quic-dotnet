// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Qpack;

/// <summary>
/// Represents QPACK field-section decode status for internal sink-based decode paths.
/// </summary>
internal readonly record struct QPackFieldSectionDecodeStatus(
    ulong StreamId,
    bool IsBlocked,
    ulong RequiredInsertCount);
