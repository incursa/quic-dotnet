// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Qpack;

/// <summary>
/// Represents the result of decoding or blocking a QPACK field section.
/// </summary>
public sealed class QPackFieldSectionDecodeResult
{
    internal QPackFieldSectionDecodeResult(
        ulong streamId,
        bool isBlocked,
        ulong requiredInsertCount,
        QPackFieldLine[] fieldLines)
    {
        StreamId = streamId;
        IsBlocked = isBlocked;
        RequiredInsertCount = requiredInsertCount;
        FieldLines = fieldLines;
    }

    /// <summary>
    /// Gets the stream that carried the encoded field section.
    /// </summary>
    public ulong StreamId { get; }

    /// <summary>
    /// Gets a value indicating whether the field section is blocked on dynamic table state.
    /// </summary>
    public bool IsBlocked { get; }

    /// <summary>
    /// Gets the Required Insert Count decoded from the field section prefix.
    /// </summary>
    public ulong RequiredInsertCount { get; }

    /// <summary>
    /// Gets decoded field lines when <see cref="IsBlocked" /> is false.
    /// </summary>
    public QPackFieldLine[] FieldLines { get; }
}
