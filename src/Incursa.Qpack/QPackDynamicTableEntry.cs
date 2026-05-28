// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Qpack;

/// <summary>
/// Represents one entry stored in the QPACK dynamic table.
/// </summary>
public readonly record struct QPackDynamicTableEntry
{
    /// <summary>
    /// Initializes a new instance of the <see cref="QPackDynamicTableEntry" /> struct.
    /// </summary>
    public QPackDynamicTableEntry(ulong absoluteIndex, QPackFieldLine fieldLine, int size)
    {
        AbsoluteIndex = absoluteIndex;
        FieldLine = fieldLine;
        Size = size;
    }

    /// <summary>
    /// Gets the entry's absolute index.
    /// </summary>
    public ulong AbsoluteIndex { get; }

    /// <summary>
    /// Gets the field line stored by the entry.
    /// </summary>
    public QPackFieldLine FieldLine { get; }

    /// <summary>
    /// Gets the entry size defined by RFC 9204.
    /// </summary>
    public int Size { get; }
}
