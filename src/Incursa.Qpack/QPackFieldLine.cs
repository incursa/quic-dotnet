// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Qpack;

/// <summary>
/// Represents one HTTP field line in an ordered QPACK field section.
/// </summary>
public readonly record struct QPackFieldLine
{
    /// <summary>
    /// Initializes a new instance of the <see cref="QPackFieldLine"/> struct.
    /// </summary>
    public QPackFieldLine(string name, string? value)
    {
        Name = name ?? throw new ArgumentNullException(nameof(name));
        Value = value ?? string.Empty;
    }

    /// <summary>
    /// Gets the field name.
    /// </summary>
    public string Name { get; }

    /// <summary>
    /// Gets the field value.
    /// </summary>
    public string Value { get; }
}
