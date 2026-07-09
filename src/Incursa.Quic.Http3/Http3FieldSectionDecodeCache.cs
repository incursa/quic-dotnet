// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics.CodeAnalysis;
using Incursa.Qpack;

namespace Incursa.Quic.Http3;

internal sealed class Http3FieldSectionDecodeCache
{
    private const int CacheSize = 16;
    private const int MaximumCachedEncodedLength = 256;
    private const int MaximumCachedFieldCount = 32;
    private const ulong FnvOffsetBasis = 14695981039346656037UL;
    private const ulong FnvPrime = 1099511628211UL;

    private readonly Entry[] entries = new Entry[CacheSize];
    private int nextIndex;

    public bool TryGet(
        ReadOnlySpan<byte> encodedFieldSection,
        [NotNullWhen(true)] out IReadOnlyList<QPackFieldLine>? fields)
    {
        if (!IsCacheable(encodedFieldSection))
        {
            fields = null;
            return false;
        }

        ulong hash = ComputeHash(encodedFieldSection);
        for (int index = 0; index < entries.Length; index++)
        {
            Entry entry = entries[index];
            if (entry.Hash == hash
                && entry.Encoded is byte[] encoded
                && encodedFieldSection.SequenceEqual(encoded)
                && entry.Fields is IReadOnlyList<QPackFieldLine> cachedFields)
            {
                fields = cachedFields;
                return true;
            }
        }

        fields = null;
        return false;
    }

    public void Store(ReadOnlySpan<byte> encodedFieldSection, IReadOnlyList<QPackFieldLine> fields)
    {
        ArgumentNullException.ThrowIfNull(fields);
        if (!IsCacheable(encodedFieldSection) || fields.Count > MaximumCachedFieldCount)
        {
            return;
        }

        entries[nextIndex] = new Entry(encodedFieldSection.ToArray(), ComputeHash(encodedFieldSection), fields);
        nextIndex = (nextIndex + 1) % entries.Length;
    }

    private static bool IsCacheable(ReadOnlySpan<byte> encodedFieldSection)
    {
        return encodedFieldSection.Length is > 0 and <= MaximumCachedEncodedLength
            && encodedFieldSection[0] == 0;
    }

    private static ulong ComputeHash(ReadOnlySpan<byte> source)
    {
        ulong hash = FnvOffsetBasis;
        for (int index = 0; index < source.Length; index++)
        {
            hash ^= source[index];
            hash *= FnvPrime;
        }

        return hash == 0 ? 1 : hash;
    }

    private readonly record struct Entry(byte[]? Encoded, ulong Hash, IReadOnlyList<QPackFieldLine>? Fields);
}
