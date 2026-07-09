// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers;

namespace Incursa.Quic;

// CONTEXT: Additional ACK ranges can be pooled and owned or copied into a non-owning view, so the
// frame type keeps explicit ownership state to avoid returning borrowed arrays to ArrayPool twice.
// SEE: SetOwnedAdditionalRanges and AdditionalRanges
/// <summary>
/// A parsed or constructed ACK frame view.
/// </summary>
internal sealed class QuicAckFrame : IDisposable
{
    [ThreadStatic]
    private static QuicAckFrame? pooledFrame;

    private QuicAckRange[] additionalRanges = [];
    private int additionalRangeCount;
    private bool ownsAdditionalRanges;
    private bool returnToPool;

    /// <summary>
    /// Rents an ACK frame instance for hot runtime parse/build paths.
    /// </summary>
    internal static QuicAckFrame Rent()
    {
        QuicAckFrame? frame = pooledFrame;
        if (frame is null)
        {
            frame = new QuicAckFrame();
        }
        else
        {
            pooledFrame = null;
        }

        frame.returnToPool = true;
        return frame;
    }

    /// <summary>
    /// Gets or sets the ACK frame type. Valid values are 0x02 and 0x03.
    /// </summary>
    internal byte FrameType { get; set; }

    /// <summary>
    /// Gets or sets the Largest Acknowledged field.
    /// </summary>
    internal ulong LargestAcknowledged { get; set; }

    /// <summary>
    /// Gets or sets the ACK Delay field.
    /// </summary>
    internal ulong AckDelay { get; set; }

    /// <summary>
    /// Gets or sets the First ACK Range field.
    /// </summary>
    internal ulong FirstAckRange { get; set; }

    /// <summary>
    /// Gets or sets the additional ACK Ranges after the first ACK Range.
    /// </summary>
    internal QuicAckRange[] AdditionalRanges
    {
        get
        {
            if (additionalRangeCount == additionalRanges.Length)
            {
                return additionalRanges;
            }

            if (additionalRangeCount == 0)
            {
                return [];
            }

            return additionalRanges.AsSpan(0, additionalRangeCount).ToArray();
        }

        set
        {
            ReleaseOwnedAdditionalRanges();
            additionalRanges = value ?? [];
            additionalRangeCount = additionalRanges.Length;
        }
    }

    /// <summary>
    /// Gets the additional ACK ranges as a non-allocating logical slice.
    /// </summary>
    internal ReadOnlySpan<QuicAckRange> AdditionalRangeSpan => additionalRanges.AsSpan(0, additionalRangeCount);

    /// <summary>
    /// Gets the number of additional ACK ranges as a signed count.
    /// </summary>
    internal int AdditionalRangeCount => additionalRangeCount;

    /// <summary>
    /// Gets or sets the optional ECN counters carried by ACK frame type 0x03.
    /// </summary>
    internal QuicEcnCounts? EcnCounts { get; set; }

    /// <summary>
    /// Gets the number of additional ACK Ranges.
    /// </summary>
    internal ulong AckRangeCount => (ulong)additionalRangeCount;

    /// <summary>
    /// Gets an additional ACK range by logical index.
    /// </summary>
    internal QuicAckRange GetAdditionalRange(int index)
    {
        if ((uint)index >= (uint)additionalRangeCount)
        {
            throw new ArgumentOutOfRangeException(nameof(index));
        }

        return additionalRanges[index];
    }

    /// <summary>
    /// Takes ownership of a pooled additional range buffer.
    /// </summary>
    internal void SetOwnedAdditionalRanges(QuicAckRange[] ranges, int count)
    {
        ArgumentNullException.ThrowIfNull(ranges);
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        if (count > ranges.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(count));
        }

        ReleaseOwnedAdditionalRanges();
        additionalRanges = ranges;
        additionalRangeCount = count;
        ownsAdditionalRanges = true;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        ReleaseOwnedAdditionalRanges();
        ResetFields();

        if (!returnToPool)
        {
            return;
        }

        returnToPool = false;
        ReturnToPool(this);
    }

    private static void ReturnToPool(QuicAckFrame frame)
    {
        pooledFrame ??= frame;
    }

    private void ReleaseOwnedAdditionalRanges()
    {
        if (ownsAdditionalRanges)
        {
            ArrayPool<QuicAckRange>.Shared.Return(additionalRanges);
        }

        additionalRanges = [];
        additionalRangeCount = 0;
        ownsAdditionalRanges = false;
    }

    private void ResetFields()
    {
        FrameType = default;
        LargestAcknowledged = default;
        AckDelay = default;
        FirstAckRange = default;
        EcnCounts = null;
    }
}
