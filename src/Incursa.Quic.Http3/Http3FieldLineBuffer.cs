using System.Buffers;
using Incursa.Qpack;

namespace Incursa.Quic.Http3;

internal sealed class Http3FieldLineBuffer : IBufferWriter<QPackFieldLine>
{
    private const int DefaultInitialCapacity = 8;
    private QPackFieldLine[] buffer;
    private int written;
    private bool committed;

    public Http3FieldLineBuffer(int initialCapacity = DefaultInitialCapacity)
    {
        if (initialCapacity < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(initialCapacity));
        }

        buffer = initialCapacity == 0 ? [] : new QPackFieldLine[initialCapacity];
    }

    public void Advance(int count)
    {
        ThrowIfCommitted();
        if (count < 0 || written > buffer.Length - count)
        {
            throw new ArgumentOutOfRangeException(nameof(count));
        }

        written += count;
    }

    public Memory<QPackFieldLine> GetMemory(int sizeHint = 0)
    {
        ThrowIfCommitted();
        EnsureCapacity(sizeHint);
        return buffer.AsMemory(written);
    }

    public Span<QPackFieldLine> GetSpan(int sizeHint = 0)
    {
        ThrowIfCommitted();
        EnsureCapacity(sizeHint);
        return buffer.AsSpan(written);
    }

    public IReadOnlyList<QPackFieldLine> CommitToReadOnlyList()
    {
        ThrowIfCommitted();
        committed = true;
        return new Http3FieldLineList(buffer, written);
    }

    private void EnsureCapacity(int sizeHint)
    {
        if (sizeHint < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(sizeHint));
        }

        if (sizeHint == 0)
        {
            sizeHint = 1;
        }

        if (buffer.Length - written >= sizeHint)
        {
            return;
        }

        int newCapacity = buffer.Length == 0 ? DefaultInitialCapacity : buffer.Length * 2;
        int minimumCapacity = checked(written + sizeHint);
        if (newCapacity < minimumCapacity)
        {
            newCapacity = minimumCapacity;
        }

        Array.Resize(ref buffer, newCapacity);
    }

    private void ThrowIfCommitted()
    {
        if (committed)
        {
            throw new InvalidOperationException("The HTTP/3 field-line buffer has already been committed.");
        }
    }
}

internal sealed class Http3FieldLineList : IReadOnlyList<QPackFieldLine>
{
    private readonly QPackFieldLine[] fields;

    public Http3FieldLineList(QPackFieldLine[] fields, int count)
    {
        ArgumentNullException.ThrowIfNull(fields);
        if ((uint)count > (uint)fields.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(count));
        }

        this.fields = fields;
        Count = count;
    }

    public int Count { get; }

    public QPackFieldLine this[int index]
    {
        get
        {
            if ((uint)index >= (uint)Count)
            {
                throw new ArgumentOutOfRangeException(nameof(index));
            }

            return fields[index];
        }
    }

    public IEnumerator<QPackFieldLine> GetEnumerator()
    {
        for (int index = 0; index < Count; index++)
        {
            yield return fields[index];
        }
    }

    System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
}
