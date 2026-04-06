namespace Incursa.Quic;

/// <summary>
/// Tracks RFC 9000 flow-control limits and byte-credit accounting for a single helper view.
/// </summary>
public sealed class QuicFlowControlState
{
    /// <summary>
    /// Flow-control counters are encoded in variable-length integers with a 62-bit maximum.
    /// </summary>
    private const ulong MaximumStreamLimit = 1UL << 60;

    private ulong _connectionData;
    private ulong _maximumData;
    private ulong _maximumStreamData;
    private ulong _connectionDataSent;
    private ulong _maximumStreamsBidi;
    private ulong _maximumStreamsUni;

    private readonly Dictionary<ulong, ulong> _streamMaximumData = [];
    private readonly Dictionary<ulong, ulong> _streamDataSent = [];

    /// <summary>
    /// Initializes flow-control accounting with RFC 9000 initial connection-wide and stream-count limits.
    /// </summary>
    public QuicFlowControlState(
        ulong initialMaximumData = 0,
        ulong initialMaximumStreamsBidi = 0,
        ulong initialMaximumStreamsUni = 0)
    {
        _maximumData = initialMaximumData;
        _maximumStreamsBidi = initialMaximumStreamsBidi;
        _maximumStreamsUni = initialMaximumStreamsUni;
    }

    /// <summary>
    /// Gets the current connection-wide maximum data credit.
    /// </summary>
    public ulong MaximumData => _maximumData;

    /// <summary>
    /// Gets the total amount of connection data sent so far.
    /// </summary>
    public ulong ConnectionDataSent => _connectionDataSent;

    /// <summary>
    /// Gets the maximum number of bidirectional streams that may be opened.
    /// </summary>
    public ulong MaximumStreamsBidi => _maximumStreamsBidi;

    /// <summary>
    /// Gets the maximum number of unidirectional streams that may be opened.
    /// </summary>
    public ulong MaximumStreamsUni => _maximumStreamsUni;

    /// <summary>
    /// Gets whether a bidirectional stream limit has been set to zero.
    /// </summary>
    public bool IsBidirectionalStreamLimitExceeded => _maximumStreamsBidi == 0;

    /// <summary>
    /// Gets whether a unidirectional stream limit has been set to zero.
    /// </summary>
    public bool IsUnidirectionalStreamLimitExceeded => _maximumStreamsUni == 0;

    /// <summary>
    /// Applies a MAX_DATA credit update.
    /// </summary>
    public bool TryApplyMaxDataFrame(QuicMaxDataFrame frame)
    {
        if (_maximumData < frame.MaximumData)
        {
            _maximumData = frame.MaximumData;
            return true;
        }

        return false;
    }

    /// <summary>
    /// Applies a MAX_STREAM_DATA credit update.
    /// </summary>
    public bool TryApplyMaxStreamDataFrame(QuicMaxStreamDataFrame frame)
    {
        if (_streamMaximumData.TryGetValue(frame.StreamId, out ulong prior) && prior >= frame.MaximumStreamData)
        {
            return false;
        }

        _streamMaximumData[frame.StreamId] = frame.MaximumStreamData;
        return true;
    }

    /// <summary>
    /// Applies a MAX_STREAMS credit update.
    /// </summary>
    public bool TryApplyMaxStreamsFrame(QuicMaxStreamsFrame frame)
    {
        if (frame.MaximumStreams > MaximumStreamLimit)
        {
            return false;
        }

        ref ulong target = ref (frame.IsBidirectional ? ref _maximumStreamsBidi : ref _maximumStreamsUni);
        if (frame.MaximumStreams > target)
        {
            target = frame.MaximumStreams;
            return true;
        }

        return false;
    }

    /// <summary>
    /// Gets the current maximum stream-data credit for a stream.
    /// </summary>
    public ulong GetStreamMaximumData(ulong streamId)
    {
        if (_streamMaximumData.TryGetValue(streamId, out ulong limit))
        {
            return limit;
        }

        return 0;
    }

    /// <summary>
    /// Attempts to account for a connection-wide data send.
    /// </summary>
    public bool TrySendConnectionData(ulong dataToSend, out QuicDataBlockedFrame blockedFrame)
    {
        if (_connectionDataSent > ulong.MaxValue - dataToSend)
        {
            blockedFrame = new QuicDataBlockedFrame(_maximumData);
            return false;
        }

        ulong projected = checked(_connectionDataSent + dataToSend);
        if (_maximumData != 0 && projected > _maximumData)
        {
            blockedFrame = new QuicDataBlockedFrame(_maximumData);
            return false;
        }

        _connectionDataSent = projected;
        blockedFrame = new QuicDataBlockedFrame(_maximumData);
        return true;
    }

    /// <summary>
    /// Attempts to account for stream data send.
    /// </summary>
    public bool TrySendStreamData(ulong streamId, ulong dataToSend, out QuicStreamDataBlockedFrame blockedFrame)
    {
        if (!_streamMaximumData.TryGetValue(streamId, out ulong maximumStreamData) || maximumStreamData == 0)
        {
            blockedFrame = default;
            return true;
        }

        ulong sent = _streamDataSent.GetValueOrDefault(streamId);
        if (sent > ulong.MaxValue - dataToSend)
        {
            blockedFrame = new QuicStreamDataBlockedFrame(streamId, maximumStreamData);
            return false;
        }

        ulong projected = sent + dataToSend;
        if (projected > maximumStreamData)
        {
            blockedFrame = new QuicStreamDataBlockedFrame(streamId, maximumStreamData);
            return false;
        }

        _streamDataSent[streamId] = projected;
        blockedFrame = new QuicStreamDataBlockedFrame(streamId, _maximumStreamData);
        return true;
    }

    /// <summary>
    /// Updates an externally provided stream credit, including any explicit reset value.
    /// </summary>
    public void SetStreamCredit(ulong streamId, ulong maximumStreamData)
    {
        _streamMaximumData[streamId] = maximumStreamData;
    }
}
