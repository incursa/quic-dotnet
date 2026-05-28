namespace Incursa.Qpack;

/// <summary>
/// Represents QPACK field-section decode status for internal sink-based decode paths.
/// </summary>
internal readonly record struct QPackFieldSectionDecodeStatus(
    ulong StreamId,
    bool IsBlocked,
    ulong RequiredInsertCount);
