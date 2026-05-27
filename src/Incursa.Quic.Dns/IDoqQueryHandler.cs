namespace Incursa.Quic.Dns;

/// <summary>
/// Handles DNS over QUIC queries delivered by <see cref="DoqServer"/>.
/// </summary>
public interface IDoqQueryHandler
{
    /// <summary>
    /// Handles one DNS query and returns the response payload to write on the same QUIC stream.
    /// </summary>
    ValueTask<DoqQueryResult> HandleAsync(DoqQueryContext context, CancellationToken cancellationToken = default);
}
