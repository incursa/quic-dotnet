namespace Incursa.Quic;

internal readonly record struct QuicConnectionRuntimeRoute(
    int ShardIndex,
    QuicConnectionRuntime Runtime);

internal readonly record struct QuicConnectionRuntimeShardWorkItem(
    QuicConnectionHandle Handle,
    QuicConnectionRuntime Runtime,
    QuicConnectionEvent ConnectionEvent);
