namespace Incursa.Quic;

/// <summary>
/// Authenticated QUIC version information exchanged in transport parameters.
/// </summary>
internal sealed class QuicVersionInformation
{
    /// <summary>
    /// Gets or sets the version chosen for the connection.
    /// </summary>
    internal uint ChosenVersion { get; set; }

    /// <summary>
    /// Gets or sets the versions the sender says are available.
    /// </summary>
    internal uint[] AvailableVersions { get; set; } = [];
}
