namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-API-0007")]
public sealed class REQ_QUIC_API_0007
{
    private static readonly Type[] NamedInternalSeamTypes =
    [
        typeof(QuicTlsTranscriptProgress),
        typeof(QuicTlsKeySchedule),
        typeof(QuicTransportTlsBridgeState),
        typeof(QuicHandshakeFlowCoordinator),
        typeof(QuicInitialPacketProtection),
        typeof(QuicHandshakePacketProtection),
        typeof(QuicTlsPacketProtectionMaterial),
        typeof(QuicConnectionRuntime),
        typeof(QuicConnectionRuntimeHost),
        typeof(QuicListenerHost),
        typeof(QuicConnectionRuntimeShard),
        typeof(QuicConnectionSendRuntime),
        typeof(QuicConnectionRuntimeEndpoint),
        typeof(QuicConnectionEndpointHost),
        typeof(QuicClientConnectionHost),
        typeof(QuicClientConnectionOptionsValidator),
    ];

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void NamedTlsHandshakePacketAndRuntimeSeamsRemainNonPublic()
    {
        foreach (Type seamType in NamedInternalSeamTypes)
        {
            Assert.False(seamType.IsVisible, $"{seamType.FullName} must not be externally visible.");
            Assert.False(seamType.IsPublic, $"{seamType.FullName} must not be a public top-level type.");
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PublicApiBaselinesDoNotApproveInternalSeams()
    {
        string publicApiText = string.Join(
            Environment.NewLine,
            File.ReadAllText(Path.Combine(GetRepoRoot(), "src", "Incursa.Quic", "PublicAPI.Shipped.txt")),
            File.ReadAllText(Path.Combine(GetRepoRoot(), "src", "Incursa.Quic", "PublicAPI.Unshipped.txt")));

        foreach (Type seamType in NamedInternalSeamTypes)
        {
            Assert.DoesNotContain(seamType.FullName!, publicApiText, StringComparison.Ordinal);
        }
    }

    private static string GetRepoRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);

        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "src", "Incursa.Quic", "PublicAPI.Unshipped.txt")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root from the test output directory.");
    }
}
