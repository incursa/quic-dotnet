namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0059")]
public sealed class REQ_QUIC_CRT_0059
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PathIdentityIncludesRemoteAndLocalEndpointComponents()
    {
        QuicConnectionPathIdentity path = new(
            RemoteAddress: "203.0.113.10",
            LocalAddress: "198.51.100.10",
            RemotePort: 443,
            LocalPort: 61234);

        QuicConnectionActivePathRecord activePath = new(
            Identity: path,
            ActivatedAtTicks: 10,
            LastActivityTicks: 11,
            IsValidated: true,
            RecoverySnapshot: null);

        Assert.Equal("203.0.113.10", activePath.Identity.RemoteAddress);
        Assert.Equal("198.51.100.10", activePath.Identity.LocalAddress);
        Assert.Equal(443, activePath.Identity.RemotePort);
        Assert.Equal(61234, activePath.Identity.LocalPort);

        Assert.NotEqual(path, path with { LocalPort = 61235 });
        Assert.NotEqual(path, path with { LocalAddress = "198.51.100.11" });
        Assert.NotEqual(path, path with { RemoteAddress = "203.0.113.11" });
    }
}
