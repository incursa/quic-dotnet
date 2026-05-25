namespace Incursa.Quic.Tests;

public sealed class QuicServerResumptionTicketStoreUnitTests
{
    [Fact]
    public void TryStoreIssuedTicket_ClonesVersionInformationInZeroRttTransportParameters()
    {
        QuicServerResumptionTicketStore store = new();
        byte[] ticketBytes = [0x01, 0x02, 0x03];
        byte[] ticketNonce = [0x10, 0x11, 0x12];
        byte[] resumptionMasterSecret = [0x20, 0x21, 0x22, 0x23];
        uint[] availableVersions =
        [
            QuicVersionNegotiation.Version2,
            QuicVersionNegotiation.Version1,
        ];
        QuicTransportParameters parameters = new()
        {
            VersionInformation = new QuicVersionInformation
            {
                ChosenVersion = QuicVersionNegotiation.Version2,
                AvailableVersions = availableVersions,
            },
        };
        long nowTicks = DateTimeOffset.UtcNow.UtcTicks;

        Assert.True(store.TryStoreIssuedTicket(
            ticketBytes,
            ticketNonce,
            ticketAgeAdd: 7,
            ticketLifetimeSeconds: 60,
            resumptionMasterSecret,
            parameters,
            nowTicks));

        parameters.VersionInformation!.ChosenVersion = QuicVersionNegotiation.Version1;
        parameters.VersionInformation.AvailableVersions[0] = 0x11223344;

        Assert.True(store.TryGetLiveTicket(ticketBytes, nowTicks, out QuicServerResumptionTicketRecord ticket));
        Assert.NotNull(ticket.ZeroRttTransportParameters);
        Assert.NotNull(ticket.ZeroRttTransportParameters!.VersionInformation);
        Assert.Equal(QuicVersionNegotiation.Version2, ticket.ZeroRttTransportParameters.VersionInformation!.ChosenVersion);
        Assert.Equal(QuicVersionNegotiation.Version2, ticket.ZeroRttTransportParameters.VersionInformation.AvailableVersions[0]);
        Assert.Equal(QuicVersionNegotiation.Version1, ticket.ZeroRttTransportParameters.VersionInformation.AvailableVersions[1]);
    }
}
