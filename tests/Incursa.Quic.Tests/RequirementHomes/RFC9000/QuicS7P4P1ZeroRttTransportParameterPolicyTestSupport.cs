namespace Incursa.Quic.Tests;

internal static class QuicS7P4P1ZeroRttTransportParameterPolicyTestSupport
{
    internal static QuicTransportParameters CreateRememberedParameters()
    {
        return new QuicTransportParameters
        {
            MaxIdleTimeout = 30,
            MaxUdpPayloadSize = 1_300,
            InitialMaxData = 1_000,
            InitialMaxStreamDataBidiLocal = 100,
            InitialMaxStreamDataBidiRemote = 120,
            InitialMaxStreamDataUni = 80,
            InitialMaxStreamsBidi = 2,
            InitialMaxStreamsUni = 3,
            DisableActiveMigration = true,
            ActiveConnectionIdLimit = 4,
        };
    }

    internal static QuicTransportParameters CreateCurrentServerParameters()
    {
        return new QuicTransportParameters
        {
            MaxIdleTimeout = 40,
            MaxUdpPayloadSize = 1_400,
            InitialMaxData = 1_200,
            InitialMaxStreamDataBidiLocal = 140,
            InitialMaxStreamDataBidiRemote = 160,
            InitialMaxStreamDataUni = 120,
            InitialMaxStreamsBidi = 4,
            InitialMaxStreamsUni = 5,
            DisableActiveMigration = true,
            ActiveConnectionIdLimit = 5,
        };
    }

    internal static QuicZeroRttTransportParameterAcceptanceDecision Evaluate(
        Action<QuicTransportParameters>? configureRemembered = null,
        Action<QuicTransportParameters>? configureCurrent = null)
    {
        QuicTransportParameters remembered = CreateRememberedParameters();
        QuicTransportParameters current = CreateCurrentServerParameters();
        configureRemembered?.Invoke(remembered);
        configureCurrent?.Invoke(current);
        return QuicZeroRttTransportParameterPolicy.EvaluateServerZeroRttAcceptance(remembered, current);
    }
}
