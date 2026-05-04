using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

namespace Incursa.Quic.Tests;

internal static class QuicS8P1P3ServerTokenValidationTestSupport
{
    internal const int TokenMismatchFailureCode = 6;

    internal static async ValueTask<RetryValidationScenario> StartRetryValidationScenarioAsync(
        QuicAddressValidationTokenProtector? addressValidationTokenProtector = null)
    {
        RetryValidationScenario scenario = new(addressValidationTokenProtector);
        scenario.Start();
        await Task.Yield();
        return scenario;
    }

    internal sealed class RetryValidationScenario : IAsyncDisposable
    {
        private readonly X509Certificate2 serverCertificate;
        private readonly Socket clientSocket;
        private readonly byte[] cryptoPayload;
        private readonly QuicAddressValidationTokenProtector addressValidationTokenProtector;
        private readonly TaskCompletionSource<bool> callbackEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private QuicRetryBootstrapMetadata? retryMetadata;

        internal RetryValidationScenario(QuicAddressValidationTokenProtector? addressValidationTokenProtector)
        {
            this.addressValidationTokenProtector =
                addressValidationTokenProtector ?? QuicAddressValidationTokenProtector.CreateEphemeral();
            IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
            serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
            ListenerHost = new QuicListenerHost(
                listenEndPoint,
                [SslApplicationProtocol.Http3],
                (_, _, _) =>
                {
                    callbackEntered.TrySetResult(true);
                    return ValueTask.FromResult(QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate));
                },
                listenBacklog: 1,
                retryBootstrapEnabled: true,
                addressValidationTokenProtector: this.addressValidationTokenProtector);

            clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            clientSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            clientSocket.Connect(listenEndPoint);
            cryptoPayload = QuicFrameTestData.BuildCryptoFrame(
                new QuicCryptoFrame(0, QuicS12P3TestSupport.CreateSequentialBytes(0x60, 16)));
        }

        internal QuicListenerHost ListenerHost { get; }

        internal Task CallbackEntered => callbackEntered.Task;

        internal void Start()
        {
            _ = ListenerHost.RunAsync();
        }

        internal async ValueTask<QuicRetryBootstrapMetadata> IssueRetryAsync()
        {
            byte[] initialPacket = BuildInitialPacket(
                QuicS17P2P2TestSupport.InitialDestinationConnectionId,
                ReadOnlySpan<byte>.Empty);

            int bytesSent = clientSocket.Send(initialPacket);
            Assert.Equal(initialPacket.Length, bytesSent);

            QuicRetryBootstrapMetadata parsedRetryMetadata = await ReceiveRetryAsync();
            Assert.Equal(Convert.ToHexString(parsedRetryMetadata.RetryToken), ListenerHost.RetryBootstrapTokenHex);

            retryMetadata = parsedRetryMetadata;
            return parsedRetryMetadata;
        }

        internal byte[] IssueNewTokenForClient(DateTimeOffset? issuedAt = null)
        {
            IPEndPoint clientEndPoint = (IPEndPoint)clientSocket.LocalEndPoint!;
            return addressValidationTokenProtector.IssueNewToken(
                clientEndPoint.Address.ToString(),
                issuedAt ?? DateTimeOffset.UtcNow);
        }

        internal byte[] IssueNewTokenForAddress(string remoteAddress, DateTimeOffset? issuedAt = null)
        {
            return addressValidationTokenProtector.IssueNewToken(
                remoteAddress,
                issuedAt ?? DateTimeOffset.UtcNow);
        }

        internal void SendInitialWithToken(ReadOnlySpan<byte> token)
        {
            byte[] initialPacket = BuildInitialPacket(
                QuicS17P2P2TestSupport.InitialDestinationConnectionId,
                token);

            int bytesSent = clientSocket.Send(initialPacket);
            Assert.Equal(initialPacket.Length, bytesSent);
        }

        internal async ValueTask<QuicRetryBootstrapMetadata> SendInitialWithTokenAndReceiveRetryAsync(byte[] token)
        {
            SendInitialWithToken(token);
            QuicRetryBootstrapMetadata parsedRetryMetadata = await ReceiveRetryAsync();
            retryMetadata = parsedRetryMetadata;
            return parsedRetryMetadata;
        }

        private async ValueTask<QuicRetryBootstrapMetadata> ReceiveRetryAsync()
        {
            byte[] retryResponse = new byte[256];
            using CancellationTokenSource receiveTimeout = new(TimeSpan.FromSeconds(5));
            int retryBytes = await clientSocket.ReceiveAsync(
                retryResponse.AsMemory(),
                SocketFlags.None,
                receiveTimeout.Token);

            Assert.True(QuicRetryIntegrity.TryParseRetryBootstrapMetadata(
                QuicS17P2P2TestSupport.InitialDestinationConnectionId,
                retryResponse.AsSpan(0, retryBytes),
                out QuicRetryBootstrapMetadata parsedRetryMetadata));
            return parsedRetryMetadata;
        }

        internal void SendRetryReplay(ReadOnlySpan<byte> token)
        {
            QuicRetryBootstrapMetadata metadata = retryMetadata
                ?? throw new InvalidOperationException("Retry must be issued before sending a replay Initial.");
            byte[] replayPacket = BuildInitialPacket(metadata.RetrySourceConnectionId, token);

            int bytesSent = clientSocket.Send(replayPacket);
            Assert.Equal(replayPacket.Length, bytesSent);
        }

        internal async Task WaitForCallbackAsync()
        {
            await callbackEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        }

        internal async Task WaitForReplayAdmittedAsync()
        {
            DateTime deadline = DateTime.UtcNow + TimeSpan.FromSeconds(5);
            while (DateTime.UtcNow < deadline)
            {
                if (ListenerHost.RetryBootstrapReplayAdmitted)
                {
                    return;
                }

                await Task.Delay(TimeSpan.FromMilliseconds(10));
            }

            Assert.True(ListenerHost.RetryBootstrapReplayAdmitted);
        }

        internal async Task WaitForNoCallbackAsync()
        {
            await Task.Delay(TimeSpan.FromMilliseconds(250));
            Assert.False(callbackEntered.Task.IsCompleted);
        }

        public async ValueTask DisposeAsync()
        {
            clientSocket.Dispose();
            await ListenerHost.DisposeAsync().ConfigureAwait(false);
            serverCertificate.Dispose();
        }

        private byte[] BuildInitialPacket(
            ReadOnlySpan<byte> destinationConnectionId,
            ReadOnlySpan<byte> token)
        {
            Assert.True(QuicInitialPacketProtection.TryCreate(
                QuicTlsRole.Client,
                destinationConnectionId,
                out QuicInitialPacketProtection clientProtection));

            QuicHandshakeFlowCoordinator coordinator = new(
                QuicS17P2P2TestSupport.InitialDestinationConnectionId,
                QuicS17P2P2TestSupport.InitialSourceConnectionId);
            Assert.True(coordinator.TryBuildProtectedInitialPacket(
                cryptoPayload,
                cryptoPayloadOffset: 0,
                destinationConnectionId,
                token,
                clientProtection,
                out byte[] initialPacket));

            return initialPacket;
        }
    }
}
