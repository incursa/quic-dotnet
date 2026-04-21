using System.Reflection;
using System.Text.Json;
using Incursa.Quic.Qlog;
using Incursa.Qlog;
using Incursa.Qlog.Quic;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0136")]
public sealed class REQ_QUIC_CRT_0136
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DiagnosticsSinkMapsRepresentativeTransportEventsIntoTypedQlogQuicEvents()
    {
        QuicConnectionPathIdentity pathIdentity = new(
            RemoteAddress: "203.0.113.10",
            LocalAddress: "198.51.100.3",
            RemotePort: 443,
            LocalPort: 61234);

        QuicQlogDiagnosticsSink clientSink = new(isServer: false);
        Assert.True(clientSink.IsEnabled);
        Assert.Equal(QlogKnownValues.ClientVantagePoint, clientSink.Trace.VantagePoint?.Type);

        clientSink.Emit(QuicDiagnostics.InitialPacketReceived(pathIdentity));
        clientSink.Emit(QuicDiagnostics.InitialPacketOpenFailed(pathIdentity));
        clientSink.Emit(QuicDiagnostics.InitialPacketProcessingResult(true));
        clientSink.Emit(QuicDiagnostics.InitialPacketProcessingResult(false));
        clientSink.Emit(QuicDiagnostics.TranscriptAdvanced(QuicTlsEncryptionLevel.Initial, 2));
        clientSink.Emit(QuicDiagnostics.TranscriptAdvanced(QuicTlsEncryptionLevel.Handshake, 5));

        QuicConnectionPathClassification classification = QuicConnectionPathClassification.MigrationCandidate;
        clientSink.Emit(QuicDiagnostics.AddressChangeClassified(pathIdentity, classification));
        clientSink.Emit(QuicDiagnostics.PathValidationFailedNoValidatedPathsRemain(pathIdentity));
        clientSink.Emit(QuicDiagnostics.PathValidationTimerExpiredNoValidatedPathsRemain());
        clientSink.Emit(QuicDiagnostics.CandidatePathBudgetExhausted(pathIdentity));
        clientSink.Emit(QuicDiagnostics.AcceptedStatelessReset(pathIdentity, 0x2A));

        Assert.Single(clientSink.Trace.EventSchemas);
        Assert.Equal(QlogQuicKnownValues.DraftEventSchemaUri, clientSink.Trace.EventSchemas[0]);

        string[] eventNames =
        [
            .. clientSink.Trace.Events.Select(static qlogEvent => qlogEvent.Name),
        ];

        Assert.Equal(
            [
                QlogQuicKnownValues.PacketReceivedEventName,
                QlogQuicKnownValues.PacketDroppedEventName,
                QlogQuicKnownValues.ConnectionStateUpdatedEventName,
                QlogQuicKnownValues.ConnectionStateUpdatedEventName,
                QlogQuicKnownValues.KeyUpdatedEventName,
                QlogQuicKnownValues.KeyUpdatedEventName,
                QlogQuicKnownValues.MigrationStateUpdatedEventName,
                QlogQuicKnownValues.MigrationStateUpdatedEventName,
                QlogQuicKnownValues.MigrationStateUpdatedEventName,
                QlogQuicKnownValues.MigrationStateUpdatedEventName,
                QlogQuicKnownValues.ConnectionClosedEventName,
            ],
            eventNames);

        QlogEvent initialPacketReceived = clientSink.Trace.Events[0];
        Assert.Equal("203.0.113.10:443|198.51.100.3:61234", initialPacketReceived.Tuple);
        Assert.Equal(QlogQuicKnownValues.PacketTypeInitial, ReadObjectString(initialPacketReceived.Data["header"], "packet_type"));

        QlogEvent initialPacketDropped = clientSink.Trace.Events[1];
        Assert.Equal("203.0.113.10:443|198.51.100.3:61234", initialPacketDropped.Tuple);
        Assert.Equal(QlogQuicKnownValues.PacketTypeInitial, ReadObjectString(initialPacketDropped.Data["header"], "packet_type"));

        QlogEvent initialPacketAdvanced = clientSink.Trace.Events[2];
        Assert.Equal(QlogQuicKnownValues.ConnectionStateAttempted, ReadString(initialPacketAdvanced.Data["old"]));
        Assert.Equal(QlogQuicKnownValues.ConnectionStateHandshakeStarted, ReadString(initialPacketAdvanced.Data["new"]));
        Assert.True(ReadBoolean(initialPacketAdvanced.Data["processed"]));

        QlogEvent initialPacketNotAdvanced = clientSink.Trace.Events[3];
        Assert.Equal(QlogQuicKnownValues.ConnectionStateAttempted, ReadString(initialPacketNotAdvanced.Data["old"]));
        Assert.Equal(QlogQuicKnownValues.ConnectionStateAttempted, ReadString(initialPacketNotAdvanced.Data["new"]));
        Assert.False(ReadBoolean(initialPacketNotAdvanced.Data["processed"]));

        QlogEvent initialKeyUpdated = clientSink.Trace.Events[4];
        Assert.Equal(QlogQuicKnownValues.KeyTypeClientInitialSecret, ReadString(initialKeyUpdated.Data["key_type"]));
        Assert.Equal(QlogQuicKnownValues.KeyLifecycleTriggerTls, ReadString(initialKeyUpdated.Data["trigger"]));
        Assert.Equal(2L, ReadNumber(initialKeyUpdated.Data["transcript_update_count"]));

        QlogEvent handshakeKeyUpdated = clientSink.Trace.Events[5];
        Assert.Equal(QlogQuicKnownValues.KeyTypeClientHandshakeSecret, ReadString(handshakeKeyUpdated.Data["key_type"]));
        Assert.Equal(QlogQuicKnownValues.KeyLifecycleTriggerTls, ReadString(handshakeKeyUpdated.Data["trigger"]));
        Assert.Equal(5L, ReadNumber(handshakeKeyUpdated.Data["transcript_update_count"]));

        QlogEvent migrationStarted = clientSink.Trace.Events[6];
        Assert.Equal(QlogQuicKnownValues.MigrationStateStarted, ReadString(migrationStarted.Data["new"]));
        Assert.Equal("203.0.113.10:443|198.51.100.3:61234", migrationStarted.Tuple);
        Assert.Equal("203.0.113.10", ReadObjectString(migrationStarted.Data["tuple_remote"], "ip_v4"));
        Assert.Equal(443L, ReadObjectNumber(migrationStarted.Data["tuple_remote"], "port_v4"));
        Assert.Equal("198.51.100.3", ReadObjectString(migrationStarted.Data["tuple_local"], "ip_v4"));
        Assert.Equal(61234L, ReadObjectNumber(migrationStarted.Data["tuple_local"], "port_v4"));

        QlogEvent pathValidationFailed = clientSink.Trace.Events[7];
        Assert.Equal(QlogQuicKnownValues.MigrationStateAbandoned, ReadString(pathValidationFailed.Data["new"]));
        Assert.Equal("203.0.113.10:443|198.51.100.3:61234", pathValidationFailed.Tuple);

        QlogEvent pathValidationExpired = clientSink.Trace.Events[8];
        Assert.Equal(QlogQuicKnownValues.MigrationStateProbingAbandoned, ReadString(pathValidationExpired.Data["new"]));

        QlogEvent budgetExhausted = clientSink.Trace.Events[9];
        Assert.Equal(QlogQuicKnownValues.MigrationStateAbandoned, ReadString(budgetExhausted.Data["new"]));
        Assert.Equal("203.0.113.10:443|198.51.100.3:61234", budgetExhausted.Tuple);

        QlogEvent statelessReset = clientSink.Trace.Events[10];
        Assert.Equal(QlogQuicKnownValues.RemoteInitiator, ReadString(statelessReset.Data["initiator"]));
        Assert.Equal(QlogQuicKnownValues.CloseTriggerStatelessReset, ReadString(statelessReset.Data["trigger"]));
        Assert.Equal(42L, ReadNumber(statelessReset.Data["connection_id"]));
        Assert.Equal("203.0.113.10:443|198.51.100.3:61234", statelessReset.Tuple);

        QuicQlogDiagnosticsSink serverSink = new(isServer: true);
        serverSink.Emit(QuicDiagnostics.TranscriptAdvanced(QuicTlsEncryptionLevel.Initial, 1));

        Assert.Equal(QlogQuicKnownValues.KeyTypeServerInitialSecret, ReadString(serverSink.Trace.Events[0].Data["key_type"]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DiagnosticsSinkMapsHandshakePacketLifecycleIntoTypedQlogPacketEvents()
    {
        QuicConnectionPathIdentity pathIdentity = new(
            RemoteAddress: "203.0.113.10",
            LocalAddress: "198.51.100.3",
            RemotePort: 443,
            LocalPort: 61234);

        byte[] initialPacketBytes = [0x01, 0x02, 0x03];
        byte[] handshakePacketReceivedBytes = [0x04, 0x05, 0x06];
        byte[] handshakePacketSentBytes = [0x07, 0x08];
        byte[] retryBytes = [0x09, 0x0A];
        byte[] versionNegotiationBytes = [0x0B];

        QuicQlogDiagnosticsSink clientSink = new(isServer: false);

        clientSink.Emit(QuicDiagnostics.InitialPacketSent(pathIdentity, initialPacketBytes));
        clientSink.Emit(QuicDiagnostics.HandshakePacketReceived(pathIdentity, handshakePacketReceivedBytes));
        clientSink.Emit(QuicDiagnostics.HandshakePacketSent(pathIdentity, handshakePacketSentBytes));
        clientSink.Emit(QuicDiagnostics.RetryReceived(retryBytes));
        clientSink.Emit(QuicDiagnostics.VersionNegotiationReceived(versionNegotiationBytes));

        Assert.Equal(
            [
                QlogQuicKnownValues.PacketSentEventName,
                QlogQuicKnownValues.PacketReceivedEventName,
                QlogQuicKnownValues.PacketSentEventName,
                QlogQuicKnownValues.PacketReceivedEventName,
                QlogQuicKnownValues.PacketReceivedEventName,
            ],
            clientSink.Trace.Events.Select(static qlogEvent => qlogEvent.Name));

        QlogEvent initialPacketSent = clientSink.Trace.Events[0];
        Assert.Equal("203.0.113.10:443|198.51.100.3:61234", initialPacketSent.Tuple);
        Assert.Equal(QlogQuicKnownValues.PacketTypeInitial, ReadObjectString(initialPacketSent.Data["header"], "packet_type"));
        Assert.Equal("00000001", ReadObjectString(initialPacketSent.Data["header"], "version"));
        Assert.Equal(3L, ReadObjectNumber(initialPacketSent.Data["raw"], "length"));
        Assert.Equal(3L, ReadObjectNumber(initialPacketSent.Data["raw"], "payload_length"));
        Assert.Equal("010203", ReadObjectString(initialPacketSent.Data["raw"], "data"));

        QlogEvent handshakePacketReceived = clientSink.Trace.Events[1];
        Assert.Equal("203.0.113.10:443|198.51.100.3:61234", handshakePacketReceived.Tuple);
        Assert.Equal(QlogQuicKnownValues.PacketTypeHandshake, ReadObjectString(handshakePacketReceived.Data["header"], "packet_type"));
        Assert.Equal("00000001", ReadObjectString(handshakePacketReceived.Data["header"], "version"));
        Assert.Equal(3L, ReadObjectNumber(handshakePacketReceived.Data["raw"], "length"));
        Assert.Equal(3L, ReadObjectNumber(handshakePacketReceived.Data["raw"], "payload_length"));
        Assert.Equal("040506", ReadObjectString(handshakePacketReceived.Data["raw"], "data"));

        QlogEvent handshakePacketSent = clientSink.Trace.Events[2];
        Assert.Equal("203.0.113.10:443|198.51.100.3:61234", handshakePacketSent.Tuple);
        Assert.Equal(QlogQuicKnownValues.PacketTypeHandshake, ReadObjectString(handshakePacketSent.Data["header"], "packet_type"));
        Assert.Equal("00000001", ReadObjectString(handshakePacketSent.Data["header"], "version"));
        Assert.Equal(2L, ReadObjectNumber(handshakePacketSent.Data["raw"], "length"));
        Assert.Equal(2L, ReadObjectNumber(handshakePacketSent.Data["raw"], "payload_length"));
        Assert.Equal("0708", ReadObjectString(handshakePacketSent.Data["raw"], "data"));

        QlogEvent retryReceived = clientSink.Trace.Events[3];
        Assert.Equal(QlogQuicKnownValues.PacketTypeRetry, ReadObjectString(retryReceived.Data["header"], "packet_type"));
        Assert.Equal("00000001", ReadObjectString(retryReceived.Data["header"], "version"));
        Assert.Equal(2L, ReadObjectNumber(retryReceived.Data["raw"], "length"));
        Assert.Equal(2L, ReadObjectNumber(retryReceived.Data["raw"], "payload_length"));
        Assert.Equal("090A", ReadObjectString(retryReceived.Data["raw"], "data"));

        QlogEvent versionNegotiationReceived = clientSink.Trace.Events[4];
        Assert.Equal(QlogQuicKnownValues.PacketTypeVersionNegotiation, ReadObjectString(versionNegotiationReceived.Data["header"], "packet_type"));
        Assert.Equal("00000000", ReadObjectString(versionNegotiationReceived.Data["header"], "version"));
        Assert.Equal(1L, ReadObjectNumber(versionNegotiationReceived.Data["raw"], "length"));
        Assert.Equal(1L, ReadObjectNumber(versionNegotiationReceived.Data["raw"], "payload_length"));
        Assert.Equal("0B", ReadObjectString(versionNegotiationReceived.Data["raw"], "data"));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AssemblyReferencesKeepTheTransportCoreFreeOfQlogDependencies()
    {
        Assembly coreAssembly = typeof(QuicConnection).Assembly;
        Assembly adapterAssembly = typeof(QuicQlogDiagnosticsSink).Assembly;

        string[] coreReferences = coreAssembly
            .GetReferencedAssemblies()
            .Select(static assemblyName => assemblyName.Name ?? string.Empty)
            .ToArray();

        string[] adapterReferences = adapterAssembly
            .GetReferencedAssemblies()
            .Select(static assemblyName => assemblyName.Name ?? string.Empty)
            .ToArray();

        Assert.DoesNotContain("Incursa.Qlog", coreReferences);
        Assert.DoesNotContain("Incursa.Qlog.Quic", coreReferences);
        Assert.DoesNotContain("Incursa.Quic.Qlog", coreReferences);

        Assert.Contains("Incursa.Quic", adapterReferences);
        Assert.Contains("Incursa.Qlog", adapterReferences);
        Assert.Contains("Incursa.Qlog.Quic", adapterReferences);
    }

    private static string ReadString(QlogValue value)
    {
        using JsonDocument document = JsonDocument.Parse(value.ToJson());
        return document.RootElement.GetString() ?? throw new InvalidOperationException("Expected a JSON string.");
    }

    private static bool ReadBoolean(QlogValue value)
    {
        using JsonDocument document = JsonDocument.Parse(value.ToJson());
        return document.RootElement.GetBoolean();
    }

    private static long ReadNumber(QlogValue value)
    {
        using JsonDocument document = JsonDocument.Parse(value.ToJson());
        return document.RootElement.GetInt64();
    }

    private static string ReadObjectString(QlogValue value, string propertyName)
    {
        using JsonDocument document = JsonDocument.Parse(value.ToJson());
        return document.RootElement.GetProperty(propertyName).GetString() ?? throw new InvalidOperationException($"Expected '{propertyName}' to be a JSON string.");
    }

    private static long ReadObjectNumber(QlogValue value, string propertyName)
    {
        using JsonDocument document = JsonDocument.Parse(value.ToJson());
        return document.RootElement.GetProperty(propertyName).GetInt64();
    }
}
