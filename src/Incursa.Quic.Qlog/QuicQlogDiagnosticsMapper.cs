using System.Net;
using Incursa.Quic;
using Incursa.Qlog;
using Incursa.Qlog.Quic;

namespace Incursa.Quic.Qlog;

internal static class QuicQlogDiagnosticsMapper
{
    internal static bool TryMap(
        QuicDiagnosticEvent diagnosticEvent,
        double eventTime,
        bool isServer,
        out QlogEvent? qlogEvent)
    {
        qlogEvent = diagnosticEvent.Kind switch
        {
            QuicDiagnosticKind.InitialPacketReceived => CreateInitialPacketReceived(eventTime, diagnosticEvent),
            QuicDiagnosticKind.InitialPacketOpenFailed => CreatePacketDropped(eventTime, diagnosticEvent, QlogQuicKnownValues.PacketTypeInitial),
            QuicDiagnosticKind.InitialPacketAdvanced => CreateConnectionStateUpdated(eventTime, processed: true),
            QuicDiagnosticKind.InitialPacketNotAdvanced => CreateConnectionStateUpdated(eventTime, processed: false),
            QuicDiagnosticKind.InitialPacketSent => CreateInitialPacketSent(eventTime, diagnosticEvent),
            QuicDiagnosticKind.HandshakePacketOpenFailed => CreatePacketDropped(eventTime, diagnosticEvent, QlogQuicKnownValues.PacketTypeHandshake),
            QuicDiagnosticKind.RetryReceived => CreateRetryReceived(eventTime, diagnosticEvent),
            QuicDiagnosticKind.VersionNegotiationReceived => CreateVersionNegotiationReceived(eventTime, diagnosticEvent),
            QuicDiagnosticKind.InitialTranscriptAdvanced when diagnosticEvent.EncryptionLevel.HasValue => CreateKeyUpdated(
                eventTime,
                diagnosticEvent,
                diagnosticEvent.EncryptionLevel.Value,
                isServer),
            QuicDiagnosticKind.HandshakeTranscriptAdvanced when diagnosticEvent.EncryptionLevel.HasValue => CreateKeyUpdated(
                eventTime,
                diagnosticEvent,
                diagnosticEvent.EncryptionLevel.Value,
                isServer),
            QuicDiagnosticKind.PathValidationFailedNoValidatedPathsRemain => CreatePathValidationStateUpdated(
                eventTime,
                diagnosticEvent,
                QlogQuicKnownValues.MigrationStateAbandoned),
            QuicDiagnosticKind.PathValidationTimerExpiredNoValidatedPathsRemain => CreatePathValidationStateUpdated(
                eventTime,
                diagnosticEvent,
                QlogQuicKnownValues.MigrationStateProbingAbandoned),
            QuicDiagnosticKind.AcceptedStatelessReset => CreateAcceptedStatelessReset(eventTime, diagnosticEvent),
            QuicDiagnosticKind.AddressChangeClassified => CreateAddressChangeClassified(eventTime, diagnosticEvent),
            QuicDiagnosticKind.CandidatePathBudgetExhausted => CreateCandidatePathBudgetExhausted(eventTime, diagnosticEvent),
            _ => null,
        };

        return qlogEvent is not null;
    }

    private static QlogEvent CreateInitialPacketReceived(double eventTime, QuicDiagnosticEvent diagnosticEvent)
    {
        return CreatePacketReceived(
            eventTime,
            diagnosticEvent,
            QlogQuicKnownValues.PacketTypeInitial,
            version: QuicVersionNegotiation.Version1.ToString("x8"));
    }

    private static QlogEvent CreateInitialPacketSent(double eventTime, QuicDiagnosticEvent diagnosticEvent)
    {
        return CreatePacketSent(
            eventTime,
            diagnosticEvent,
            QlogQuicKnownValues.PacketTypeInitial,
            version: QuicVersionNegotiation.Version1.ToString("x8"));
    }

    private static QlogEvent CreateRetryReceived(double eventTime, QuicDiagnosticEvent diagnosticEvent)
    {
        return CreatePacketReceived(
            eventTime,
            diagnosticEvent,
            QlogQuicKnownValues.PacketTypeRetry,
            version: QuicVersionNegotiation.Version1.ToString("x8"));
    }

    private static QlogEvent CreateVersionNegotiationReceived(double eventTime, QuicDiagnosticEvent diagnosticEvent)
    {
        return CreatePacketReceived(
            eventTime,
            diagnosticEvent,
            QlogQuicKnownValues.PacketTypeVersionNegotiation,
            version: "00000000");
    }

    private static QlogEvent CreatePacketSent(
        double eventTime,
        QuicDiagnosticEvent diagnosticEvent,
        string packetType,
        string? version = null)
    {
        QuicPacketSent payload = new()
        {
            Header = new QuicPacketHeader
            {
                PacketType = packetType,
                Version = version,
            },
            Raw = CreateRawInfo(diagnosticEvent.PacketBytes),
        };

        QlogEvent qlogEvent = QlogQuicEvents.CreatePacketSent(eventTime, payload);
        ApplyTuple(qlogEvent, diagnosticEvent.PathIdentity);
        return qlogEvent;
    }

    private static QlogEvent CreatePacketReceived(
        double eventTime,
        QuicDiagnosticEvent diagnosticEvent,
        string packetType,
        string? version = null)
    {
        QuicPacketReceived payload = new()
        {
            Header = new QuicPacketHeader
            {
                PacketType = packetType,
                Version = version,
            },
            Raw = CreateRawInfo(diagnosticEvent.PacketBytes),
        };

        QlogEvent qlogEvent = QlogQuicEvents.CreatePacketReceived(eventTime, payload);
        ApplyTuple(qlogEvent, diagnosticEvent.PathIdentity);
        return qlogEvent;
    }

    private static QlogEvent CreatePacketDropped(double eventTime, QuicDiagnosticEvent diagnosticEvent, string packetType)
    {
        QuicPacketDropped payload = new()
        {
            Header = new QuicPacketHeader
            {
                PacketType = packetType,
            },
        };

        if (!string.IsNullOrWhiteSpace(diagnosticEvent.Message))
        {
            payload.ExtensionData["reason"] = QlogValue.FromString(diagnosticEvent.Message);
        }

        QlogEvent qlogEvent = QlogQuicEvents.CreatePacketDropped(eventTime, payload);
        ApplyTuple(qlogEvent, diagnosticEvent.PathIdentity);
        return qlogEvent;
    }

    private static QlogEvent CreateConnectionStateUpdated(double eventTime, bool processed)
    {
        QuicConnectionStateUpdated payload = new()
        {
            Old = QlogQuicKnownValues.ConnectionStateAttempted,
            New = processed
                ? QlogQuicKnownValues.ConnectionStateHandshakeStarted
                : QlogQuicKnownValues.ConnectionStateAttempted,
        };

        payload.ExtensionData["processed"] = QlogValue.FromBoolean(processed);
        return QlogQuicEvents.CreateConnectionStateUpdated(eventTime, payload);
    }

    private static QlogEvent CreateKeyUpdated(
        double eventTime,
        QuicDiagnosticEvent diagnosticEvent,
        QuicTlsEncryptionLevel encryptionLevel,
        bool isServer)
    {
        QuicKeyUpdated payload = new()
        {
            KeyType = MapKeyType(encryptionLevel, isServer),
            Trigger = QlogQuicKnownValues.KeyLifecycleTriggerTls,
        };

        if (diagnosticEvent.TranscriptUpdateCount.HasValue)
        {
            payload.ExtensionData["transcript_update_count"] = QlogValue.FromNumber((long)diagnosticEvent.TranscriptUpdateCount.Value);
        }

        return QlogQuicEvents.CreateKeyUpdated(eventTime, payload);
    }

    private static QlogEvent CreatePathValidationStateUpdated(
        double eventTime,
        QuicDiagnosticEvent diagnosticEvent,
        string newState)
    {
        QuicMigrationStateUpdated payload = new()
        {
            New = newState,
        };

        if (diagnosticEvent.PathIdentity is QuicConnectionPathIdentity pathIdentity)
        {
            payload.TupleId = CreateTupleId(pathIdentity);
            payload.TupleRemote = CreateTupleEndpointInfo(pathIdentity.RemoteAddress, pathIdentity.RemotePort);
            payload.TupleLocal = CreateTupleEndpointInfo(pathIdentity.LocalAddress, pathIdentity.LocalPort);
        }

        QlogEvent qlogEvent = QlogQuicEvents.CreateMigrationStateUpdated(eventTime, payload);
        ApplyTuple(qlogEvent, diagnosticEvent.PathIdentity);
        return qlogEvent;
    }

    private static QlogEvent CreateAcceptedStatelessReset(double eventTime, QuicDiagnosticEvent diagnosticEvent)
    {
        QuicConnectionClosed payload = new()
        {
            Initiator = QlogQuicKnownValues.RemoteInitiator,
            Trigger = QlogQuicKnownValues.CloseTriggerStatelessReset,
            Reason = diagnosticEvent.Message,
        };

        if (diagnosticEvent.ConnectionId.HasValue)
        {
            payload.ExtensionData["connection_id"] = QlogValue.FromNumber(diagnosticEvent.ConnectionId.Value);
        }

        QlogEvent qlogEvent = QlogQuicEvents.CreateConnectionClosed(eventTime, payload);
        ApplyTuple(qlogEvent, diagnosticEvent.PathIdentity);
        return qlogEvent;
    }

    private static QlogEvent CreateAddressChangeClassified(double eventTime, QuicDiagnosticEvent diagnosticEvent)
    {
        string newState = diagnosticEvent.PathClassification switch
        {
            QuicConnectionPathClassification.SamePathTraffic => QlogQuicKnownValues.MigrationStateProbingSuccessful,
            QuicConnectionPathClassification.ProbableNatRebinding => QlogQuicKnownValues.MigrationStateProbingStarted,
            QuicConnectionPathClassification.MigrationCandidate => QlogQuicKnownValues.MigrationStateStarted,
            QuicConnectionPathClassification.PreferredAddressTransition => QlogQuicKnownValues.MigrationStateComplete,
            QuicConnectionPathClassification.NoiseOrAttack => QlogQuicKnownValues.MigrationStateProbingAbandoned,
            _ => QlogQuicKnownValues.MigrationStateStarted,
        };

        return CreatePathValidationStateUpdated(eventTime, diagnosticEvent, newState);
    }

    private static QlogEvent CreateCandidatePathBudgetExhausted(double eventTime, QuicDiagnosticEvent diagnosticEvent)
    {
        return CreatePathValidationStateUpdated(eventTime, diagnosticEvent, QlogQuicKnownValues.MigrationStateAbandoned);
    }

    private static string MapKeyType(QuicTlsEncryptionLevel encryptionLevel, bool isServer)
    {
        return encryptionLevel switch
        {
            QuicTlsEncryptionLevel.Initial => isServer
                ? QlogQuicKnownValues.KeyTypeServerInitialSecret
                : QlogQuicKnownValues.KeyTypeClientInitialSecret,
            QuicTlsEncryptionLevel.Handshake => isServer
                ? QlogQuicKnownValues.KeyTypeServerHandshakeSecret
                : QlogQuicKnownValues.KeyTypeClientHandshakeSecret,
            QuicTlsEncryptionLevel.OneRtt => isServer
                ? QlogQuicKnownValues.KeyTypeServerOneRttSecret
                : QlogQuicKnownValues.KeyTypeClientOneRttSecret,
            _ => throw new ArgumentOutOfRangeException(nameof(encryptionLevel)),
        };
    }

    private static QuicTupleEndpointInfo CreateTupleEndpointInfo(string? address, int? port)
    {
        QuicTupleEndpointInfo tupleEndpointInfo = new();
        if (!string.IsNullOrWhiteSpace(address))
        {
            if (IPAddress.TryParse(address, out IPAddress? ipAddress))
            {
                if (ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                {
                    tupleEndpointInfo.IpV6 = ipAddress.ToString();
                }
                else
                {
                    tupleEndpointInfo.IpV4 = ipAddress.ToString();
                }
            }
            else
            {
                tupleEndpointInfo.IpV4 = address;
            }
        }

        if (port.HasValue && port.Value is >= ushort.MinValue and <= ushort.MaxValue)
        {
            if (tupleEndpointInfo.IpV6 is not null)
            {
                tupleEndpointInfo.PortV6 = (ushort)port.Value;
            }
            else
            {
                tupleEndpointInfo.PortV4 = (ushort)port.Value;
            }
        }

        return tupleEndpointInfo;
    }

    private static void ApplyTuple(QlogEvent qlogEvent, QuicConnectionPathIdentity? pathIdentity)
    {
        if (pathIdentity is not QuicConnectionPathIdentity value)
        {
            return;
        }

        qlogEvent.Tuple = CreateTupleId(value);
    }

    private static QuicRawInfo? CreateRawInfo(ReadOnlyMemory<byte> packetBytes)
    {
        if (packetBytes.IsEmpty)
        {
            return null;
        }

        return new QuicRawInfo
        {
            Length = (ulong)packetBytes.Length,
            PayloadLength = (ulong)packetBytes.Length,
            Data = Convert.ToHexString(packetBytes.Span),
        };
    }

    private static string CreateTupleId(QuicConnectionPathIdentity pathIdentity)
    {
        return $"{FormatEndpoint(pathIdentity.RemoteAddress, pathIdentity.RemotePort)}|{FormatEndpoint(pathIdentity.LocalAddress, pathIdentity.LocalPort)}";
    }

    private static string FormatEndpoint(string? address, int? port)
    {
        if (string.IsNullOrWhiteSpace(address))
        {
            return string.Empty;
        }

        string formattedAddress = address.Contains(':', StringComparison.Ordinal)
            ? $"[{address}]"
            : address;

        return port.HasValue
            ? $"{formattedAddress}:{port.Value}"
            : formattedAddress;
    }
}
