// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

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
            QuicDiagnosticKind.SocketDatagramReceived => CreateSocketDatagramReceived(eventTime, diagnosticEvent),
            QuicDiagnosticKind.ListenerIngressClassified => CreateListenerIngressClassified(eventTime, diagnosticEvent),
            QuicDiagnosticKind.ListenerPreAcceptanceClassified => CreateListenerPreAcceptanceClassified(eventTime, diagnosticEvent),
            QuicDiagnosticKind.ListenerInitialAdmissionResult => CreateListenerInitialAdmissionResult(eventTime, diagnosticEvent),
            QuicDiagnosticKind.InitialPacketReceived => CreateInitialPacketReceived(eventTime, diagnosticEvent),
            QuicDiagnosticKind.InitialPacketOpenFailed => CreatePacketDropped(eventTime, diagnosticEvent, QlogQuicKnownValues.PacketTypeInitial),
            QuicDiagnosticKind.InitialPacketAdvanced => CreateConnectionStateUpdated(eventTime, processed: true),
            QuicDiagnosticKind.InitialPacketNotAdvanced => CreateConnectionStateUpdated(eventTime, processed: false),
            QuicDiagnosticKind.InitialPacketSent => CreateInitialPacketSent(eventTime, diagnosticEvent),
            QuicDiagnosticKind.HandshakePacketReceived => CreateHandshakePacketReceived(eventTime, diagnosticEvent),
            QuicDiagnosticKind.HandshakePacketSent => CreateHandshakePacketSent(eventTime, diagnosticEvent),
            QuicDiagnosticKind.HandshakePacketOpenFailed => CreatePacketDropped(eventTime, diagnosticEvent, QlogQuicKnownValues.PacketTypeHandshake),
            QuicDiagnosticKind.RetryReceived => CreateRetryReceived(eventTime, diagnosticEvent),
            QuicDiagnosticKind.VersionNegotiationReceived => CreateVersionNegotiationReceived(eventTime, diagnosticEvent),
            QuicDiagnosticKind.VersionNegotiationSent => CreateVersionNegotiationSent(eventTime, diagnosticEvent),
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
            QuicDiagnosticKind.PeerHandshakeTranscriptCompleted => CreateConnectionStateUpdated(
                eventTime,
                QlogQuicKnownValues.ConnectionStateHandshakeComplete),
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
            QuicDiagnosticKind.FlowControlBlocked => CreateFlowControlBlocked(eventTime, diagnosticEvent),
            QuicDiagnosticKind.StreamLimitBlocked => CreateStreamLimitBlocked(eventTime, diagnosticEvent),
            QuicDiagnosticKind.PacketHeaderObserved => CreatePacketHeaderObserved(eventTime, diagnosticEvent),
            QuicDiagnosticKind.CoalescedDatagramReceived => CreateCoalescedDatagramReceived(eventTime, diagnosticEvent),
            QuicDiagnosticKind.ConnectionIdIssued => CreateConnectionIdEvent(eventTime, "quic:connection_id_issued", diagnosticEvent),
            QuicDiagnosticKind.ConnectionIdRetired => CreateConnectionIdEvent(eventTime, "quic:connection_id_retired", diagnosticEvent),
            QuicDiagnosticKind.ConnectionIdUsedOnPath => CreateConnectionIdEvent(eventTime, "quic:connection_id_used_on_path", diagnosticEvent),
            QuicDiagnosticKind.PathValidationChallengeSent => CreatePathValidationDiagnostic(eventTime, "quic:path_validation_challenge_sent", diagnosticEvent),
            QuicDiagnosticKind.PathValidationSucceeded => CreatePathValidationDiagnostic(eventTime, "quic:path_validation_succeeded", diagnosticEvent),
            QuicDiagnosticKind.PathValidationFailed => CreatePathValidationDiagnostic(eventTime, "quic:path_validation_failed", diagnosticEvent),
            QuicDiagnosticKind.PathValidationTimedOut => CreatePathValidationDiagnostic(eventTime, "quic:path_validation_timed_out", diagnosticEvent),
            QuicDiagnosticKind.PathPromoted => CreatePathValidationDiagnostic(eventTime, "quic:path_promoted", diagnosticEvent),
            QuicDiagnosticKind.SpinBitUpdated => CreateSpinBitUpdated(eventTime, diagnosticEvent),
            QuicDiagnosticKind.IcmpPacketTooBigReceived => CreateIcmpPacketTooBigReceived(eventTime, diagnosticEvent),
            QuicDiagnosticKind.PmtuUpdated => CreatePmtuUpdated(eventTime, diagnosticEvent),
            QuicDiagnosticKind.ConnectionCloseStateChanged => CreateConnectionCloseStateChanged(eventTime, diagnosticEvent),
            QuicDiagnosticKind.UdpReceiveError => CreateUdpError(eventTime, "quic:udp_receive_error", diagnosticEvent),
            QuicDiagnosticKind.UdpSendError => CreateUdpError(eventTime, "quic:udp_send_error", diagnosticEvent),
            QuicDiagnosticKind.AntiAmplificationBlocked => CreateAntiAmplificationBlocked(eventTime, diagnosticEvent),
            _ => null,
        };

        return qlogEvent is not null;
    }

    private static QlogEvent CreateSocketDatagramReceived(double eventTime, QuicDiagnosticEvent diagnosticEvent)
    {
        QlogEvent qlogEvent = new()
        {
            Time = eventTime,
            Name = "quic:socket_datagram_received",
        };

        if (diagnosticEvent.DatagramLength.HasValue)
        {
            qlogEvent.Data["datagram_length"] = QlogValue.FromNumber(diagnosticEvent.DatagramLength.Value);
        }

        if (!string.IsNullOrWhiteSpace(diagnosticEvent.Message))
        {
            qlogEvent.Data["message"] = QlogValue.FromString(diagnosticEvent.Message);
        }

        ApplyTuple(qlogEvent, diagnosticEvent.PathIdentity);
        return qlogEvent;
    }

    private static QlogEvent CreateListenerIngressClassified(double eventTime, QuicDiagnosticEvent diagnosticEvent)
    {
        QlogEvent qlogEvent = CreateDiagnosticEvent(eventTime, "quic:listener_ingress_classified", diagnosticEvent);

        if (diagnosticEvent.IngressDisposition.HasValue)
        {
            qlogEvent.Data["disposition"] = QlogValue.FromString(diagnosticEvent.IngressDisposition.Value.ToString());
        }

        if (diagnosticEvent.EndpointHandlingKind.HasValue)
        {
            qlogEvent.Data["handling_kind"] = QlogValue.FromString(diagnosticEvent.EndpointHandlingKind.Value.ToString());
        }

        ApplyTuple(qlogEvent, diagnosticEvent.PathIdentity);
        return qlogEvent;
    }

    private static QlogEvent CreateListenerPreAcceptanceClassified(double eventTime, QuicDiagnosticEvent diagnosticEvent)
    {
        QlogEvent qlogEvent = CreateDiagnosticEvent(eventTime, "quic:listener_pre_acceptance_classified", diagnosticEvent);

        if (diagnosticEvent.PreAcceptanceAction.HasValue)
        {
            qlogEvent.Data["action"] = QlogValue.FromString(diagnosticEvent.PreAcceptanceAction.Value.ToString());
        }

        ApplyTuple(qlogEvent, diagnosticEvent.PathIdentity);
        return qlogEvent;
    }

    private static QlogEvent CreateListenerInitialAdmissionResult(double eventTime, QuicDiagnosticEvent diagnosticEvent)
    {
        QlogEvent qlogEvent = CreateDiagnosticEvent(eventTime, "quic:listener_initial_admission_result", diagnosticEvent);

        if (!string.IsNullOrWhiteSpace(diagnosticEvent.AdmissionStage))
        {
            qlogEvent.Data["stage"] = QlogValue.FromString(diagnosticEvent.AdmissionStage);
        }

        if (!string.IsNullOrWhiteSpace(diagnosticEvent.Reason))
        {
            qlogEvent.Data["reason"] = QlogValue.FromString(diagnosticEvent.Reason);
        }

        if (diagnosticEvent.Succeeded.HasValue)
        {
            qlogEvent.Data["succeeded"] = QlogValue.FromBoolean(diagnosticEvent.Succeeded.Value);
        }

        ApplyTuple(qlogEvent, diagnosticEvent.PathIdentity);
        return qlogEvent;
    }

    private static QlogEvent CreateDiagnosticEvent(
        double eventTime,
        string name,
        QuicDiagnosticEvent diagnosticEvent)
    {
        QlogEvent qlogEvent = new()
        {
            Time = eventTime,
            Name = name,
        };

        if (!string.IsNullOrWhiteSpace(diagnosticEvent.Message))
        {
            qlogEvent.Data["message"] = QlogValue.FromString(diagnosticEvent.Message);
        }

        return qlogEvent;
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

    private static QlogEvent CreateHandshakePacketReceived(double eventTime, QuicDiagnosticEvent diagnosticEvent)
    {
        return CreatePacketReceived(
            eventTime,
            diagnosticEvent,
            QlogQuicKnownValues.PacketTypeHandshake,
            version: QuicVersionNegotiation.Version1.ToString("x8"));
    }

    private static QlogEvent CreateHandshakePacketSent(double eventTime, QuicDiagnosticEvent diagnosticEvent)
    {
        return CreatePacketSent(
            eventTime,
            diagnosticEvent,
            QlogQuicKnownValues.PacketTypeHandshake,
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

    private static QlogEvent CreateVersionNegotiationSent(double eventTime, QuicDiagnosticEvent diagnosticEvent)
    {
        return CreatePacketSent(
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

    private static QlogEvent CreateConnectionStateUpdated(double eventTime, string newState)
    {
        QuicConnectionStateUpdated payload = new()
        {
            Old = QlogQuicKnownValues.ConnectionStateHandshakeStarted,
            New = newState,
        };

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

    private static QlogEvent CreateFlowControlBlocked(double eventTime, QuicDiagnosticEvent diagnosticEvent)
    {
        QlogEvent qlogEvent = CreateDiagnosticEvent(eventTime, "quic:flow_control_blocked", diagnosticEvent);
        ApplyStreamAndLimit(qlogEvent, diagnosticEvent);
        return qlogEvent;
    }

    private static QlogEvent CreateStreamLimitBlocked(double eventTime, QuicDiagnosticEvent diagnosticEvent)
    {
        QlogEvent qlogEvent = CreateDiagnosticEvent(eventTime, "quic:stream_limit_blocked", diagnosticEvent);

        if (diagnosticEvent.IsBidirectionalStream.HasValue)
        {
            qlogEvent.Data["stream_type"] = QlogValue.FromString(
                diagnosticEvent.IsBidirectionalStream.Value ? "bidirectional" : "unidirectional");
        }

        ApplyStreamAndLimit(qlogEvent, diagnosticEvent);
        return qlogEvent;
    }

    private static QlogEvent CreatePacketHeaderObserved(double eventTime, QuicDiagnosticEvent diagnosticEvent)
    {
        QlogEvent qlogEvent = CreateDiagnosticEvent(eventTime, "quic:packet_header_observed", diagnosticEvent);

        if (diagnosticEvent.HeaderForm.HasValue)
        {
            qlogEvent.Data["header_form"] = QlogValue.FromString(
                diagnosticEvent.HeaderForm.Value == QuicHeaderForm.Long ? "long" : "short");
        }

        if (!string.IsNullOrWhiteSpace(diagnosticEvent.PacketType))
        {
            qlogEvent.Data["packet_type"] = QlogValue.FromString(diagnosticEvent.PacketType);
        }

        if (diagnosticEvent.PacketIndex.HasValue)
        {
            qlogEvent.Data["packet_index"] = QlogValue.FromNumber(diagnosticEvent.PacketIndex.Value);
        }

        if (diagnosticEvent.PacketOffset.HasValue)
        {
            qlogEvent.Data["packet_offset"] = QlogValue.FromNumber(diagnosticEvent.PacketOffset.Value);
        }

        if (diagnosticEvent.DatagramLength.HasValue)
        {
            qlogEvent.Data["datagram_length"] = QlogValue.FromNumber(diagnosticEvent.DatagramLength.Value);
        }

        ApplyTuple(qlogEvent, diagnosticEvent.PathIdentity);
        return qlogEvent;
    }

    private static QlogEvent CreateCoalescedDatagramReceived(double eventTime, QuicDiagnosticEvent diagnosticEvent)
    {
        QlogEvent qlogEvent = CreateDiagnosticEvent(eventTime, "quic:coalesced_datagram_received", diagnosticEvent);

        if (diagnosticEvent.PacketCount.HasValue)
        {
            qlogEvent.Data["packet_count"] = QlogValue.FromNumber(diagnosticEvent.PacketCount.Value);
        }

        if (diagnosticEvent.DatagramLength.HasValue)
        {
            qlogEvent.Data["datagram_length"] = QlogValue.FromNumber(diagnosticEvent.DatagramLength.Value);
        }

        ApplyTuple(qlogEvent, diagnosticEvent.PathIdentity);
        return qlogEvent;
    }

    private static QlogEvent CreateConnectionIdEvent(double eventTime, string name, QuicDiagnosticEvent diagnosticEvent)
    {
        QlogEvent qlogEvent = CreateDiagnosticEvent(eventTime, name, diagnosticEvent);

        if (diagnosticEvent.ConnectionId.HasValue)
        {
            qlogEvent.Data["connection_id_sequence"] = QlogValue.FromNumber((long)diagnosticEvent.ConnectionId.Value);
        }

        ApplyTuple(qlogEvent, diagnosticEvent.PathIdentity);
        return qlogEvent;
    }

    private static QlogEvent CreatePathValidationDiagnostic(double eventTime, string name, QuicDiagnosticEvent diagnosticEvent)
    {
        QlogEvent qlogEvent = CreateDiagnosticEvent(eventTime, name, diagnosticEvent);

        if (diagnosticEvent.Succeeded.HasValue)
        {
            qlogEvent.Data["succeeded"] = QlogValue.FromBoolean(diagnosticEvent.Succeeded.Value);
        }

        if (diagnosticEvent.ChallengeSendCount.HasValue && diagnosticEvent.ChallengeSendCount.Value <= long.MaxValue)
        {
            qlogEvent.Data["challenge_send_count"] = QlogValue.FromNumber((long)diagnosticEvent.ChallengeSendCount.Value);
        }

        if (diagnosticEvent.IsSet.HasValue)
        {
            qlogEvent.Data["preserve_recovery_state"] = QlogValue.FromBoolean(diagnosticEvent.IsSet.Value);
        }

        ApplyTuple(qlogEvent, diagnosticEvent.PathIdentity);
        return qlogEvent;
    }

    private static QlogEvent CreateSpinBitUpdated(double eventTime, QuicDiagnosticEvent diagnosticEvent)
    {
        QlogEvent qlogEvent = CreateDiagnosticEvent(eventTime, "quic:spin_bit_updated", diagnosticEvent);

        if (diagnosticEvent.IsSet.HasValue)
        {
            qlogEvent.Data["spin_bit"] = QlogValue.FromBoolean(diagnosticEvent.IsSet.Value);
        }

        ApplyTuple(qlogEvent, diagnosticEvent.PathIdentity);
        return qlogEvent;
    }

    private static QlogEvent CreateIcmpPacketTooBigReceived(double eventTime, QuicDiagnosticEvent diagnosticEvent)
    {
        QlogEvent qlogEvent = CreateDiagnosticEvent(eventTime, "quic:icmp_packet_too_big_received", diagnosticEvent);
        ApplyMaximumDatagramSize(qlogEvent, diagnosticEvent);

        if (diagnosticEvent.Accepted.HasValue)
        {
            qlogEvent.Data["accepted"] = QlogValue.FromBoolean(diagnosticEvent.Accepted.Value);
        }

        ApplyTuple(qlogEvent, diagnosticEvent.PathIdentity);
        return qlogEvent;
    }

    private static QlogEvent CreatePmtuUpdated(double eventTime, QuicDiagnosticEvent diagnosticEvent)
    {
        QlogEvent qlogEvent = CreateDiagnosticEvent(eventTime, "quic:pmtu_updated", diagnosticEvent);
        ApplyMaximumDatagramSize(qlogEvent, diagnosticEvent);

        if (diagnosticEvent.IsProvisional.HasValue)
        {
            qlogEvent.Data["provisional"] = QlogValue.FromBoolean(diagnosticEvent.IsProvisional.Value);
        }

        ApplyTuple(qlogEvent, diagnosticEvent.PathIdentity);
        return qlogEvent;
    }

    private static QlogEvent CreateConnectionCloseStateChanged(double eventTime, QuicDiagnosticEvent diagnosticEvent)
    {
        QlogEvent qlogEvent = CreateDiagnosticEvent(eventTime, "quic:connection_close_state_changed", diagnosticEvent);

        if (diagnosticEvent.CloseOrigin.HasValue)
        {
            qlogEvent.Data["origin"] = QlogValue.FromString(diagnosticEvent.CloseOrigin.Value.ToString());
        }

        if (diagnosticEvent.ConnectionPhase.HasValue)
        {
            qlogEvent.Data["phase"] = QlogValue.FromString(diagnosticEvent.ConnectionPhase.Value.ToString());
        }

        return qlogEvent;
    }

    private static QlogEvent CreateUdpError(double eventTime, string name, QuicDiagnosticEvent diagnosticEvent)
    {
        QlogEvent qlogEvent = CreateDiagnosticEvent(eventTime, name, diagnosticEvent);

        if (!string.IsNullOrWhiteSpace(diagnosticEvent.SocketErrorName))
        {
            qlogEvent.Data["socket_error"] = QlogValue.FromString(diagnosticEvent.SocketErrorName);
        }

        if (diagnosticEvent.SocketErrorCode.HasValue)
        {
            qlogEvent.Data["socket_error_code"] = QlogValue.FromNumber(diagnosticEvent.SocketErrorCode.Value);
        }

        return qlogEvent;
    }

    private static QlogEvent CreateAntiAmplificationBlocked(double eventTime, QuicDiagnosticEvent diagnosticEvent)
    {
        QlogEvent qlogEvent = CreateDiagnosticEvent(eventTime, "quic:anti_amplification_blocked", diagnosticEvent);

        if (diagnosticEvent.AttemptedBytes.HasValue && diagnosticEvent.AttemptedBytes.Value <= long.MaxValue)
        {
            qlogEvent.Data["attempted_bytes"] = QlogValue.FromNumber((long)diagnosticEvent.AttemptedBytes.Value);
        }

        if (diagnosticEvent.RemainingSendBudget.HasValue && diagnosticEvent.RemainingSendBudget.Value <= long.MaxValue)
        {
            qlogEvent.Data["remaining_send_budget"] = QlogValue.FromNumber((long)diagnosticEvent.RemainingSendBudget.Value);
        }

        ApplyTuple(qlogEvent, diagnosticEvent.PathIdentity);
        return qlogEvent;
    }

    private static void ApplyMaximumDatagramSize(QlogEvent qlogEvent, QuicDiagnosticEvent diagnosticEvent)
    {
        if (diagnosticEvent.MaximumDatagramSizeBytes.HasValue && diagnosticEvent.MaximumDatagramSizeBytes.Value <= long.MaxValue)
        {
            qlogEvent.Data["maximum_datagram_size_bytes"] = QlogValue.FromNumber((long)diagnosticEvent.MaximumDatagramSizeBytes.Value);
        }
    }

    private static void ApplyStreamAndLimit(QlogEvent qlogEvent, QuicDiagnosticEvent diagnosticEvent)
    {
        if (diagnosticEvent.StreamId.HasValue)
        {
            qlogEvent.Data["stream_id"] = QlogValue.FromNumber((long)diagnosticEvent.StreamId.Value);
        }

        if (diagnosticEvent.Limit.HasValue && diagnosticEvent.Limit.Value <= long.MaxValue)
        {
            qlogEvent.Data["limit"] = QlogValue.FromNumber((long)diagnosticEvent.Limit.Value);
        }
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
