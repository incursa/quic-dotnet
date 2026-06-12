// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// DNS over QUIC server policy options.
/// </summary>
public sealed class DoqServerOptions
{
    private int maxDanglingStreams;
    private int maxCancellationRequests;
    private int maxQueuedZeroRttTransactions;
    private TimeSpan resumptionTicketLifetime;

    /// <summary>
    /// Initializes a new instance of the <see cref="DoqServerOptions"/> class.
    /// </summary>
    public DoqServerOptions()
    {
        resumptionTicketLifetime = TimeSpan.FromHours(6);
    }

    /// <summary>
    /// Gets or sets the maximum number of concurrently accepted query streams that have not completed.
    /// A value of zero disables the adapter-level limit.
    /// </summary>
    public int MaxDanglingStreams
    {
        get => maxDanglingStreams;
        set
        {
            ArgumentOutOfRangeException.ThrowIfNegative(value);
            maxDanglingStreams = value;
        }
    }

    /// <summary>
    /// Gets or sets the maximum number of request cancellation/reset events allowed on a connection.
    /// A value of zero disables the adapter-level limit.
    /// </summary>
    public int MaxCancellationRequests
    {
        get => maxCancellationRequests;
        set
        {
            ArgumentOutOfRangeException.ThrowIfNegative(value);
            maxCancellationRequests = value;
        }
    }

    /// <summary>
    /// Gets or sets the maximum number of non-replayable 0-RTT transactions that may be queued
    /// on a connection while the QUIC handshake completes. A value of zero disables queuing;
    /// non-replayable 0-RTT transactions are immediately refused.
    /// </summary>
    public int MaxQueuedZeroRttTransactions
    {
        get => maxQueuedZeroRttTransactions;
        set
        {
            ArgumentOutOfRangeException.ThrowIfNegative(value);
            maxQueuedZeroRttTransactions = value;
        }
    }

    /// <summary>
    /// Gets or sets the lifetime for session resumption tickets issued by this server.
    /// The default is 6 hours per RFC 9250 guidance.
    /// </summary>
    public TimeSpan ResumptionTicketLifetime
    {
        get => resumptionTicketLifetime;
        set
        {
            if (value <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(value), value, "Resumption ticket lifetime must be positive.");
            }

            resumptionTicketLifetime = value;
        }
    }

    /// <summary>
    /// Gets or sets a value indicating whether anti-replay mechanisms (RFC 8446 Section 8)
    /// are enabled for session resumption tickets. Defaults to <c>true</c>.
    /// </summary>
    public bool EnableAntiReplay { get; set; } = true;

    /// <summary>
    /// Gets or sets a detector that identifies whether an accepted query stream arrived in QUIC 0-RTT data.
    /// The current transport surface does not expose early-data state directly, so the default is <c>null</c>
    /// and all streams are treated as handshake-confirmed unless a hosting layer supplies this signal.
    /// </summary>
    public Func<QuicConnection, QuicStream, bool>? ZeroRttStreamDetector { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the 3x anti-amplification limit is enforced
    /// for server responses in the pre-validation state. When <c>true</c>, responses larger
    /// than 3x the received query size are truncated or rejected.
    /// Defaults to <c>true</c>.
    /// </summary>
    public bool EnforceAmplificationLimit { get; set; } = true;

    /// <summary>
    /// Gets or sets a value indicating whether QUIC Retry packets should be issued for
    /// new connection attempts. The underlying QUIC transport manages Retry behavior
    /// internally; this option surfaces the policy intent.
    /// Defaults to <c>true</c>.
    /// </summary>
    public bool UseRetryPackets { get; set; } = true;

    /// <summary>
    /// Gets or sets a value indicating whether address validation tokens (NEW_TOKEN frames)
    /// are issued for future connections. The underlying QUIC transport manages address
    /// validation internally; this option surfaces the policy intent.
    /// Defaults to <c>true</c>.
    /// </summary>
    public bool UseAddressValidationForFutureConnections { get; set; } = true;

    /// <summary>
    /// Gets or sets the EDNS(0) padding block size for server responses.
    /// Responses are padded to the next multiple of this value.
    /// A value of 0 or 1 disables padding.
    /// Defaults to <see cref="DoqDefaults.PaddingBlockSize"/> (128).
    /// </summary>
    public int PaddingBlockSize { get; set; } = DoqDefaults.PaddingBlockSize;
}
