// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics.Metrics;

namespace Incursa.Quic.Tests.RequirementHomes.CRT;

[Collection(ApplicationSendPressureMetricTestCollection.Name)]
public sealed class ReqQuicCrt0163
{
    [Fact]
    public void MissingQueueDelayCannotPromoteSparseMode()
    {
        QuicApplicationSendPressureClassifier classifier = default;

        for (int index = 0; index < 8; index++)
        {
            QuicApplicationSendPressureObservation observation = classifier.ObserveTurn(
                QuicApplicationSendPressureClassifier.MaximumObservedDistinctStreamCount,
                burstLimitReached: true);
            Assert.Equal(QuicApplicationSendPressureMode.Sparse, observation.Mode);
        }
    }

    [Fact]
    public void SustainedModerateDelayAndRunnablePressureEnterCooperativeMode()
    {
        QuicApplicationSendPressureClassifier classifier = default;
        classifier.ObserveQueueDelay(5);

        QuicApplicationSendPressureObservation first = classifier.ObserveTurn(
            distinctQueuedStreamCount: 1,
            burstLimitReached: true);
        QuicApplicationSendPressureObservation second = classifier.ObserveTurn(
            distinctQueuedStreamCount: 1,
            burstLimitReached: true);

        Assert.Equal(QuicApplicationSendPressureMode.Sparse, first.Mode);
        Assert.Equal(QuicApplicationSendPressureMode.Cooperative, second.Mode);
        Assert.True(second.ModeChanged);
        Assert.Equal(5_000, second.QueueDelayEwmaMicros);
    }

    [Fact]
    public void SustainedHighDelayEntersSaturatedModeWithoutAQueueDepthSignal()
    {
        QuicApplicationSendPressureClassifier classifier = default;
        classifier.ObserveQueueDelay(24);

        QuicApplicationSendPressureObservation first = classifier.ObserveTurn(
            distinctQueuedStreamCount: 1,
            burstLimitReached: false);
        QuicApplicationSendPressureObservation second = classifier.ObserveTurn(
            distinctQueuedStreamCount: 1,
            burstLimitReached: false);

        Assert.Equal(QuicApplicationSendPressureMode.Sparse, first.Mode);
        Assert.Equal(QuicApplicationSendPressureMode.Saturated, second.Mode);
    }

    [Fact]
    public void TransientHighDelayDoesNotOscillateCooperativeMode()
    {
        QuicApplicationSendPressureClassifier classifier = default;
        classifier.ObserveQueueDelay(5);
        _ = classifier.ObserveTurn(1, burstLimitReached: true);
        Assert.Equal(
            QuicApplicationSendPressureMode.Cooperative,
            classifier.ObserveTurn(1, burstLimitReached: true).Mode);

        classifier.ObserveQueueDelay(80);
        QuicApplicationSendPressureObservation transient = classifier.ObserveTurn(
            1,
            burstLimitReached: true);

        Assert.Equal(QuicApplicationSendPressureMode.Cooperative, transient.Mode);
        Assert.False(transient.ModeChanged);
    }

    [Fact]
    public void SaturatedModeRequiresSustainedReliefBeforeDemotion()
    {
        QuicApplicationSendPressureClassifier classifier = default;
        classifier.ObserveQueueDelay(24);
        _ = classifier.ObserveTurn(1, burstLimitReached: true);
        Assert.Equal(
            QuicApplicationSendPressureMode.Saturated,
            classifier.ObserveTurn(1, burstLimitReached: true).Mode);

        int reliefObservations = 0;
        for (; reliefObservations < 4; reliefObservations++)
        {
            classifier.ObserveQueueDelay(0);
            Assert.Equal(
                QuicApplicationSendPressureMode.Saturated,
                classifier.ObserveTurn(0, burstLimitReached: false).Mode);
        }

        while (classifier.Mode == QuicApplicationSendPressureMode.Saturated
            && reliefObservations < 12)
        {
            classifier.ObserveQueueDelay(0);
            _ = classifier.ObserveTurn(0, burstLimitReached: false);
            reliefObservations++;
        }

        Assert.Equal(QuicApplicationSendPressureMode.Sparse, classifier.Mode);
        Assert.InRange(reliefObservations, 5, 12);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(double.NaN)]
    [InlineData(double.PositiveInfinity)]
    public void InvalidQueueDelayIsRejected(double queueDelayMilliseconds)
    {
        QuicApplicationSendPressureClassifier classifier = default;

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            classifier.ObserveQueueDelay(queueDelayMilliseconds));
    }

    [Fact]
    public void SteadyStateObservationsDoNotAllocate()
    {
        QuicApplicationSendPressureClassifier classifier = default;
        classifier.ObserveQueueDelay(5);
        _ = classifier.ObserveTurn(1, burstLimitReached: true);
        _ = classifier.ObserveTurn(1, burstLimitReached: true);

        long allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
        for (int index = 0; index < 10_000; index++)
        {
            _ = classifier.ObserveTurn(1, burstLimitReached: true);
        }

        Assert.Equal(allocatedBefore, GC.GetAllocatedBytesForCurrentThread());
    }

    [Theory]
    [InlineData((int)QuicApplicationSendPressureMode.Sparse, "sparse")]
    [InlineData((int)QuicApplicationSendPressureMode.Cooperative, "cooperative")]
    [InlineData((int)QuicApplicationSendPressureMode.Saturated, "saturated")]
    public void MetricModeNamesAreStable(
        int mode,
        string expected)
        => Assert.Equal(
            expected,
            QuicMetrics.FormatApplicationSendPressureMode((QuicApplicationSendPressureMode)mode));

    [Fact]
    public void ShadowMetricListenerEnablesStreamWriteTimingAndReceivesObservation()
    {
        long observationCount = 0;
        Assert.False(QuicMetrics.ApplicationSendPressureShadowEnabled);
        Assert.Equal(
            0,
            QuicMetrics.GetRuntimeShardEnqueueTimestamp(
                QuicConnectionRuntimeShardWorkItemKind.StreamWrite));

        using (MeterListener listener = new()
        {
            InstrumentPublished = (instrument, meterListener) =>
            {
                if (instrument.Meter.Name == QuicMetrics.MeterName
                    && instrument.Name == "incursa.quic.runtime.application_send.pressure.shadow.observations")
                {
                    meterListener.EnableMeasurementEvents(instrument);
                }
            },
        })
        {
            listener.SetMeasurementEventCallback<long>((instrument, value, _, _) =>
            {
                if (instrument.Name == "incursa.quic.runtime.application_send.pressure.shadow.observations")
                {
                    observationCount += value;
                }
            });
            listener.Start();

            Assert.True(QuicMetrics.ApplicationSendPressureShadowEnabled);
            Assert.NotEqual(
                0,
                QuicMetrics.GetRuntimeShardEnqueueTimestamp(
                    QuicConnectionRuntimeShardWorkItemKind.StreamWrite));

            QuicApplicationSendPressureObservation observation = new(
                QuicApplicationSendPressureMode.Cooperative,
                QuicApplicationSendPressureMode.Sparse,
                QueueDelayEwmaMicros: 5_000,
                DistinctQueuedStreamCount: 8,
                BurstLimitReached: true);
            QuicMetrics.RecordApplicationSendPressureShadow(
                QuicTlsRole.Client,
                in observation);

            Assert.Equal(1, observationCount);
        }

        Assert.False(QuicMetrics.ApplicationSendPressureShadowEnabled);
        Assert.Equal(
            0,
            QuicMetrics.GetRuntimeShardEnqueueTimestamp(
                QuicConnectionRuntimeShardWorkItemKind.StreamWrite));
    }
}

[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class ApplicationSendPressureMetricTestCollection
{
    public const string Name = "Application-send pressure metric tests";
}
