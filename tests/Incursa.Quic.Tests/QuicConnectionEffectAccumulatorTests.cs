// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class QuicConnectionEffectAccumulatorTests
{
    [Fact]
    public void Add_KeepsEightEffectsReadableWithoutOverflow()
    {
        QuicConnectionEffectAccumulator accumulator = default;
        QuicConnectionEffect[] effects = CreateTimerEffects(8);

        foreach (QuicConnectionEffect effect in effects)
        {
            accumulator.Add(effect);
        }

        Assert.Equal(8, accumulator.Count);
        Assert.True(accumulator.HasEffects);
        Assert.Same(effects[7], accumulator.GetEffect(7));
        Assert.Equal(effects, accumulator.ToArray());
    }

    [Fact]
    public void Add_SpillsNinthEffectWithoutChangingOrder()
    {
        QuicConnectionEffectAccumulator accumulator = default;
        QuicConnectionEffect[] effects = CreateTimerEffects(9);

        foreach (QuicConnectionEffect effect in effects)
        {
            accumulator.Add(effect);
        }

        Assert.Equal(9, accumulator.Count);
        Assert.Equal(effects, accumulator.ToArray());
        Assert.NotNull(accumulator.ToList());
        Assert.Equal(effects, accumulator.ToList());
    }

    private static QuicConnectionEffect[] CreateTimerEffects(int count)
    {
        QuicConnectionEffect[] effects = new QuicConnectionEffect[count];
        for (int index = 0; index < count; index++)
        {
            effects[index] = new QuicConnectionArmTimerEffect(
                QuicConnectionTimerKind.AckDelay,
                Generation: (ulong)index + 1,
                new QuicConnectionTimerPriority(DueTicks: index + 1, Sequence: (ulong)index));
        }

        return effects;
    }
}
