// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Runtime.CompilerServices;

namespace Incursa.Quic.Tests;

public sealed class QuicConnectionSentPacketKeyTests
{
    [Fact]
    public void PackedKeyOccupiesOneMachineWord()
    {
        Assert.Equal(sizeof(ulong), Unsafe.SizeOf<QuicConnectionSentPacketKey>());
    }

    [Fact]
    public void DefaultKeyRepresentsInitialPacketZero()
    {
        QuicConnectionSentPacketKey key = default;

        Assert.Equal(QuicPacketNumberSpace.Initial, key.PacketNumberSpace);
        Assert.Equal(0UL, key.PacketNumber);
        Assert.Equal(new QuicConnectionSentPacketKey(QuicPacketNumberSpace.Initial, 0), key);
    }

    [Theory]
    [InlineData((int)QuicPacketNumberSpace.Initial, 0UL)]
    [InlineData((int)QuicPacketNumberSpace.Handshake, 1UL)]
    [InlineData((int)QuicPacketNumberSpace.ApplicationData, QuicVariableLengthInteger.MaxValue)]
    public void ConstructorRoundTripsPacketNumberSpaceAndPacketNumber(
        int packetNumberSpaceValue,
        ulong packetNumber)
    {
        QuicPacketNumberSpace packetNumberSpace = (QuicPacketNumberSpace)packetNumberSpaceValue;
        QuicConnectionSentPacketKey key = new(packetNumberSpace, packetNumber);

        Assert.Equal(packetNumberSpace, key.PacketNumberSpace);
        Assert.Equal(packetNumber, key.PacketNumber);
    }

    [Fact]
    public void EqualityDistinguishesPacketNumberSpaceAndPacketNumber()
    {
        QuicConnectionSentPacketKey key = new(QuicPacketNumberSpace.ApplicationData, 42);

        Assert.Equal(key, new QuicConnectionSentPacketKey(QuicPacketNumberSpace.ApplicationData, 42));
        Assert.NotEqual(key, new QuicConnectionSentPacketKey(QuicPacketNumberSpace.Handshake, 42));
        Assert.NotEqual(key, new QuicConnectionSentPacketKey(QuicPacketNumberSpace.ApplicationData, 43));
    }

    [Fact]
    public void DictionaryKeepsPacketNumberSpacesDistinct()
    {
        Dictionary<QuicConnectionSentPacketKey, string> packets = [];
        packets[new QuicConnectionSentPacketKey(QuicPacketNumberSpace.Initial, 7)] = "initial";
        packets[new QuicConnectionSentPacketKey(QuicPacketNumberSpace.Handshake, 7)] = "handshake";
        packets[new QuicConnectionSentPacketKey(QuicPacketNumberSpace.ApplicationData, 7)] = "application";

        Assert.Equal(3, packets.Count);
        Assert.Equal("initial", packets[new QuicConnectionSentPacketKey(QuicPacketNumberSpace.Initial, 7)]);
        Assert.Equal("handshake", packets[new QuicConnectionSentPacketKey(QuicPacketNumberSpace.Handshake, 7)]);
        Assert.Equal("application", packets[new QuicConnectionSentPacketKey(QuicPacketNumberSpace.ApplicationData, 7)]);
    }

    [Fact]
    public void ConstructorRejectsValuesThatCannotBePacked()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new QuicConnectionSentPacketKey((QuicPacketNumberSpace)3, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new QuicConnectionSentPacketKey(QuicPacketNumberSpace.Initial, QuicVariableLengthInteger.MaxValue + 1));
    }
}
