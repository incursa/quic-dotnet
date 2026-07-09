// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;

namespace Incursa.Quic;

// CONTEXT: This helper stays allocation-light on the hot path by formatting into a stack buffer
// first; the 64-character limit is chosen to cover IPv4 and IPv6 textual forms without falling
// back to ToString() in normal cases.
// SEE: QuicSocketPacketInformationSender
/// <summary>
/// Formats IP addresses without taking the string-allocation-heavy <see cref="IPAddress.ToString()"/> path.
/// </summary>
internal static class QuicAddressFormatting
{
    private const int MaximumFormattedAddressCharacters = 64;
    private const int MaximumAddressBytes = 16;
    private const int AddressPartBytes = 8;
    private const int BitsPerByte = 8;
    private const int AddressCacheCapacity = 4;

    [ThreadStatic]
    private static AddressTextCacheEntry[]? cachedAddressEntries;

    [ThreadStatic]
    private static int cachedAddressNextIndex;

    internal static string Format(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        Span<byte> addressBytes = stackalloc byte[MaximumAddressBytes];
        if (address.TryWriteBytes(addressBytes, out int bytesWritten))
        {
            ReadOnlySpan<byte> writtenAddressBytes = addressBytes[..bytesWritten];
            AddressFamily addressFamily = address.AddressFamily;
            ulong addressPart0 = ReadAddressPart(writtenAddressBytes, 0);
            ulong addressPart1 = ReadAddressPart(writtenAddressBytes, AddressPartBytes);

            if (TryGetCachedAddressText(addressFamily, bytesWritten, addressPart0, addressPart1, out string? cachedText))
            {
                return cachedText;
            }

            string formattedAddress = FormatUncached(address);
            CacheAddressText(addressFamily, bytesWritten, addressPart0, addressPart1, formattedAddress);
            return formattedAddress;
        }

        return FormatUncached(address);
    }

    internal static string Format(byte[] addressBytes)
    {
        ArgumentNullException.ThrowIfNull(addressBytes);

        return Format(new IPAddress(addressBytes));
    }

    private static string FormatUncached(IPAddress address)
    {
        Span<char> destination = stackalloc char[MaximumFormattedAddressCharacters];
        if (address.TryFormat(destination, out int charsWritten))
        {
            return new string(destination[..charsWritten]);
        }

        return address.ToString();
    }

    private static ulong ReadAddressPart(ReadOnlySpan<byte> addressBytes, int offset)
    {
        int available = addressBytes.Length - offset;
        if (available <= 0)
        {
            return 0;
        }

        int count = Math.Min(AddressPartBytes, available);
        ulong value = 0;
        for (int i = 0; i < count; i++)
        {
            value = (value << BitsPerByte) | addressBytes[offset + i];
        }

        return value;
    }

    private static bool TryGetCachedAddressText(
        AddressFamily addressFamily,
        int addressLength,
        ulong addressPart0,
        ulong addressPart1,
        [NotNullWhen(true)]
        out string? text)
    {
        AddressTextCacheEntry[]? entries = cachedAddressEntries;
        if (entries is not null)
        {
            foreach (AddressTextCacheEntry entry in entries)
            {
                if (entry.Matches(addressFamily, addressLength, addressPart0, addressPart1))
                {
                    text = entry.Text;
                    return true;
                }
            }
        }

        text = null;
        return false;
    }

    private static void CacheAddressText(
        AddressFamily addressFamily,
        int addressLength,
        ulong addressPart0,
        ulong addressPart1,
        string text)
    {
        AddressTextCacheEntry[] entries = cachedAddressEntries ??= new AddressTextCacheEntry[AddressCacheCapacity];
        entries[cachedAddressNextIndex] = new AddressTextCacheEntry(addressFamily, addressLength, addressPart0, addressPart1, text);
        cachedAddressNextIndex++;
        if (cachedAddressNextIndex == AddressCacheCapacity)
        {
            cachedAddressNextIndex = 0;
        }
    }

    private readonly struct AddressTextCacheEntry(
        AddressFamily addressFamily,
        int addressLength,
        ulong addressPart0,
        ulong addressPart1,
        string text)
    {
        public string Text => text;

        public bool Matches(
            AddressFamily candidateAddressFamily,
            int candidateAddressLength,
            ulong candidateAddressPart0,
            ulong candidateAddressPart1)
        {
            return text is not null
                && addressFamily == candidateAddressFamily
                && addressLength == candidateAddressLength
                && addressPart0 == candidateAddressPart0
                && addressPart1 == candidateAddressPart1;
        }
    }
}
