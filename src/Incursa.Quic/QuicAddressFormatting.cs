// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic;

/// <summary>
/// Formats IP addresses without taking the string-allocation-heavy <see cref="IPAddress.ToString()"/> path.
/// </summary>
internal static class QuicAddressFormatting
{
    private const int MaximumFormattedAddressCharacters = 64;

    internal static string Format(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        Span<char> destination = stackalloc char[MaximumFormattedAddressCharacters];
        if (address.TryFormat(destination, out int charsWritten))
        {
            return new string(destination[..charsWritten]);
        }

        return address.ToString();
    }

    internal static string Format(byte[] addressBytes)
    {
        ArgumentNullException.ThrowIfNull(addressBytes);

        return Format(new IPAddress(addressBytes));
    }
}
