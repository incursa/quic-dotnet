// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// RFC 9463 encrypted DNS discovery option code points and scalar constants.
/// </summary>
public static class EncryptedDnsDiscoveryOptionCodes
{
    /// <summary>
    /// DHCPv6 OPTION_V6_DNR option code.
    /// </summary>
    public const ushort Dhcpv6OptionV6Dnr = 144;

    /// <summary>
    /// DHCPv4 OPTION_V4_DNR option tag.
    /// </summary>
    public const byte Dhcpv4OptionV4Dnr = 162;

    /// <summary>
    /// Neighbor Discovery encrypted DNS option type.
    /// </summary>
    public const byte NeighborDiscoveryEncryptedDnsOptionType = 144;

    /// <summary>
    /// Router Advertisement lifetime value that represents infinity.
    /// </summary>
    public const uint InfiniteLifetime = uint.MaxValue;

    /// <summary>
    /// Router Advertisement lifetime value that retires an ADN.
    /// </summary>
    public const uint RetiringLifetime = 0;

    /// <summary>
    /// SvcParam key that is forbidden inside RFC 9463 encrypted DNS options.
    /// </summary>
    public const string Ipv4HintServiceParameterKey = "ipv4hint";

    /// <summary>
    /// SvcParam key that is forbidden inside RFC 9463 encrypted DNS options.
    /// </summary>
    public const string Ipv6HintServiceParameterKey = "ipv6hint";
}
