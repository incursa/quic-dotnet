// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Http3;

/// <summary>
/// Provides RFC 9484 ADDRESS_ASSIGN capsule codec and assignment-list policy helpers.
/// </summary>
public static class Http3ConnectIpAddressAssignCapsule
{
    /// <summary>
    /// Gets the RFC 9484 ADDRESS_ASSIGN Capsule Type.
    /// </summary>
    public const ulong CapsuleType = 0x01;

    /// <summary>
    /// Returns true when an endpoint may send the requested number of CONNECT-IP capsules.
    /// </summary>
    public static bool CanSendNewCapsuleCount(int capsuleCount)
    {
        return capsuleCount >= 0;
    }

    /// <summary>
    /// Creates an ADDRESS_ASSIGN capsule containing the supplied complete assignment list.
    /// </summary>
    public static Http3Capsule Create(IReadOnlyList<Http3ConnectIpAssignedAddress> assignedAddresses)
    {
        ArgumentNullException.ThrowIfNull(assignedAddresses);

        List<byte> payload = [];
        for (int index = 0; index < assignedAddresses.Count; index++)
        {
            AppendAssignedAddress(payload, assignedAddresses[index]);
        }

        return new Http3Capsule(CapsuleType, payload.ToArray());
    }

    /// <summary>
    /// Parses an ADDRESS_ASSIGN capsule payload.
    /// </summary>
    public static Http3ConnectIpAssignedAddress[] Parse(Http3Capsule capsule)
    {
        ArgumentNullException.ThrowIfNull(capsule);
        if (capsule.Type != CapsuleType)
        {
            throw Malformed("CONNECT-IP ADDRESS_ASSIGN capsule type must be 0x01.");
        }

        List<Http3ConnectIpAssignedAddress> assignedAddresses = [];
        ReadOnlySpan<byte> payload = capsule.Payload;
        int offset = 0;
        while (offset < payload.Length)
        {
            assignedAddresses.Add(ReadAssignedAddress(payload, ref offset));
        }

        return assignedAddresses.ToArray();
    }

    /// <summary>
    /// Returns true when an ADDRESS_ASSIGN capsule contains the complete assigned prefix list.
    /// </summary>
    public static bool ContainsFullAssignedPrefixList(
        IReadOnlyList<Http3ConnectIpAssignedAddress> currentAssignments,
        IReadOnlyList<Http3ConnectIpAssignedAddress> capsuleAssignments)
    {
        ArgumentNullException.ThrowIfNull(currentAssignments);
        ArgumentNullException.ThrowIfNull(capsuleAssignments);

        if (currentAssignments.Count != capsuleAssignments.Count)
        {
            return false;
        }

        HashSet<string> expected = [];
        for (int index = 0; index < currentAssignments.Count; index++)
        {
            expected.Add(CreateAssignmentKey(currentAssignments[index]));
        }

        for (int index = 0; index < capsuleAssignments.Count; index++)
        {
            if (!expected.Remove(CreateAssignmentKey(capsuleAssignments[index])))
            {
                return false;
            }
        }

        return expected.Count == 0;
    }

    /// <summary>
    /// Applies the complete assignment list semantics of ADDRESS_ASSIGN.
    /// </summary>
    public static Http3ConnectIpAssignedAddress[] ApplyCompleteAssignmentList(
        IReadOnlyList<Http3ConnectIpAssignedAddress> previousAssignments,
        IReadOnlyList<Http3ConnectIpAssignedAddress> capsuleAssignments)
    {
        ArgumentNullException.ThrowIfNull(previousAssignments);
        ArgumentNullException.ThrowIfNull(capsuleAssignments);
        return [.. capsuleAssignments];
    }

    private static void AppendAssignedAddress(List<byte> payload, Http3ConnectIpAssignedAddress assignedAddress)
    {
        ArgumentNullException.ThrowIfNull(assignedAddress);

        byte[] requestId = Http3ConnectIpFoundationPolicy.EncodeVariableLengthInteger(assignedAddress.RequestId);
        payload.AddRange(requestId);
        payload.Add((byte)assignedAddress.IpVersion);
        payload.AddRange(assignedAddress.Address.GetAddressBytes());
        payload.Add((byte)assignedAddress.PrefixLength);
    }

    private static Http3ConnectIpAssignedAddress ReadAssignedAddress(ReadOnlySpan<byte> payload, ref int offset)
    {
        if (!Http3VariableLengthInteger.TryParse(payload[offset..], out ulong requestId, out int bytesConsumed))
        {
            throw Malformed("CONNECT-IP ADDRESS_ASSIGN Request ID is malformed.");
        }

        offset += bytesConsumed;
        if (offset >= payload.Length)
        {
            throw Malformed("CONNECT-IP ADDRESS_ASSIGN IP Version field is truncated.");
        }

        int ipVersion = payload[offset++];
        int addressLength = ipVersion switch
        {
            Http3ConnectIpScopePolicy.Ipv4Version => 4,
            Http3ConnectIpScopePolicy.Ipv6Version => 16,
            _ => throw Malformed("CONNECT-IP ADDRESS_ASSIGN IP Version must be 4 or 6."),
        };

        if (payload.Length - offset < addressLength + 1)
        {
            throw Malformed("CONNECT-IP ADDRESS_ASSIGN IP Address or Prefix Length field is truncated.");
        }

        IPAddress address = new(payload.Slice(offset, addressLength));
        offset += addressLength;
        int prefixLength = payload[offset++];
        try
        {
            return new Http3ConnectIpAssignedAddress(requestId, address, prefixLength);
        }
        catch (ArgumentException)
        {
            throw Malformed("CONNECT-IP ADDRESS_ASSIGN assigned address fields are malformed.");
        }
    }

    private static string CreateAssignmentKey(Http3ConnectIpAssignedAddress assignedAddress)
    {
        return string.Create(
            System.Globalization.CultureInfo.InvariantCulture,
            $"{assignedAddress.RequestId}|{assignedAddress.IpVersion}|{assignedAddress.Address}|{assignedAddress.PrefixLength}");
    }

    private static Http3Exception Malformed(string message)
    {
        return new Http3Exception(Http3ErrorCode.MessageError, message);
    }
}
