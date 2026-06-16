// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Http3;

/// <summary>
/// Provides RFC 9484 ADDRESS_REQUEST capsule codec and response policy helpers.
/// </summary>
public static class Http3ConnectIpAddressRequestCapsule
{
    /// <summary>
    /// Gets the RFC 9484 ADDRESS_REQUEST Capsule Type.
    /// </summary>
    public const ulong CapsuleType = 0x02;

    /// <summary>
    /// Returns true when an endpoint expecting an address assignment must send ADDRESS_REQUEST.
    /// </summary>
    public static bool ShouldSendAddressRequest(bool expectingAddressAssignment, bool needsAddressAssignment)
    {
        return expectingAddressAssignment && needsAddressAssignment;
    }

    /// <summary>
    /// Indicates that ADDRESS_ASSIGN capsules may be sent without a preceding request.
    /// </summary>
    public const bool CanSendUnpromptedAddressAssign = true;

    /// <summary>
    /// Creates an ADDRESS_REQUEST capsule containing one or more Requested Addresses.
    /// </summary>
    public static Http3Capsule Create(IReadOnlyList<Http3ConnectIpRequestedAddress> requestedAddresses)
    {
        ArgumentNullException.ThrowIfNull(requestedAddresses);
        ValidateRequestIds(requestedAddresses);
        if (requestedAddresses.Count == 0)
        {
            throw new ArgumentException("CONNECT-IP ADDRESS_REQUEST must contain at least one Requested Address.", nameof(requestedAddresses));
        }

        List<byte> payload = [];
        for (int index = 0; index < requestedAddresses.Count; index++)
        {
            AppendRequestedAddress(payload, requestedAddresses[index]);
        }

        return new Http3Capsule(CapsuleType, payload.ToArray());
    }

    /// <summary>
    /// Parses an ADDRESS_REQUEST capsule payload.
    /// </summary>
    public static Http3ConnectIpRequestedAddress[] Parse(Http3Capsule capsule)
    {
        ArgumentNullException.ThrowIfNull(capsule);
        if (capsule.Type != CapsuleType)
        {
            throw Malformed("CONNECT-IP ADDRESS_REQUEST capsule type must be 0x02.");
        }

        List<Http3ConnectIpRequestedAddress> requestedAddresses = [];
        ReadOnlySpan<byte> payload = capsule.Payload;
        int offset = 0;
        while (offset < payload.Length)
        {
            requestedAddresses.Add(ReadRequestedAddress(payload, ref offset));
        }

        if (requestedAddresses.Count == 0)
        {
            throw Malformed("CONNECT-IP ADDRESS_REQUEST must contain at least one Requested Address.");
        }

        ValidateRequestIds(requestedAddresses);
        return requestedAddresses.ToArray();
    }

    /// <summary>
    /// Returns true when the Requested Address request IDs are unique and non-zero.
    /// </summary>
    public static bool RequestIdsAreUniqueAndNonZero(IReadOnlyList<Http3ConnectIpRequestedAddress> requestedAddresses)
    {
        ArgumentNullException.ThrowIfNull(requestedAddresses);
        HashSet<ulong> seen = [];
        for (int index = 0; index < requestedAddresses.Count; index++)
        {
            ulong requestId = requestedAddresses[index].RequestId;
            if (requestId == 0 || !seen.Add(requestId))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Returns true when an endpoint must abort after receiving an empty ADDRESS_REQUEST capsule.
    /// </summary>
    public static bool ShouldAbortRequestStreamForEmptyAddressRequest(int requestedAddressCount)
    {
        return requestedAddressCount == 0;
    }

    /// <summary>
    /// Returns true when an endpoint should respond with ADDRESS_ASSIGN after processing ADDRESS_REQUEST.
    /// </summary>
    public static bool ShouldRespondWithAddressAssign(bool addressRequestReceived, bool canAssignAtLeastOneAddress)
    {
        return addressRequestReceived && canAssignAtLeastOneAddress;
    }

    /// <summary>
    /// Creates an Assigned Address response for a Requested Address.
    /// </summary>
    public static Http3ConnectIpAssignedAddress CreateAssignedAddressResponse(
        Http3ConnectIpRequestedAddress requestedAddress,
        IPAddress? assignedAddress,
        int? assignedPrefixLength)
    {
        ArgumentNullException.ThrowIfNull(requestedAddress);
        if (assignedAddress is null)
        {
            return CreateUnassignedAddressResponse(requestedAddress);
        }

        return new Http3ConnectIpAssignedAddress(
            requestedAddress.RequestId,
            assignedAddress,
            assignedPrefixLength ?? requestedAddress.PrefixLength);
    }

    /// <summary>
    /// Returns true when an Assigned Address response matches a Requested Address request ID.
    /// </summary>
    public static bool ResponseMatchesRequestId(Http3ConnectIpRequestedAddress requestedAddress, Http3ConnectIpAssignedAddress assignedAddress)
    {
        ArgumentNullException.ThrowIfNull(requestedAddress);
        ArgumentNullException.ThrowIfNull(assignedAddress);
        return requestedAddress.RequestId == assignedAddress.RequestId;
    }

    /// <summary>
    /// Returns true when a rejected address should appear in later ADDRESS_ASSIGN capsules.
    /// </summary>
    public static bool ShouldIncludeRejectedAddressInSubsequentAssignments(bool addressRejected)
    {
        return !addressRejected;
    }

    private static Http3ConnectIpAssignedAddress CreateUnassignedAddressResponse(Http3ConnectIpRequestedAddress requestedAddress)
    {
        IPAddress zeroAddress = requestedAddress.IpVersion == Http3ConnectIpScopePolicy.Ipv4Version
            ? IPAddress.Parse("0.0.0.0")
            : IPAddress.IPv6None;
        int prefixLength = Http3ConnectIpAssignedAddress.GetBitLength(requestedAddress.IpVersion);
        return new Http3ConnectIpAssignedAddress(requestedAddress.RequestId, zeroAddress, prefixLength);
    }

    private static void AppendRequestedAddress(List<byte> payload, Http3ConnectIpRequestedAddress requestedAddress)
    {
        ArgumentNullException.ThrowIfNull(requestedAddress);

        byte[] requestId = Http3ConnectIpFoundationPolicy.EncodeVariableLengthInteger(requestedAddress.RequestId);
        payload.AddRange(requestId);
        payload.Add((byte)requestedAddress.IpVersion);
        payload.AddRange(requestedAddress.Address.GetAddressBytes());
        payload.Add((byte)requestedAddress.PrefixLength);
    }

    private static Http3ConnectIpRequestedAddress ReadRequestedAddress(ReadOnlySpan<byte> payload, ref int offset)
    {
        if (!Http3VariableLengthInteger.TryParse(payload[offset..], out ulong requestId, out int bytesConsumed))
        {
            throw Malformed("CONNECT-IP ADDRESS_REQUEST Request ID is malformed.");
        }

        offset += bytesConsumed;
        if (offset >= payload.Length)
        {
            throw Malformed("CONNECT-IP ADDRESS_REQUEST IP Version field is truncated.");
        }

        int ipVersion = payload[offset++];
        int addressLength = ipVersion switch
        {
            Http3ConnectIpScopePolicy.Ipv4Version => 4,
            Http3ConnectIpScopePolicy.Ipv6Version => 16,
            _ => throw Malformed("CONNECT-IP ADDRESS_REQUEST IP Version must be 4 or 6."),
        };

        if (payload.Length - offset < addressLength + 1)
        {
            throw Malformed("CONNECT-IP ADDRESS_REQUEST IP Address or Prefix Length field is truncated.");
        }

        IPAddress address = new(payload.Slice(offset, addressLength));
        offset += addressLength;
        int prefixLength = payload[offset++];
        try
        {
            return new Http3ConnectIpRequestedAddress(requestId, address, prefixLength);
        }
        catch (ArgumentException)
        {
            throw Malformed("CONNECT-IP ADDRESS_REQUEST requested address fields are malformed.");
        }
    }

    private static void ValidateRequestIds(IReadOnlyList<Http3ConnectIpRequestedAddress> requestedAddresses)
    {
        if (!RequestIdsAreUniqueAndNonZero(requestedAddresses))
        {
            throw Malformed("CONNECT-IP ADDRESS_REQUEST Request IDs must be unique and non-zero.");
        }
    }

    private static Http3Exception Malformed(string message)
    {
        return new Http3Exception(Http3ErrorCode.MessageError, message);
    }
}
