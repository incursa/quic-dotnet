// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers.Binary;

namespace Incursa.Quic.Dns;

/// <summary>
/// Provides EDNS(0) padding for DoQ messages to mitigate traffic analysis.
/// Padding follows RFC 7830 and RFC 8467 recommendations.
/// </summary>
public static class DoqPadding
{
    /// <summary>
    /// The EDNS(0) option code for padding as defined in RFC 7830.
    /// </summary>
    public const int PaddingOptionCode = 12;

    private const ushort OptRecordType = 41;
    private const int U16 = 2;
    private const int DnsHdr = 12;
    private const int QFixed = 4;
    private const int RdOff = 8;
    private const int RecSz = 10;
    private const int OptOvhd = 11;
    private const int PadOpt = 4;
    private const int ArcMsb = 10;
    private const int QdMsb = 4;
    private const int QdEnd = QdMsb + U16;
    private const int U32 = 4;
    private const int BitShift = 8;

    /// <summary>
    /// Adds EDNS(0) padding to a DNS message payload (without the DoQ length prefix).
    /// The message is padded to the next multiple of <paramref name="blockSize"/> bytes.
    /// </summary>
    public static byte[] PadMessage(ReadOnlySpan<byte> msg, int blockSize)
    {
        if (blockSize <= 1 || msg.Length < DnsHdr)
        {
            return msg.ToArray();
        }

        int qd = BinaryPrimitives.ReadUInt16BigEndian(msg[QdMsb..QdEnd]);
        int p = DnsHdr;
        for (int i = 0; i < qd && p < msg.Length; i++)
        {
            if (!Skip(msg, ref p)) return msg.ToArray();
            p += QFixed;
        }

        int optOff = -1;
        int arc = BinaryPrimitives.ReadUInt16BigEndian(msg[ArcMsb..(ArcMsb + U16)]);
        if (arc > 0)
        {
            int s = p;
            for (int i = 0; i < arc && s < msg.Length; i++)
            {
                if (!Skip(msg, ref s)) break;
                if (s + U16 > msg.Length) break;
                if (BinaryPrimitives.ReadUInt16BigEndian(msg[s..(s + U16)]) == OptRecordType && i == arc - 1)
                {
                    optOff = s - 1; break;
                }
                if (s + RdOff > msg.Length) break;
                ushort rdl = BinaryPrimitives.ReadUInt16BigEndian(msg[(s + RdOff)..(s + RecSz)]);
                s += RecSz + rdl;
            }
        }

        int ovhd = optOff >= 0 ? PadOpt : OptOvhd + PadOpt;
        int baseLen = msg.Length + ovhd;
        int mod = baseLen % blockSize;
        if (mod == 0)
        {
            if (optOff < 0 && msg.Length + OptOvhd > DoqMessageCodec.MaxPayloadLength)
            {
                return msg.ToArray();
            }

            return optOff >= 0 ? msg.ToArray() : Build(msg, p, optOff, 0);
        }

        int padLen = blockSize - mod;
        int total = baseLen + padLen;
        if (total > DoqMessageCodec.MaxPayloadLength)
        {
            padLen = DoqMessageCodec.MaxPayloadLength - baseLen;
            if (padLen < U16) return msg.ToArray();
        }

        return Build(msg, p, optOff, padLen);
    }

    private static byte[] Build(ReadOnlySpan<byte> msg, int addStart, int optOff, int padLen)
    {
        int curLen = msg.Length;

        if (optOff >= 0)
        {
            int origRdl = BinaryPrimitives.ReadUInt16BigEndian(msg[(optOff + RdOff)..(optOff + RecSz)]);
            if (padLen <= 0) return msg.ToArray();

            int newRdl = origRdl + PadOpt + padLen;
            byte[] r = new byte[curLen - origRdl + newRdl];
            msg[..(optOff + RecSz)].CopyTo(r);
            BinaryPrimitives.WriteUInt16BigEndian(r.AsSpan(optOff + RdOff, U16), checked((ushort)newRdl));
            msg.Slice(optOff + RecSz, origRdl).CopyTo(r.AsSpan(optOff + RecSz));
            int w = optOff + RecSz + origRdl;
            WriteOpt(r, ref w, padLen);
            return r;
        }

        int padTotal = PadOpt + padLen;
        int totalLen = padLen <= 0 ? curLen + OptOvhd : curLen + OptOvhd + padTotal;

        byte[] res = new byte[totalLen];
        msg[..addStart].CopyTo(res);
        int newArc = BinaryPrimitives.ReadUInt16BigEndian(msg[ArcMsb..(ArcMsb + U16)]) + 1;
        res[ArcMsb] = (byte)(newArc >> BitShift);
        res[ArcMsb + 1] = (byte)newArc;
        msg[addStart..].CopyTo(res.AsSpan(addStart));

        if (padLen <= 0)
        {
            int z = curLen;
            res[z] = 0; z++;
            BinaryPrimitives.WriteUInt16BigEndian(res.AsSpan(z, U16), OptRecordType); z += U16;
            BinaryPrimitives.WriteUInt16BigEndian(res.AsSpan(z, U16), 0); z += U16;
            BinaryPrimitives.WriteUInt32BigEndian(res.AsSpan(z, U32), 0); z += U32;
            BinaryPrimitives.WriteUInt16BigEndian(res.AsSpan(z, U16), 0);
            return res;
        }

        int o = curLen;
        res[o] = 0; o++;
        BinaryPrimitives.WriteUInt16BigEndian(res.AsSpan(o, U16), OptRecordType); o += U16;
        BinaryPrimitives.WriteUInt16BigEndian(res.AsSpan(o, U16), 0); o += U16;
        BinaryPrimitives.WriteUInt32BigEndian(res.AsSpan(o, U32), 0); o += U32;
        BinaryPrimitives.WriteUInt16BigEndian(res.AsSpan(o, U16), checked((ushort)padTotal)); o += U16;
        WriteOpt(res, ref o, padLen);
        return res;
    }

    private static void WriteOpt(byte[] dest, ref int off, int len)
    {
        BinaryPrimitives.WriteUInt16BigEndian(dest.AsSpan(off, U16), PaddingOptionCode); off += U16;
        BinaryPrimitives.WriteUInt16BigEndian(dest.AsSpan(off, U16), checked((ushort)len)); off += U16;
        Array.Fill(dest, (byte)0, off, len);
        off += len;
    }

    private static bool Skip(ReadOnlySpan<byte> m, ref int off)
    {
        const byte Ptr = 0xC0;
        const int PtrSk = 2;
        while (off < m.Length && m[off] != 0)
        {
            byte l = m[off];
            if ((l & Ptr) == Ptr) { off += PtrSk; return true; }
            off += 1 + l;
            if (off > m.Length) return false;
        }
        if (off >= m.Length) return false;
        off++;
        return true;
    }
}
