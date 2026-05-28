// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers;
using System.Globalization;
using System.Text;

namespace Incursa.Qpack;

internal static class QPackHuffman
{
    private const int EndOfStringSymbol = 256;
    private const int DecodedCapacityMultiplier = 2;
    private const int MinimumDecodedCapacity = 1;
    private const int MaximumPaddingBits = 7;

    private static readonly Node Root = BuildTree();

    public static string Decode(ReadOnlySpan<byte> source, QPackErrorCode errorCode)
    {
        int initialCapacity = source.Length <= int.MaxValue / DecodedCapacityMultiplier
            ? source.Length * DecodedCapacityMultiplier
            : source.Length;
        ArrayBufferWriter<byte> writer = new(Math.Max(MinimumDecodedCapacity, initialCapacity));
        Node node = Root;

        for (int byteIndex = 0; byteIndex < source.Length; byteIndex++)
        {
            byte value = source[byteIndex];
            for (int bitIndex = 7; bitIndex >= 0; bitIndex--)
            {
                Node? next = ((value >> bitIndex) & 0x01) == 0 ? node.Zero : node.One;
                if (next is null)
                {
                    throw new QPackException(errorCode, "The QPACK Huffman string literal is malformed.");
                }

                node = next;
                if (!node.HasSymbol)
                {
                    continue;
                }

                if (node.Symbol == EndOfStringSymbol)
                {
                    throw new QPackException(errorCode, "The QPACK Huffman string literal contains EOS.");
                }

                writer.GetSpan(1)[0] = checked((byte)node.Symbol);
                writer.Advance(1);
                node = Root;
            }
        }

        if (node != Root && (!node.IsEndOfStringPrefix || node.Depth > MaximumPaddingBits))
        {
            throw new QPackException(errorCode, "The QPACK Huffman string literal padding is invalid.");
        }

        return Encoding.Latin1.GetString(writer.WrittenSpan);
    }

    private static Node BuildTree()
    {
        Node root = new(0, true);
        foreach (string entry in CodeEntries.Split(';'))
        {
            string[] parts = entry.Split(':');
            int symbol = int.Parse(parts[0], CultureInfo.InvariantCulture);
            uint code = uint.Parse(parts[1], NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            int bitLength = int.Parse(parts[2], CultureInfo.InvariantCulture);
            AddCode(root, symbol, code, bitLength);
        }

        return root;
    }

    private static void AddCode(Node root, int symbol, uint code, int bitLength)
    {
        Node node = root;
        bool eosPrefix = true;
        for (int bitIndex = bitLength - 1; bitIndex >= 0; bitIndex--)
        {
            bool one = ((code >> bitIndex) & 0x01) != 0;
            eosPrefix &= one;
            Node? next = one ? node.One : node.Zero;
            if (next is null)
            {
                next = new Node(node.Depth + 1, eosPrefix);
                if (one)
                {
                    node.One = next;
                }
                else
                {
                    node.Zero = next;
                }
            }

            node = next;
        }

        node.Symbol = symbol;
        node.HasSymbol = true;
    }

    private sealed class Node(int depth, bool isEndOfStringPrefix)
    {
        public Node? Zero { get; set; }

        public Node? One { get; set; }

        public int Depth { get; } = depth;

        public bool IsEndOfStringPrefix { get; } = isEndOfStringPrefix;

        public int Symbol { get; set; }

        public bool HasSymbol { get; set; }
    }

    private const string CodeEntries = "0:1ff8:13;1:7fffd8:23;2:fffffe2:28;3:fffffe3:28;4:fffffe4:28;5:fffffe5:28;6:fffffe6:28;7:fffffe7:28;8:fffffe8:28;9:ffffea:24;10:3ffffffc:30;11:fffffe9:28;12:fffffea:28;13:3ffffffd:30;14:fffffeb:28;15:fffffec:28;16:fffffed:28;17:fffffee:28;18:fffffef:28;19:ffffff0:28;20:ffffff1:28;21:ffffff2:28;22:3ffffffe:30;23:ffffff3:28;24:ffffff4:28;25:ffffff5:28;26:ffffff6:28;27:ffffff7:28;28:ffffff8:28;29:ffffff9:28;30:ffffffa:28;31:ffffffb:28;32:14:6;33:3f8:10;34:3f9:10;35:ffa:12;36:1ff9:13;37:15:6;38:f8:8;39:7fa:11;40:3fa:10;41:3fb:10;42:f9:8;43:7fb:11;44:fa:8;45:16:6;46:17:6;47:18:6;48:0:5;49:1:5;50:2:5;51:19:6;52:1a:6;53:1b:6;54:1c:6;55:1d:6;56:1e:6;57:1f:6;58:5c:7;59:fb:8;60:7ffc:15;61:20:6;62:ffb:12;63:3fc:10;64:1ffa:13;65:21:6;66:5d:7;67:5e:7;68:5f:7;69:60:7;70:61:7;71:62:7;72:63:7;73:64:7;74:65:7;75:66:7;76:67:7;77:68:7;78:69:7;79:6a:7;80:6b:7;81:6c:7;82:6d:7;83:6e:7;84:6f:7;85:70:7;86:71:7;87:72:7;88:fc:8;89:73:7;90:fd:8;91:1ffb:13;92:7fff0:19;93:1ffc:13;94:3ffc:14;95:22:6;96:7ffd:15;97:3:5;98:23:6;99:4:5;100:24:6;101:5:5;102:25:6;103:26:6;104:27:6;105:6:5;106:74:7;107:75:7;108:28:6;109:29:6;110:2a:6;111:7:5;112:2b:6;113:76:7;114:2c:6;115:8:5;116:9:5;117:2d:6;118:77:7;119:78:7;120:79:7;121:7a:7;122:7b:7;123:7ffe:15;124:7fc:11;125:3ffd:14;126:1ffd:13;127:ffffffc:28;128:fffe6:20;129:3fffd2:22;130:fffe7:20;131:fffe8:20;132:3fffd3:22;133:3fffd4:22;134:3fffd5:22;135:7fffd9:23;136:3fffd6:22;137:7fffda:23;138:7fffdb:23;139:7fffdc:23;140:7fffdd:23;141:7fffde:23;142:ffffeb:24;143:7fffdf:23;144:ffffec:24;145:ffffed:24;146:3fffd7:22;147:7fffe0:23;148:ffffee:24;149:7fffe1:23;150:7fffe2:23;151:7fffe3:23;152:7fffe4:23;153:1fffdc:21;154:3fffd8:22;155:7fffe5:23;156:3fffd9:22;157:7fffe6:23;158:7fffe7:23;159:ffffef:24;160:3fffda:22;161:1fffdd:21;162:fffe9:20;163:3fffdb:22;164:3fffdc:22;165:7fffe8:23;166:7fffe9:23;167:1fffde:21;168:7fffea:23;169:3fffdd:22;170:3fffde:22;171:fffff0:24;172:1fffdf:21;173:3fffdf:22;174:7fffeb:23;175:7fffec:23;176:1fffe0:21;177:1fffe1:21;178:3fffe0:22;179:1fffe2:21;180:7fffed:23;181:3fffe1:22;182:7fffee:23;183:7fffef:23;184:fffea:20;185:3fffe2:22;186:3fffe3:22;187:3fffe4:22;188:7ffff0:23;189:3fffe5:22;190:3fffe6:22;191:7ffff1:23;192:3ffffe0:26;193:3ffffe1:26;194:fffeb:20;195:7fff1:19;196:3fffe7:22;197:7ffff2:23;198:3fffe8:22;199:1ffffec:25;200:3ffffe2:26;201:3ffffe3:26;202:3ffffe4:26;203:7ffffde:27;204:7ffffdf:27;205:3ffffe5:26;206:fffff1:24;207:1ffffed:25;208:7fff2:19;209:1fffe3:21;210:3ffffe6:26;211:7ffffe0:27;212:7ffffe1:27;213:3ffffe7:26;214:7ffffe2:27;215:fffff2:24;216:1fffe4:21;217:1fffe5:21;218:3ffffe8:26;219:3ffffe9:26;220:ffffffd:28;221:7ffffe3:27;222:7ffffe4:27;223:7ffffe5:27;224:fffec:20;225:fffff3:24;226:fffed:20;227:1fffe6:21;228:3fffe9:22;229:1fffe7:21;230:1fffe8:21;231:7ffff3:23;232:3fffea:22;233:3fffeb:22;234:1ffffee:25;235:1ffffef:25;236:fffff4:24;237:fffff5:24;238:3ffffea:26;239:7ffff4:23;240:3ffffeb:26;241:7ffffe6:27;242:3ffffec:26;243:3ffffed:26;244:7ffffe7:27;245:7ffffe8:27;246:7ffffe9:27;247:7ffffea:27;248:7ffffeb:27;249:ffffffe:28;250:7ffffec:27;251:7ffffed:27;252:7ffffee:27;253:7ffffef:27;254:7fffff0:27;255:3ffffee:26;256:3fffffff:30";
}
