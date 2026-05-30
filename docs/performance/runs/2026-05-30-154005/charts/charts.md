# Performance Charts

## 1. Before vs After P4: Total Managed Allocation

```mermaid
xychart-beta
  title "Managed Allocation Before/After P4 (KB/op)"
  x-axis ["Before P4", "After P4"]
  y-axis "KB/op" 0 --> 950
  bar [922, 325]
```

## 2. Before vs After P4: Server Constructor Allocation

```mermaid
xychart-beta
  title "Server Constructor Before/After P4 (KB/op)"
  x-axis ["Before P4", "After P4"]
  y-axis "KB/op" 0 --> 650
  bar [611, 15]
```

## 3. Incursa.Quic vs System.Net.Quic: Managed Allocation

```mermaid
xychart-beta
  title "Managed Allocation (KB/op) - Pass 2"
  x-axis ["Incursa.Quic", "System.Net.Quic"]
  y-axis "KB/op" 0 --> 350
  bar [325, 91]
```

## 4. Incursa.Quic vs System.Net.Quic: Private Bytes / Working Set

```mermaid
xychart-beta
  title "Private Bytes per Operation (MB/op) - Pass 2"
  x-axis ["Incursa.Quic", "System.Net.Quic"]
  y-axis "MB/op" 0 --> 3
  bar [0.002, 2.495]
```

```mermaid
xychart-beta
  title "Working Set per Operation (MB/op) - Pass 2"
  x-axis ["Incursa.Quic", "System.Net.Quic"]
  y-axis "MB/op" 0 --> 3
  bar [0.003, 2.320]
```

## 5. Connect+Accept Sub-Phase Breakdown

```mermaid
pie showData
  title "Connect+Accept Allocation by Sub-Phase"
  "remaining handshake processing" : 222538
  "client runtime construction" : 15312
  "server runtime construction" : 15296
  "TLS key schedule + ClientHello" : 2188
  "initial packet protection" : 1402
```

## 6. Server Runtime Constructor Breakdown (Top 8)

```mermaid
xychart-beta
  title "Server Constructor Components (KB/op)"
  x-axis ["collections", "TLS bridge driver", "channels", "TLS bridge state", "RecoveryController", "field-init", "StreamRegistry", "PeerConnIdState"]
  y-axis "KB/op" 0 --> 5
  bar [4.2, 3.0, 2.5, 2.3, 0.7, 0.5, 0.5, 0.5]
```

## 7. Lifecycle Phase Breakdown

```mermaid
pie showData
  title "Allocation by Lifecycle Phase"
  "connect+accept" : 256780
  "listener" : 46928
  "close+dispose" : 33912
