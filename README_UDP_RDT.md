# ==============================================================================
# StreapRous - Distributed Streaming-based Client-Server Collaboration App
# Assignment 1: UDP-based Reliable Data Transfer (UDP-RDT) Module
# ==============================================================================

## 1. TỔNG QUAN DỰ ÁN & ĐỊNH HƯỚNG KIẾN TRÚC
Hệ thống ban đầu được thiết kế dựa trên **TCP Raw Socket (`socket.SOCK_RAW`)** tại tầng IP. Tuy nhiên, qua quá trình triển khai thực tế và đánh giá độ phức tạp khi thao tác packet raw trên đa nền tảng (OS privilege limits, IP header checksum overhead, routing loopback issues), nhóm đã thống nhất đập đi xây lại toàn bộ trên nền **UDP chuẩn (`socket.SOCK_DGRAM`)**, đồng thời tự xây dựng **Module Reliability (RDT)** ở tầng Application để mô phỏng các cơ chế tin cậy giống TCP (nhưng hoàn toàn kiểm soát trên UDP).

---

## 2. TECH STACK & CẤU TRÚC THƯ MỤC DỰ ÁN (`UDP-RELIABILITY`)

```text
UDP-reliability/
│
├── streaprous_socket/                  # Core Networking & RDT Modules
│   ├── __init__.py
│   ├── streaprous_packet_struct.py     # MODULE RELIABILITY CHÍNH (Custom Header, RFC 1071 Checksum, chunk_and_pack_data)
│   ├── streaprous_packet_dispatcher.py # Packet dispatching utilities
│   └── streaprous_raw_connection.py    # UDP Connection & 3-Way Handshake (giữ tên legacy)
│
├── tests/                              # Unit Tests
│   ├── test_streaprous_packet_struct.py  # Tests: Header pack/unpack, Checksum, Fragmentation
│   └── test_streaprous_handshake.py      # Tests: 3-Way Handshake, Chunking, Send/Receive
│
├── daemon/                             # Server Daemon & HTTP/Streaming Adapters
├── apps/                               # Sample Client/Server Applications
├── static/                             # Web Static Assets (CSS, Images)
├── www/                                # HTML templates
├── start_backend.py                    # Backend runner
├── start_proxy.py                      # Proxy runner
└── README_UDP_RDT.md                   # Documentation chính của Module RDT
```

### 🛠️ Tech Stack sử dụng:
- **Ngôn ngữ:** Python 3.x
- **Thư viện chuẩn:** 
  - `socket` (`SOCK_DGRAM` cho truyền nhận UDP Datagram).
  - `struct` (Đóng/mở gói cấu trúc Custom RDT Header 16-byte theo định dạng Big-Endian `!IIHHHH`).
  - `memoryview` (Xử lý cắt lát dữ liệu zero-copy tối ưu RAM khi phân mảnh packet).
  - `unittest` (Framework kiểm thử tự động).

---

## 3. CÁC FILE QUAN TRỌNG VÀ CHỨC NĂNG

### A. `streaprous_socket/streaprous_packet_struct.py` (Core Reliability)
Đóng vai trò trung tâm của Module RDT, cung cấp các hàm cốt lõi:

**Constants & Flags (TCP-simulation):**
- `SYN = 0x02`, `ACK = 0x10`, `FIN = 0x01`, `DATA = 0x08`, `SYN_ACK = SYN | ACK`

**Core Functions:**
1. **`pack_rdt_header(seq_num, ack_num, flags, checksum, rwnd, payload_len)`**: Đóng gói 16-byte header chuẩn Network Byte Order (`!IIHHHH`).
2. **`unpack_rdt_header(header_bytes)`**: Mở gói 16-byte header thành Python dict.
3. **`compute_checksum(header_bytes, payload_bytes)`**: Internet Checksum 16-bit chuẩn **RFC 1071** (One's complement, auto-padding).
4. **`chunk_and_pack_data(data, start_seq, mss=1400)`**: **Hàm mới** - Phân mảnh dữ liệu bằng `memoryview` zero-copy, trả về `list[bytes]` các gói RDT hoàn chỉnh (header + payload + checksum) để module Reliability đưa vào hàng đợi. **KHÔNG gửi socket.**
5. **`rdt_send(udp_sock, dest_addr, data, ...)`**: Gửi dữ liệu tin cậy qua UDP (wrap `chunk_and_pack_data` + `sendto`).

### B. `streaprous_socket/streaprous_raw_connection.py` (UDP Connection & Handshake)
**Giữ nguyên tên file legacy** nhưng logic bên trong đã chuyển hoàn toàn sang UDP (`socket.SOCK_DGRAM`):

1. **`create_udp_socket(ip, port)`**: Khởi tạo & bind UDP socket chuẩn.
2. **`connect_udp_handshake(sock, server_addr, timeout, max_retries)`**: **Client 3-Way Handshake** - Gửi SYN, chờ SYN-ACK (timeout + retry), gửi ACK cuối cùng. Trả về `conn_struct`.
3. **`accept_udp_handshake(sock, timeout)`**: **Server 3-Way Handshake** - Lắng nghe SYN, phản hồi SYN-ACK, chờ ACK hợp lệ. Trả về `(conn_struct, client_addr)`.
4. **`run_conn_send/recv`**, **`close_connection`**: Wrapper send/recv/close trên kết nối đã established.

### C. `tests/test_streaprous_packet_struct.py` (Unit Tests)
- `test_pack_and_unpack_rdt_header`: Round-trip 16-byte header.
- `test_compute_internet_checksum`: Verify checksum = 0.
- `test_memoryview_fragmentation_and_rdt_send`: Phân mảnh 3500 bytes → 3 chunks, check seq_num.

### D. `tests/test_streaprous_handshake.py` (Unit Tests - **New Phase 1**)
- `test_chunk_and_pack_data_basic`: Chunking single packet.
- `test_chunk_and_pack_data_fragmentation`: Multi-chunk 3500 bytes.
- `test_handshake_flags`: Verify flag constants.
- `test_3way_handshake_localhost`: Full handshake client/server on localhost.
- `test_rdt_send_receive`: Data transfer after handshake.
- `test_handshake_timeout_retry`: Client retry logic on timeout.

---

## 4. LUỒNG HOẠT ĐỘNG (DATA FLOW)

### Gửi dữ liệu (`rdt_send`):
1. **Tiếp nhận dữ liệu (`data`)**: Chuyển đổi linh hoạt sang bytes nếu là string hoặc buffer khác.
2. **Phân mảnh Zero-copy (`memoryview`)**: Cắt `memoryview(data)` thành các phần có kích thước tối đa bằng MSS (`1400 bytes`).
3. **Đóng gói Header & Tính Checksum**:
   - Tạo draft header với `checksum = 0`.
   - Tính toán Internet Checksum trên `draft_header + chunk_payload`.
   - Tạo final header với checksum vừa tính.
4. **Truyền tải qua UDP**: Ghép `final_header + chunk_payload` (tổng gói 1416 bytes) và gọi `udp_sock.sendto()` đến địa chỉ đích.
5. **Cập nhật Seq Number**: Tăng `seq_num` theo số byte payload thực tế của chunk đã gửi.

---

## 5. SO SÁNH VÀ Ý NGHĨA THAY ĐỔI SO VỚI HỆ THỐNG CŨ (TCP RAW SOCKET)

| Tiêu chí | Mô hình cũ (TCP Raw Socket) | Mô hình mới (UDP Standard + App RDT) | Ý nghĩa cải tiến |
| :--- | :--- | :--- | :--- |
| **Socket Type** | `socket.SOCK_RAW` | `socket.SOCK_DGRAM` (UDP chuẩn) | **Không cần quyền root/admin**, chạy mượt mà trên mọi OS (Windows/Linux/macOS). |
| **Header Size** | 20 bytes (TCP) + 20 bytes (IP) | **16 bytes** (Custom RDT Header) | Gọn nhẹ, chuyên biệt hóa cho ứng dụng streaming và collaboration. |
| **Checksum** | Pseudo-IP Header + TCP Checksum | **RFC 1071 thuần túy** | Độc lập khỏi địa chỉ IP tầng Network, linh hoạt chuyển trạm/NAT. |
| **Phân mảnh** | Phụ thuộc OS / IP layer | **App-level MSS chunking (`memoryview`)** | Tránh thất lạc fragment IP, kiểm soát 100% kích thước gói tin (tránh IP fragmentation). |
| **Độ tin cậy** | Phức tạp, phụ thuộc OS TCP stack | Tự chủ hoàn toàn ở Application Layer | Dễ dàng tùy biến các thuật toán điều khiển tắc nghẽn và RDT (Stop-and-Wait, Go-Back-N, Selective Repeat). |

---

## 4. LUỒNG HOẠT ĐỘNG (DATA FLOW) - CẬP NHẬT PHASE 1

### Gửi dữ liệu (`rdt_send` / `chunk_and_pack_data`):
1. **Tiếp nhận dữ liệu**: Chuyển đổi sang bytes nếu là string/buffer khác.
2. **Phân mảnh Zero-copy (`memoryview`)**: Cắt thành các chunk ≤ MSS (1400 bytes).
3. **Đóng gói Header & Checksum** (cho từng chunk):
   - Tạo draft header với `checksum = 0`.
   - Tính Internet Checksum (RFC 1071) trên `draft_header + payload`.
   - Tạo final header với checksum đúng.
4. **Trả về list packets** (cho `chunk_and_pack_data`) hoặc **gửi qua UDP** (cho `rdt_send`).
5. **Cập nhật Seq Number**: Tăng `seq_num` theo byte payload thực tế.

### Mô phỏng 3-Way Handshake (UDP):
```
CLIENT (connect_udp_handshake)          SERVER (accept_udp_handshake)
     │                                      │
     ├────────── SYN (seq=C) ─────────────►│  1. Nhận SYN, kiểm tra flag
     │                                      │  2. Tạo server_seq=S
     │◄─────── SYN-ACK (seq=S, ack=C+1) ───┤  3. Gửi SYN-ACK
     │                                      │
     ├────────── ACK (seq=C+1, ack=S+1) ──►│  4. Nhận ACK, kiểm tra ack=S+1
     │                                      │  5. Connection ESTABLISHED
     │           ESTABLISHED                │
     ▼                                      ▼
```
- **Client**: Random `client_seq`, timeout/retry logic (`sock.settimeout`), validate `ack_num = client_seq + 1`.
- **Server**: Random `server_seq`, gửi `SYN_ACK` với `ack = client_seq + 1`, chờ `ACK` với `ack = server_seq + 1`.
- **State**: Cả hai tạo `conn_struct` với `state="ESTABLISHED"`, cập nhật sequence numbers.

---

## 5. SO SÁNH VÀ Ý NGHĨA THAY ĐỔI (BEFORE vs AFTER Phase 1)

### A. So sánh với hệ thống cũ (TCP Raw Socket → UDP Standard + App RDT)

| Tiêu chí | Mô hình cũ (TCP Raw Socket) | Mô hình mới (UDP Standard + App RDT) | Ý nghĩa cải tiến |
| :--- | :--- | :--- | :--- |
| **Socket Type** | `socket.SOCK_RAW` | `socket.SOCK_DGRAM` (UDP chuẩn) | **Không cần quyền root/admin**, chạy mượt trên mọi OS (Win/Linux/macOS). |
| **Header Size** | 20 bytes (TCP) + 20 bytes (IP) | **16 bytes** (Custom RDT Header) | Gọn nhẹ, chuyên biệt cho streaming/collaboration. |
| **Checksum** | Pseudo-IP Header + TCP Checksum | **RFC 1071 thuần túy** | Độc lập IP layer, linh hoạt NAT/forwarding. |
| **Phân mảnh** | Phụ thuộc OS / IP layer | **App-level MSS chunking (`memoryview`)** | Tránh IP fragmentation, kiểm soát 100% packet size. |
| **Độ tin cậy** | Phức tạp, phụ thuộc OS TCP stack | Tự chủ hoàn toàn ở Application Layer | Dễ tùy biến RDT (Stop-and-Wait, Go-Back-N, Selective Repeat). |

### B. Thay đổi trong Phase 1 (Mô phỏng 3-Way Handshake & Chunking)

| Thành phần | Trước Phase 1 | Sau Phase 1 | Ghi chú |
| :--- | :--- | :--- | :--- |
| **`streaprous_packet_struct.py`** | Chỉ có `pack/unpack`, `compute_checksum`, `rdt_send` | **+ Flag constants (SYN/ACK/FIN/DATA)**<br>**+ `chunk_and_pack_data()`** (tách bạch logic chunking khỏi send) | Tách biệt "chuẩn bị gói tin" và "gửi socket" → dễ test, dễ queue. |
| **`streaprous_raw_connection.py`** | Raw socket TCP: IP header, TCP header, pseudo-checksum, `SOCK_RAW` | **UDP Socket (`SOCK_DGRAM`)**<br>**+ `create_udp_socket()`**<br>**+ `connect_udp_handshake()`** (Client)<br>**+ `accept_udp_handshake()`** (Server) | Giữ tên file legacy để tương thích import, nhưng logic bên trong hoàn toàn UDP-RDT. |
| **Test Coverage** | Chỉ test header & checksum | **+ Handshake E2E test** (localhost client/server)<br>**+ Chunking test**<br>**+ Timeout/Retry test** | Đảm bảo handshake hoạt động thực tế, không chỉ mock. |

---

## 6. HƯỚNG DẪN CHẠY TEST

```bash
# Chạy tất cả test trong thư mục tests/
python -m unittest discover tests -v

# Hoặc chạy file test cụ thể
python -m unittest tests.test_streaprous_packet_struct -v
python -m unittest tests.test_streaprous_handshake -v
```

**Expected Output (9 tests pass):**
```
test_3way_handshake_localhost ... ok
test_chunk_and_pack_data_basic ... ok
test_chunk_and_pack_data_fragmentation ... ok
test_handshake_flags ... ok
test_rdt_send_receive ... ok
test_handshake_timeout_retry ... ok
test_compute_internet_checksum ... ok
test_memoryview_fragmentation_and_rdt_send ... ok
test_pack_and_unpack_rdt_header ... ok

Ran 9 tests in ~1.2s
OK
```

---

## 7. TÍNH TƯƠNG THÍCH VỚI MODULE RELIABILITY (Người khác viết)

Module `streaprous_reliability.py` (Sliding Window, Retransmission, Queue) **chỉ cần import và sử dụng**:

```python
from streaprous_socket.streaprous_packet_struct import chunk_and_pack_data

# Trong reliable_send():
packets = chunk_and_pack_data(payload, start_seq=seq, mss=1400)
for pkt in packets:
    packet_queue.put(pkt)  # Đưa vào hàng đợi gửi
```

- `chunk_and_pack_data` **không phụ thuộc socket**, chỉ trả về `list[bytes]`.
- Header format `!IIHHHH` (16 bytes) ổn định, tương thích unpack ở receiver.
- Flags `DATA` (0x08) phân biệt với handshake flags.

