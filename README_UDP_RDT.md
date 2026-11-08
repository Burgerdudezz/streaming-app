# StreapRous - Distributed Streaming-based Client-Server Collaboration App
# Assignment 1: UDP-based Reliable Data Transfer (UDP-RDT) Module

## 🚀 1. TỔNG QUAN & CHUYỂN HƯỚNG KIẾN TRÚC (ARCHITECTURAL SHIFT)
Hệ thống ban đầu được thiết kế dựa trên **TCP Raw Socket (`socket.SOCK_RAW`)** thao tác trực tiếp tại tầng IP. Tuy nhiên, qua quá trình triển khai thực tế và đánh giá độ phức tạp khi vận hành raw socket trên đa nền tảng (quyền quản trị `root/admin` ngặt nghèo, xung đột định tuyến loopback, cấu trúc IP/TCP checksum phức tạp), nhóm đã quyết định **thay thế hoàn toàn** bằng mô hình **UDP chuẩn (`socket.SOCK_DGRAM`)** kết hợp xây dựng **Module Reliability (RDT)** riêng ở tầng Application.

Mô hình mới giúp giả lập đầy đủ các đặc tính tin cậy của TCP (như Sequence Number, Acknowledgment, Checksum, Flow Control) nhưng chạy hoàn toàn trên UDP datagram đơn giản, an toàn và dễ kiểm soát.

---

## 📂 2. CẤU TRÚC THƯ MỤC DỰ ÁN (`UDP-reliability/`)

```text
UDP-reliability/
│
├── streaprous_socket/                  # Core Networking & RDT Modules
│   ├── __init__.py
│   ├── streaprous_packet_struct.py     # 🌟 RDT Core: Custom 16-byte Header, RFC 1071 Checksum, rdt_send
│   ├── streaprous_packet_dispatcher.py # Packet routing & dispatching utilities
│   └── streaprous_raw_connection.py    # Connection wrappers (isolated from legacy TCP raw code)
│
├── tests/                              # Unit Testing Suite
│   └── test_streaprous_packet_struct.py# 🧪 Unit Tests cho RDT Header, Checksum và Memoryview Fragmentation
│
├── daemon/                             # Server Daemon & HTTP/Streaming Adapters
├── apps/                               # Sample Client / Server Collaboration Applications
├── static/                             # Web Static Assets (CSS, JS, Images)
├── www/                                # HTML Templates
├── start_backend.py                    # Backend server runner
├── start_proxy.py                      # Proxy server runner
└── README_UDP_RDT.md                   # Tài liệu chi tiết module UDP-RDT
```

---

## 🔑 3. CÁC FILE QUAN TRỌNG VÀ TECH STACK

### 📌 `streaprous_socket/streaprous_packet_struct.py` (Core Reliability Module)
Đây là trái tim của hệ thống UDP-RDT, thực hiện 3 nhiệm vụ cốt lõi:
1. **Custom RDT Header (16 bytes):** Sử dụng thư viện `struct` với chuẩn Big-Endian (`!IIHHHH`) gồm:
   - `seq_num` (4 bytes, `I`): Số thứ tự gói tin (Sequence Number)
   - `ack_num` (4 bytes, `I`): Số xác nhận (Acknowledgment Number)
   - `flags` (2 bytes, `H`): Cờ điều khiển (`SYN=0x0002`, `ACK=0x0010`, `FIN=0x0001`, `DATA=0x0001`, v.v.)
   - `checksum` (2 bytes, `H`): Mã kiểm tra lỗi Internet Checksum
   - `rwnd` (2 bytes, `H`): Kích thước cửa sổ nhận (Receive Window)
   - `payload_len` (2 bytes, `H`): Độ dài phần dữ liệu (Payload Length)
2. **Internet Checksum (RFC 1071):**
   - Hàm `compute_checksum(header_bytes, payload_bytes)` tính tổng bù 1 (one's complement sum) qua Header (với checksum field ban đầu bằng 0) kết hợp với Payload.
   - Không cần Pseudo-IP Header như TCP chuẩn, giúp gói tin độc lập và linh hoạt trên nền UDP.
3. **Zero-copy Fragmentation (`rdt_send`):**
   - Sử dụng `memoryview(data)` để cắt lát dữ liệu thành các chunk có kích thước MSS chuẩn (`mss = 1400` bytes).
   - Tổng kích thước gói UDP truyền đi là $16 + 1400 = 1416$ bytes, nằm an toàn dưới ngưỡng Ethernet MTU (1500 bytes), triệt tiêu hoàn toàn hiện tượng phân mảnh IP tại tầng Network.

### 📌 `tests/test_streaprous_packet_struct.py` (Test Suite)
- Kiểm tra toàn diện 3 chức năng: Pack/Unpack header, tính toán và xác thực Checksum (đảm bảo tổng kiểm tra trả về `0`), và cơ chế chia nhỏ dữ liệu lớn (`memoryview` fragmentation & mock socket `sendto`).

---

## ➿ 4. LUỒNG HOẠT ĐỘNG DỮ LIỆU (DATA FLOW)

1. **Khởi tạo dữ liệu gửi:** Ứng dụng gọi `rdt_send(udp_sock, dest_addr, data, seq_num, ...)`.
2. **Cắt lát dữ liệu (Zero-copy):** Dữ liệu được bọc bằng `memoryview` và chia thành các đoạn nhỏ tối đa `mss = 1400` bytes.
3. **Đóng gói RDT Header & Checksum:**
   - Tạo draft header với `checksum = 0`.
   - Tính toán `compute_checksum(draft_header, chunk_payload)`.
   - Tạo final header chứa giá trị checksum thực tế.
   - Ghép `packet = final_header + chunk_payload`.
4. **Truyền qua UDP Socket:** Gói tin được gửi qua `udp_sock.sendto(packet, dest_addr)` đến đích một cách an toàn.

---

## 📊 5. SO SÁNH VÀ Ý NGHĨA THAY ĐỔI SO VỚI HỆ THỐNG CŨ

| Tiêu chí | Hệ thống cũ (TCP Raw Socket) | Hệ thống mới (UDP Standard + App RDT) | Ý nghĩa cải tiến |
|----------|-----------------------------|--------------------------------------|------------------|
| **Socket Type** | `socket.SOCK_RAW` (IP Layer) | `socket.SOCK_DGRAM` (UDP Standard) | Chạy được trên mọi hệ điều hành mà không cần quyền `root/admin`. |
| **Header Overhead** | 20 bytes (TCP) + 20 bytes (IP) = 40 bytes | **16 bytes (Custom RDT Header)** | Gọn nhẹ, tối ưu riêng cho ứng dụng streaming và collaboration. |
| **Checksum Mechanism** | Pseudo-IP Header + TCP Checksum | **RFC 1071 Internet Checksum thuần túy** | Độc lập với địa chỉ IP tầng Network, linh hoạt khi chuyển trạm/NAT. |
| **Fragmentation Control** | Phụ thuộc vào OS / Network layer | **Application-level MSS Chunking (`memoryview`)** | Tránh tình trạng mất mát fragment IP, kiểm soát tuyệt đối kích thước gói. |
| **Tính mở rộng & Tin cậy** | Phụ thuộc hoàn toàn vào OS TCP stack | **Tự chủ hoàn toàn ở Application Layer** | Dễ dàng tùy biến các cơ chế RDT nâng cao (Stop-and-Wait, Go-Back-N, Selective Repeat). |

---

## 🧪 6. HƯỚNG DẪN CHẠY TEST

Để kiểm tra toàn bộ module RDT và các đơn vị kiểm thử:
```bash
python -m unittest discover -s tests -p 'test_*.py' -v
```
Kết quả mong đợi: `Ran 3 tests in 0.001s - OK`.

