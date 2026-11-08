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
│   ├── streaprous_packet_struct.py     # MODULE RELIABILITY CHÍNH (Custom Header, RFC 1071 Checksum, rdt_send)
│   ├── streaprous_packet_dispatcher.py # Packet dispatching utilities
│   └── streaprous_raw_connection.py    # Legacy connection wrappers
│
├── tests/                              # Unit Tests
│   └── test_streaprous_packet_struct.py# Comprehensive Unit Tests cho Custom Header, Checksum, và Fragmentation
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
Đóng vai trò trung tâm của Module RDT, cung cấp 4 hàm cốt lõi:
1. **`pack_rdt_header(seq_num, ack_num, flags, checksum, rwnd, payload_len)`**: Đóng gói các trường thành 16-byte header chuẩn Network Byte Order.
2. **`unpack_rdt_header(header_bytes)`**: Mở gói 16-byte header từ byte stream nhận được thành Python dictionary để dễ dàng kiểm tra.
3. **`compute_checksum(header_bytes, payload_bytes)`**: Thuật toán **Internet Checksum 16-bit chuẩn RFC 1071** (One's complement sum, tự động thêm padding `\x00` nếu tổng độ dài lẻ và đảo bit bù 1).
4. **`rdt_send(udp_sock, dest_addr, data, ...)`**: Hàm gửi phân mảnh ứng dụng. Sử dụng `memoryview(data)` để cắt dữ liệu thành các chunk có kích thước tối ưu MSS (1400 bytes), tự động tính checksum cho từng gói và gửi qua UDP socket mà không gây ra IP Fragmentation ở tầng mạng.

### B. `tests/test_streaprous_packet_struct.py` (Unit Tests)
Bao gồm các test case kiểm tra độ tin cậy tuyệt đối:
- `test_pack_and_unpack_rdt_header`: Kiểm tra tính chính xác của quá trình pack/unpack round-trip 16-byte header.
- `test_compute_internet_checksum`: Kiểm tra tính toàn vẹn gói tin bằng Internet Checksum (tổng kiểm tra verify trả về `0`).
- `test_memoryview_fragmentation_and_rdt_send`: Kiểm tra phân mảnh dữ liệu lớn (3500 bytes thành 3 chunks với MSS=1400), kiểm tra tuần tự `seq_num` và hoạt động của mock socket `sendto`.

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

