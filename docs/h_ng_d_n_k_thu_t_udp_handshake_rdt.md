# HƯỚNG DẪN KỸ THUẬT: UDP HANDSHAKE & ĐÓNG GÓI RDT

Tài liệu này hướng dẫn Thành viên 1 cách thiết lập cấu trúc gói tin 16 bytes, thuật toán Checksum RFC 1071, phân mảnh zero-copy và cơ chế Bắt tay 3 bước (3-way handshake) trên nền UDP phi kết nối.

---

## 1. Cấu trúc Gói tin và Định nghĩa Cờ (Flags)

Dù chạy trên UDP, ta vẫn định nghĩa các Cờ (Flags) giống hệt TCP để quản lý trạng thái kết nối.

```python
import struct

# Format 16 bytes: Seq(4), Ack(4), Flags(2), Checksum(2), Rwnd(2), PayloadLen(2)
HEADER_FORMAT = '!IIHHHH'
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

# TCP-like Flags (Mô phỏng)
FLAG_FIN  = 0x0001
FLAG_SYN  = 0x0002
FLAG_RST  = 0x0004
FLAG_DATA = 0x0008
FLAG_ACK  = 0x0010

def pack_rdt_header(seq, ack, flags, checksum, rwnd, payload_len):
    return struct.pack(HEADER_FORMAT, seq, ack, flags, checksum, rwnd, payload_len)
```

---

## 2. Thuật toán Internet Checksum (RFC 1071)

Tính toán toàn vẹn dữ liệu. Bắt buộc set trường Checksum = 0 trước khi nạp vào hàm này.

```python
def compute_checksum(header_without_checksum, payload: bytes) -> int:
    packet = header_without_checksum + payload
    if len(packet) % 2 != 0:
        packet += b'\x00'
        
    checksum = 0
    for i in range(0, len(packet), 2):
        word = (packet[i] << 8) + packet[i+1]
        checksum += word
        
    while (checksum >> 16) > 0:
        checksum = (checksum & 0xffff) + (checksum >> 16)
        
    return ~checksum & 0xffff
```

---

## 3. Phân mảnh tích hợp với Hàng đợi Reliability

Vì bạn của bạn đã xử lý luồng (flow/congestion control), hàm của bạn chỉ làm nhiệm vụ **chuẩn bị hàng loạt các gói tin** và nạp vào hàng đợi (Queue) thay vì đẩy trực tiếp ra mạng.

```python
def chunk_and_pack_data(data: bytes, start_seq: int, mss=1400) -> list:
    """
    Cắt data và đóng gói thành các packet UDP hoàn chỉnh.
    Trả về list các gói tin để đưa vào hàng đợi Sliding Window.
    """
    mem_view = memoryview(data)
    chunks = [mem_view[i:i+mss] for i in range(0, len(data), mss)]
    
    packets = []
    current_seq = start_seq
    
    for chunk in chunks:
        chunk_bytes = chunk.tobytes()
        payload_len = len(chunk_bytes)
        
        draft_header = pack_rdt_header(current_seq, ack=0, flags=FLAG_DATA, checksum=0, rwnd=65535, payload_len=payload_len)
        chksum = compute_checksum(draft_header, chunk_bytes)
        final_header = pack_rdt_header(current_seq, ack=0, flags=FLAG_DATA, checksum=chksum, rwnd=65535, payload_len=payload_len)
        
        packets.append(final_header + chunk_bytes)
        current_seq += payload_len
        
    return packets
```

---

## 4. Mô phỏng 3-Way Handshake trên UDP

Bản chất UDP không có kết nối. Ta dùng file `streaprous_raw_connection.py` (giữ nguyên tên) để tạo ra các hàm thiết lập session.

**Client Connect (Active Open):**
1. Client gởi gói tin mang cờ `SYN`. Bật timeout.
2. Nếu timeout mà chưa nhận phản hồi, gửi lại `SYN`.
3. Chờ nhận gói `SYN + ACK` từ Server.
4. Client gửi lại `ACK` và đưa Connection vào trạng thái ESTABLISHED.

**Server Accept (Passive Open):**
1. Server `.recvfrom()` lắng nghe.
2. Nếu nhận được gói `SYN`, server cấp phát một `ConnectionInfo` (chứa Client IP, Client Port).
3. Server phản hồi gói `SYN + ACK` về Client IP/Port đó. Bật timeout chờ `ACK`.
4. Nếu nhận được `ACK` hợp lệ, xác nhận Connection ESTABLISHED và báo cho Daemon.

*Lưu ý:* Việc dùng `sock.settimeout()` rất quan trọng ở pha này để tránh Deadlock nếu gói SYN bị rớt.

---

## 5. TÀI LIỆU VÀ KEYWORD HỌC TẬP CHUYÊN SÂU

Dưới đây là các tài liệu và từ khóa bạn nên đọc để có thể tự bảo vệ đồ án trước giảng viên:

1. **Vấn đề Mô phỏng Kết nối trên UDP (UDP Connection Simulation):**
   * **Từ khóa tìm kiếm:** `Reliable UDP (RUDP)`, `UDP Hole Punching`, `Session Management over UDP`.
   * **Tài liệu lõi - QUIC Protocol:** Đọc **RFC 9000 (QUIC: A UDP-Based Multiplexed and Secure Transport)**. Google đã tạo ra giao thức QUIC chạy trên nền UDP để thay thế TCP. Họ cũng phải tự làm cơ chế Handshake (Bắt tay) và Connection ID y hệt như những gì nhóm bạn đang làm. 

2. **Cơ chế Bắt tay 3 bước (TCP 3-Way Handshake):**
   * **Từ khóa tìm kiếm:** `TCP Connection Establishment SYN SYN-ACK ACK`, `TCP State Transition Diagram`.
   * **Sách giáo trình:** *Computer Networking: A Top-Down Approach (Kurose & Ross)* - Phần "TCP Connection Management". Hãy xem kỹ sơ đồ chuyển trạng thái (State Machine) từ `CLOSED` -> `SYN_SENT` -> `ESTABLISHED`. Nhóm bạn sẽ phải code State Machine này vào hệ thống.

3. **Thuật toán Checksum & Memory:**
   * Đọc **RFC 1071 (Computing the Internet Checksum)**.
   * Tìm hiểu khái niệm `Zero-copy buffering in Python` với `memoryview`. Điều này chứng minh cho giảng viên thấy nhóm bạn có tư duy tối ưu bộ nhớ cấp cao, không chỉ viết code cho chạy được.