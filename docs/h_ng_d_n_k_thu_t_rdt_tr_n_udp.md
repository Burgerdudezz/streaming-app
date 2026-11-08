# HƯỚNG DẪN KỸ THUẬT: ĐÓNG GÓI & PHÂN MẢNH GIAO THỨC RDT (UDP)

Dưới đây là mã nguồn mẫu và kiến trúc để bạn triển khai Module Reliability trên nền UDP (`socket.SOCK_DGRAM`).

## 1. Cấu trúc Custom Header (16 bytes)

Để tạo ra đúng 16 bytes theo yêu cầu phân công nội bộ, bạn sử dụng format chuỗi `!IIHHHH` của thư viện `struct` trong Python:

*   `!` : Big-Endian (Network Byte Order - Bắt buộc).
*   `I` (Unsigned Int): 4 bytes (dành cho Seq và Ack).
*   `H` (Unsigned Short): 2 bytes (dành cho Flags, Checksum, Rwnd, Payload_len).

**Mã nguồn triển khai:**

```python
import struct

# Format: ! (Big-Endian), I (Seq-4B), I (Ack-4B), H (Flags-2B), H (Checksum-2B), H (Rwnd-2B), H (PayloadLen-2B) = 16 Bytes
HEADER_FORMAT = '!IIHHHH'
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

def pack_rdt_header(seq_num, ack_num, flags, checksum, rwnd, payload_len):
    return struct.pack(HEADER_FORMAT, seq_num, ack_num, flags, checksum, rwnd, payload_len)

def unpack_rdt_header(header_bytes):
    return struct.unpack(HEADER_FORMAT, header_bytes)
```

## 2. Thuật toán Internet Checksum 16-bit (RFC 1071)

Thuật toán này gom các byte thành từng cặp 16-bit (word), cộng dồn lại, xử lý phần nhớ (carry fold) và lấy bù 1. Điểm khác biệt so với TCP Raw Socket là trên UDP tự chế, ta không cần dùng "Pseudo-IP Header" trừ khi bạn muốn bảo mật chéo.

**Mã nguồn triển khai:**

```python
def compute_checksum(header_without_checksum, payload):
    # Ghép header (với trường checksum = 0) và payload
    packet = header_without_checksum + payload
    
    # Padding thêm 1 byte 0x00 nếu tổng chiều dài là số lẻ
    if len(packet) % 2 != 0:
        packet += b'\x00'
        
    checksum = 0
    # Cộng dồn từng word 16-bit
    for i in range(0, len(packet), 2):
        word = (packet[i] << 8) + packet[i+1]
        checksum += word
        
    # Xử lý tràn bit (Carry fold) - đảm bảo kết quả luôn nằm trong 16 bit
    while (checksum >> 16) > 0:
        checksum = (checksum & 0xffff) + (checksum >> 16)
        
    # Lấy bù 1 (One's complement)
    return ~checksum & 0xffff
```

## 3. Cơ chế Phân mảnh và Gửi (Chunking với `memoryview`)

Sử dụng `memoryview` giúp việc cắt dữ liệu không tạo ra các chuỗi byte nhân bản trong RAM (Zero-copy), rất quan trọng khi truyền file lớn. Do Header dài 16 bytes và Payload dài tối đa 1400 bytes, một gói tin UDP của bạn sẽ có kích thước khoảng 1416 bytes, nằm an toàn trong chuẩn MTU của mạng Ethernet (1500 bytes) để tránh bị IP phân mảnh.

**Mã nguồn triển khai:**

```python
def rdt_send(udp_sock, dest_ip, dest_port, data, current_seq, mss=1400):
    if isinstance(data, str):
        data = data.encode('utf-8')
        
    # Tối ưu RAM bằng memoryview
    mem_view = memoryview(data)
    
    # Phân mảnh dữ liệu thành các chunk
    chunks = [mem_view[i:i+mss] for i in range(0, len(data), mss)]
    
    for chunk in chunks:
        chunk_bytes = chunk.tobytes()
        payload_len = len(chunk_bytes)
        
        # 1. Tạo header nháp với checksum = 0
        # Cờ (flags) giả định gửi data là 0x0001, rwnd khởi tạo giả định 65535
        draft_header = pack_rdt_header(current_seq, ack_num=0, flags=0x0001, checksum=0, rwnd=65535, payload_len=payload_len)
        
        # 2. Tính checksum thực tế
        real_checksum = compute_checksum(draft_header, chunk_bytes)
        
        # 3. Tạo header chính thức
        final_header = pack_rdt_header(current_seq, ack_num=0, flags=0x0001, checksum=real_checksum, rwnd=65535, payload_len=payload_len)
        
        # 4. Gắn header vào payload và gửi qua UDP
        udp_packet = final_header + chunk_bytes
        udp_sock.sendto(udp_packet, (dest_ip, dest_port))
        
        # Tăng Sequence Number theo kích thước payload vừa gửi
        current_seq += payload_len
        
    return current_seq
```

---

## 4. TÀI LIỆU, KEYWORD VÀ NGUỒN HỌC TẬP CHUYÊN SÂU

Để hiểu tận gốc các vấn đề trong đoạn code trên và có kiến thức bảo vệ đồ án, hãy tìm kiếm và đọc các tài liệu sau:

1. **Về Cơ chế Đảm bảo Độ tin cậy (RDT):**
   * **Sách giáo trình:** *Computer Networking: A Top-Down Approach (Kurose & Ross)* - Chương 3: Transport Layer. Hãy đọc kỹ phần **"Principles of Reliable Data Transfer (rdt 1.0, 2.0, 2.1, 2.2, 3.0)"**. Đây là kim chỉ nam cho đồ án này.
   * **Keywords:** `Stop-and-Wait protocol`, `Sliding Window Protocol`, `Go-Back-N (GBN)`, `Selective Repeat`.

2. **Về Giao thức UDP và Lập trình Socket Python:**
   * **Keywords:** `Python socket.SOCK_DGRAM`, `UDP Datagram Maximum Size (MTU)`.
   * **Kiến thức lõi:** Tìm hiểu tại sao IP Fragmentation (phân mảnh ở tầng IP) lại nguy hiểm đối với UDP (mất 1 mảnh là hỏng cả gói) và tại sao bạn phải chủ động chia chunk (MTU/MSS) ở tầng Application. MTU chuẩn thường là 1500 bytes.

3. **Về Xử lý Byte và Memory trong Python:**
   * **Keywords:** `Python struct library format characters`, `Big-Endian vs Little-Endian in Networking`, `Python memoryview zero-copy`.
   * **Kiến thức lõi:** Network Byte Order luôn là Big-Endian (đại diện bởi dấu `!` trong thư viện `struct`). Tìm hiểu sự khác biệt giữa việc cấp phát vùng nhớ mới khi dùng thao tác cắt chuỗi `data[0:1400]` so với việc dùng `memoryview` trỏ tới vùng nhớ cũ.

4. **Về Thuật toán Checksum:**
   * **Tài liệu:** **RFC 1071 (Computing the Internet Checksum)**.
   * **Keywords:** `One's complement sum (Tổng bù 1)`, `Carry fold 16-bit`.
   * **Kiến thức lõi:** Hiểu cách các bit nhớ (carry bit) tràn ra khỏi 16-bit được vòng lại (wrap around) và cộng vào bit thấp nhất như thế nào để đảm bảo không bị thất thoát thông tin lỗi.