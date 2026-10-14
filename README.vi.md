# Codé — Framework C2 Học Thuật

> [!CAUTION]
> **Dự án này CHỈ dành cho mục đích HỌC THUẬT và GIÁO DỤC.**
> Chỉ chạy trong môi trường lab biệt lập (host-only).
> Không được sử dụng ngoài mạng ảo có kiểm soát.
> Sử dụng sai mục đích công cụ bảo mật tấn công có thể vi phạm pháp luật
> tại nơi bạn đang ở.

---

## 1. Codé là gì?

Codé là một framework **Command-and-Control (C2)** đa nền tảng, được viết như
một bài tập học thuật để nghiên cứu:

- Kỹ thuật mà đối thủ (adversary) hay dùng
- Thiết kế giao thức mạng
- Lập trình hệ thống đa nền tảng

Framework có ba thành phần:

| Thành phần | Ngôn ngữ | Vai trò |
|---|---|---|
| **Team Server** | Go | Máy chủ trung tâm. Quản lý phiên agent, phân công task, cung cấp API gRPC cho operator. Mỗi phiên chạy trên một goroutine. |
| **Operator Console** | Go (CLI) | Công cụ dòng lệnh để operator điều khiển: liệt kê phiên, gửi task, đọc kết quả. |
| **Agent** | C99 | Implant nhẹ chạy trên máy mục tiêu. Dùng lớp PAL để chạy đa nền tảng, giao tiếp qua TLS (mbedTLS), nói giao thức TLV nhị phân riêng. |

```
┌──────────────┐   gRPC/mTLS   ┌──────────────┐  TLV/TLS 1.3  ┌──────────────┐
│   Operator   │◄─────────────►│  Team Server │◄─────────────►│    Agent     │
│   Console    │               │     (Go)     │               │    (C99)     │
└──────────────┘               └──────────────┘               └──────────────┘
```

---

## 2. Các biện pháp an toàn

> [!IMPORTANT]
> Các biện pháp an toàn được cài sẵn ngay từ **commit đầu tiên**, không phải
> commit cuối. Chúng được áp đặt lúc **biên dịch (compile-time)** và không
> thể vô hiệu hóa khi chạy.

| # | Biện pháp | Mô tả |
|---|---|---|
| 1 | **Danh sách CIDR cho phép** | Phạm vi IP được phép nằm cứng trong binary lúc build. Agent từ chối nói chuyện với bất kỳ server nào có IP nằm ngoài danh sách. Mặc định: `10.13.37.0/24`. |
| 2 | **Hết hạn theo thời gian build** | Mỗi binary chứa dấu thời gian hết hạn (mặc định: 30 ngày kể từ lúc build). Sau thời điểm đó agent in thông báo và thoát ngay. |
| 3 | **Không tạo cơ chế thường trú** | Agent **không** cài registry key, cron job, service hay startup entry. Nó chỉ sống khi tiến trình còn chạy. |
| 4 | **Không tự lan truyền** | Agent không có khả năng tự sao chép, lây lan sang máy khác, hay tải/chạy payload phụ. Nó chỉ làm đúng những gì tập task cho phép. |
| 5 | **Hiển thị bình thường** | Agent chạy như một tiến trình thường, có tên rõ ràng. Không ẩn khỏi process list, không unhook API, không inject vào tiến trình khác. Dễ dàng thấy qua `ps` / Task Manager. |
| 6 | **Cờ `--lab-agent`** | Agent **bắt buộc** phải được chạy với cờ `--lab-agent`. Thiếu cờ này nó chỉ in thông báo an toàn rồi thoát. Mục đích: tránh chạy nhầm. |
| 7 | **Kill switch** | Team Server có thể gửi lệnh `SHUTDOWN` cho bất kỳ agent nào. Ngoài ra, agent kiểm tra file kill-switch cục bộ (`/tmp/.lab-c2-stop` trên Linux, `%TEMP%\.lab-c2-stop` trên Windows). Nếu file xuất hiện, agent thoát ngay lập tức. |

---

## 3. Môi trường lab

Framework được thiết kế và chỉ được kiểm thử trong môi trường sau:

```
┌─────────────────────────────────────────────────────┐
│              Mạng VMware Host-Only                   │
│              Subnet: 10.13.37.0/24                   │
│                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────┐ │
│  │  Team Server │  │  Máy mục tiêu│  │ Máy mục tiêu│ │
│  │  + Operator  │  │   (Linux)    │  │ (Windows)  │ │
│  │  10.13.37.1  │  │ 10.13.37.10  │  │ 10.13.37.20│ │
│  └──────────────┘  └──────────────┘  └────────────┘ │
│                                                      │
│  Mạng: chỉ host-only (không NAT, không bridged)      │
│  Các VM không thể ra Internet                        │
└─────────────────────────────────────────────────────┘
```

- **Hypervisor**: VMware Workstation / Fusion ở chế độ host-only
- **Subnet**: `10.13.37.0/24`
- **Cách ly**: không gắn NAT, không gắn bridged — VM không ra được Internet
  và không nối được tới bất kỳ mạng nào ngoài phân đoạn host-only.

---

## 4. Nền tảng được hỗ trợ

Agent biên dịch được cho **7 cặp OS/kiến trúc**:

| # | OS | Kiến trúc | Toolchain | Trạng thái |
|---|---|---|---|---|
| 1 | Linux | i386 (x86) | `i686-linux-musl` | ✅ |
| 2 | Linux | amd64 (x86_64) | `x86_64-linux-musl` | ✅ |
| 3 | Linux | armv7 (ARM 32-bit) | `arm-linux-musleabihf` | ✅ |
| 4 | Linux | aarch64 (ARM 64-bit) | `aarch64-linux-musl` | ✅ |
| 5 | Windows | i386 (x86) | `i686-w64-mingw32` | ✅ |
| 6 | Windows | amd64 (x86_64) | `x86_64-w64-mingw32` | ✅ |
| 7 | Windows | aarch64 (ARM 64-bit) | `aarch64-w64-mingw32` | ✅ |
| — | ~~Windows~~ | ~~armv7~~ | — | ❌ Không có toolchain |

Toàn bộ bản Linux link tĩnh với musl libc, cho ra binary tĩnh hoàn toàn.

---

## 5. Hướng dẫn build

### Yêu cầu công cụ

- **Go 1.22+** — cho Team Server và Operator Console
- **GCC / Clang** — build agent trên máy hiện tại
- **Toolchain cross-compile** — `musl-cross` cho Linux, `MinGW-w64` cho Windows
- **mbedTLS 3.x** — đặt sẵn trong `agent/vendor/mbedtls/`
- **protoc + protoc-gen-go + protoc-gen-go-grpc** — sinh code gRPC
- **OpenSSL** — tạo chứng chỉ TLS
- **GNU Make 4.0+**

### Bắt đầu nhanh

```bash
# 1. Sinh chứng chỉ TLS cho mạng lab
make certs

# 2. Build Team Server
make server

# 3. Build Operator Console
make console

# 4. Build agent cho máy hiện tại
make agent

# 5. Hoặc build chéo cho cả 7 nền tảng
make agent-all

# 6. Chạy toàn bộ test
make test
```

### Tuỳ chọn build cho agent

Agent có thể nhận các tuỳ chọn qua biến môi trường hoặc tham số Make:

```bash
# Đặt danh sách CIDR cho phép (ngăn cách bằng dấu phẩy)
make agent CIDR_ALLOWLIST="10.13.37.0/24,192.168.100.0/24"

# Đặt thời gian hết hạn (số giây tính từ lúc build)
make agent EXPIRY_SECONDS=86400    # 24 giờ

# Đặt địa chỉ Team Server
make agent SERVER_HOST=10.13.37.1 SERVER_PORT=443

# Đặt chu kỳ beacon và độ nhiễu (jitter)
make agent BEACON_INTERVAL=30 BEACON_JITTER=20
```

---

## 6. Chạy thử trong 60 giây

Khi đã có binary trong `build/`:

```bash
# Terminal 1 — chạy Team Server
./build/serverd --listen 10.13.37.1:443 \
                --cert certs/server.crt \
                --key  certs/server.key

# Terminal 2 — chạy agent trên máy mục tiêu (bắt buộc có --lab-agent)
./build/code_agent --lab-agent

# Terminal 3 — mở console để điều khiển
./build/console sessions list
./build/console task <session-id> shell "whoami"
```

Muốn **tắt khẩn cấp** một agent? Chỉ cần tạo file kill-switch:

```bash
# Trên Linux
touch /tmp/.lab-c2-stop

# Trên Windows (PowerShell)
New-Item -ItemType File $env:TEMP\.lab-c2-stop
```

Agent sẽ phát hiện ở chu kỳ beacon kế tiếp và thoát ngay.

---

## 7. Cấu trúc dự án

```
Codé/
├── README.md                  # README tiếng Anh
├── README.vi.md               # README tiếng Việt (file này)
├── PROTOCOL.md                # Đặc tả giao thức wire
├── Makefile                   # Build chính
├── certs/                     # Script sinh chứng chỉ TLS
├── server/                    # Team Server (Go)
│   ├── cmd/serverd/           # Điểm vào
│   └── internal/
│       ├── audit/             # Ghi audit log JSON-lines
│       ├── codec/             # Codec TLV
│       ├── grpcapi/           # API gRPC cho operator (mTLS)
│       ├── listener/          # TLS listener cho agent
│       ├── session/           # Máy trạng thái phiên
│       └── taskqueue/         # Hàng đợi task theo từng phiên
├── console/                   # Operator Console (Go CLI)
└── agent/                     # Agent (C99)
    ├── include/               # Headers (giao diện)
    ├── src/                   # Nguồn
    │   ├── main.c             # Điểm vào
    │   ├── agent.c            # Vòng beacon & đăng ký
    │   ├── protocol.c         # Máy trạng thái + TLS I/O
    │   ├── tlv.c              # Codec TLV
    │   ├── capabilities.c     # Dispatch task
    │   ├── safety.c           # Expiry, CIDR, kill switch
    │   ├── pal_linux.c        # PAL — Linux/POSIX
    │   └── pal_win32.c        # PAL — Windows/Winsock2
    └── tests/                 # Unit test
```

---

## 8. Giao thức

Xem [PROTOCOL.md](PROTOCOL.md) để biết đầy đủ về giao thức wire: định dạng
thông điệp, các trường TLV, sơ đồ máy trạng thái.

---

## 9. Đóng góp

Đây là một dự án học thuật. Mọi đóng góp cần:

1. Giữ nguyên hoặc tăng cường các biện pháp an toàn
2. Có test cho chức năng mới
3. Theo đúng style sẵn có (C99, Go idiomatic)
4. **Không** thêm persistence, tự lan truyền, hay né tránh phát hiện

---

## 10. Giấy phép

Mã nguồn được cung cấp chỉ cho mục đích giáo dục. Xem phần đầu từng file để
biết chi tiết giấy phép.

---

## 11. Miễn trừ trách nhiệm

Phần mềm này được cung cấp **nguyên trạng (as-is)** cho mục đích giáo dục và
nghiên cứu trong môi trường lab có kiểm soát. Tác giả không chịu trách nhiệm
cho bất kỳ việc sử dụng sai nào. **Luôn xin đúng phép trước khi kiểm thử bảo
mật.** Truy cập trái phép vào hệ thống máy tính là hành vi phạm pháp.
