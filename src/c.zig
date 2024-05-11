// usually you should only have one `@cImport` in your entire application,
// because it saves the compiler from invoking clang multiple times,
// and prevents inline functions from being duplicated.

// import into the current namespace (c.zig)
// mainly used to access C constants, C typedefs
// please give priority to using functions in the `cc` namespace
pub usingnamespace @cImport({
    @cDefine("_GNU_SOURCE", {});

    @cInclude("stdio.h");
    @cInclude("stdlib.h");
    @cInclude("stdint.h");
    @cInclude("stddef.h");
    @cInclude("string.h");
    @cInclude("errno.h");
    @cInclude("unistd.h");
    @cInclude("signal.h");
    @cInclude("time.h");
    @cInclude("fcntl.h");
    @cInclude("sys/types.h");
    @cInclude("sys/epoll.h");
    @cInclude("sys/socket.h");
    @cInclude("sys/mman.h");
    @cInclude("arpa/inet.h");
    @cInclude("netinet/in.h");
    @cInclude("netinet/tcp.h");
    @cInclude("linux/limits.h");

    @cInclude("src/net.h");
    @cInclude("src/dns.h");
    @cInclude("src/dnl.h");
    @cInclude("src/ipset.h");
    @cInclude("src/misc.h");
    @cInclude("src/wolfssl.h");
});

/// assuming CHAR_BIT=8
/// character type (signed or unsigned)
/// currently zig assumes it is **unsigned**
/// https://github.com/ziglang/zig/issues/875
pub const char = u8;

/// assuming CHAR_BIT=8
/// signed integer type
pub const schar = i8;

/// assuming CHAR_BIT=8
/// unsigned integer type
pub const uchar = u8;

/// assuming IEEE-754 binary32 format
/// single precision floating-point type
pub const float = f32;

/// assuming IEEE-754 binary64 format
/// double precision floating-point type
pub const double = f64;

/// u16 big-endian (used to label the byte order)
pub const be16 = u16;

/// u32 big-endian (used to label the byte order)
pub const be32 = u32;

/// u64 big-endian (used to label the byte order)
pub const be64 = u64;
