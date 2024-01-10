//! - provide type-safety version of C functions
//! - fix improperly translated C code/declarations
const C = @This();

const c = @import("c.zig");
const fmtchk = @import("fmtchk.zig");

const std = @import("std");
const meta = std.meta;
const trait = meta.trait;
const testing = std.testing;

const assert = std.debug.assert;
const isConstPtr = trait.isConstPtr;

// ==============================================================

pub const Str = [*:0]u8;
pub const ConstStr = [*:0]const u8;

// ==============================================================

/// remove const qualification of pointer `ptr`
/// TODO: zig 0.11 has @constCast()
pub inline fn remove_const(ptr: anytype) RemoveConst(@TypeOf(ptr)) {
    return @intToPtr(RemoveConst(@TypeOf(ptr)), @ptrToInt(ptr));
}

/// remove const qualification of pointer type `T`
pub fn RemoveConst(comptime T: type) type {
    if (comptime trait.isConstPtr(T)) {
        var info = @typeInfo(T);
        info.Pointer.is_const = false;
        return @Type(info);
    }
    return T;
}

// ==============================================================

fn IntCast(comptime DestType: type) type {
    return struct {
        pub inline fn cast(integer: anytype) DestType {
            return @intCast(DestType, integer);
        }
    };
}

pub const to_schar = IntCast(c.schar).cast;
pub const to_uchar = IntCast(c.uchar).cast;

pub const to_short = IntCast(c_short).cast;
pub const to_ushort = IntCast(c_ushort).cast;

pub const to_int = IntCast(c_int).cast;
pub const to_uint = IntCast(c_uint).cast;

pub const to_long = IntCast(c_long).cast;
pub const to_ulong = IntCast(c_ulong).cast;

pub const to_longlong = IntCast(c_longlong).cast;
pub const to_ulonglong = IntCast(c_ulonglong).cast;

pub const to_isize = IntCast(isize).cast;
pub const to_usize = IntCast(usize).cast;

pub const to_i8 = IntCast(i8).cast;
pub const to_u8 = IntCast(u8).cast;

pub const to_i16 = IntCast(i16).cast;
pub const to_u16 = IntCast(u16).cast;

pub const to_i32 = IntCast(i32).cast;
pub const to_u32 = IntCast(u32).cast;

pub const to_i64 = IntCast(i64).cast;
pub const to_u64 = IntCast(u64).cast;

// ==============================================================

// redeclared to match the parameter types of fprintf
pub usingnamespace if (isConstPtr(@TypeOf(&c.stdin)))
b: {
    // @compileLog("stdin is const", "is_musl:", builtin.target.abi.isMusl(), "is_glibc:", builtin.target.abi.isGnu());
    break :b struct {
        pub extern const stdin: *c.FILE;
        pub extern const stdout: *c.FILE;
        pub extern const stderr: *c.FILE;
    };
} else b: {
    // @compileLog("stdin is var", "is_musl:", builtin.target.abi.isMusl(), "is_glibc:", builtin.target.abi.isGnu());
    break :b struct {
        pub extern var stdin: *c.FILE;
        pub extern var stdout: *c.FILE;
        pub extern var stderr: *c.FILE;
    };
};

// ==============================================================

pub inline fn streql(str1: ConstStr, str2: ConstStr) bool {
    return c.strcmp(str1, str2) == 0;
}

pub inline fn strlen(str: ConstStr) usize {
    return c.strlen(str);
}

/// end with sentinel 0
pub inline fn is_cstr(comptime S: type) bool {
    return @typeInfo(StrSlice(S, false)).Pointer.sentinel != null;
}

/// string => []u8, []const u8, [:0]u8, [:0]const u8
pub inline fn strslice(str: anytype) StrSlice(@TypeOf(str), false) {
    const S = @TypeOf(str);
    if (comptime trait.isManyItemPtr(S)) {
        comptime assert(meta.sentinel(S).? == 0);
        return std.mem.sliceTo(str, 0);
    }
    return str;
}

/// string => []const u8, [:0]const u8
pub inline fn strslice_c(str: anytype) StrSlice(@TypeOf(str), true) {
    return strslice(str);
}

fn StrSlice(comptime S: type, comptime force_const: bool) type {
    const info = @typeInfo(S);

    if (info != .Pointer)
        @compileError("expected pointer, found " ++ @typeName(S));

    if (meta.Elem(S) != u8)
        @compileError("expected u8 pointer, found " ++ @typeName(S));

    const sentinel = meta.sentinel(S);

    if (sentinel) |end| {
        if (end != 0)
            @compileError("expected sentinel 0, found " ++ @typeName(S));
    }

    const ptr_info = info.Pointer;

    switch (ptr_info.size) {
        .One => if (@typeInfo(ptr_info.child) != .Array)
            @compileError("expected u8 array pointer, found " ++ @typeName(S)),

        .Many => if (sentinel == null)
            @compileError("expected many pointer with sentinel, found " ++ @typeName(S)),

        .Slice => {},

        .C => @compileError("expected non-C pointer, found " ++ @typeName(S)),
    }

    if (force_const or ptr_info.is_const) {
        return if (sentinel != null)
            [:0]const u8
        else
            []const u8;
    } else {
        return if (sentinel != null)
            [:0]u8
        else
            []u8;
    }
}

/// caller own the returned memory | C.free(ptr)
pub fn strdup(str: anytype) [:0]u8 {
    const s = strslice_c(str);
    return strdup_internal(s, malloc_many(u8, s.len + 1).?);
}

/// note: `str` and `buf` cannot overlap
/// similar to strdup, but copy to the given buffer
pub fn strdup_r(str: anytype, buf: []u8) error{NotEnoughSpace}![:0]u8 {
    const s = strslice_c(str);
    if (s.len > buf.len - 1)
        return error.NotEnoughSpace;
    return strdup_internal(s, buf);
}

/// `s`: strslice_c(str)
fn strdup_internal(s: anytype, buf: []u8) [:0]u8 {
    if (comptime is_cstr(@TypeOf(s))) {
        @memcpy(buf.ptr, s.ptr, s.len + 1);
    } else {
        @memcpy(buf.ptr, s.ptr, s.len);
        buf[s.len] = 0;
    }
    return buf[0..s.len :0];
}

// ==============================================================

pub inline fn malloc_one(comptime T: type) ?*T {
    return @ptrCast(?*T, @alignCast(@alignOf(T), c.malloc(@sizeOf(T))));
}

pub inline fn malloc_many(comptime T: type, n: usize) ?[]T {
    return if (c.malloc(@sizeOf(T) * n)) |ptr|
        @ptrCast([*]T, @alignCast(@alignOf(T), ptr))[0..n]
    else
        null;
}

/// if `old_memory.len` is 0 it is treated as a null pointer
pub inline fn realloc(comptime T: type, old_memory: []T, new_n: usize) ?[]T {
    const old_ptr = if (old_memory.len > 0) old_memory.ptr else null;
    const new_ptr = c.realloc(old_ptr, new_n * @sizeOf(T)) orelse return null;
    return @ptrCast([*]T, @alignCast(@alignOf(T), new_ptr))[0..new_n];
}

pub inline fn free(memory: anytype) void {
    const T = @TypeOf(memory);
    if (@typeInfo(T) == .Optional) {
        const m = memory orelse return;
        return free(m);
    }
    return if (comptime trait.isSlice(T)) {
        if (memory.len > 0)
            c.free(remove_const(memory.ptr));
    } else {
        c.free(remove_const(memory));
    };
}

// ==============================================================

pub inline fn errno() c_int {
    return c.__errno_location().*;
}

pub inline fn set_errno(err: c_int) void {
    c.__errno_location().* = err;
}

// ==============================================================

pub inline fn fprintf(file: *c.FILE, comptime fmt: [:0]const u8, args: anytype) void {
    fmtchk.check(fmt, args);
    _ = @call(.{}, c.fprintf, .{ file, fmt.ptr } ++ args);
}

/// print to stdout
pub inline fn printf(comptime fmt: [:0]const u8, args: anytype) void {
    return fprintf(C.stdout, fmt, args);
}

/// print to stderr
pub inline fn printf_err(comptime fmt: [:0]const u8, args: anytype) void {
    return fprintf(C.stderr, fmt, args);
}

/// print to string-buffer
/// return the written c-string
pub fn snprintf(buffer: []u8, comptime fmt: [:0]const u8, args: anytype) [:0]u8 {
    fmtchk.check(fmt, args);

    // at least one character and the null terminator
    assert(buffer.len >= 2);

    // number of characters (not including the terminating null character) which would have been written to buffer if bufsz was ignored,
    // or a negative value if an encoding error (for string and character conversion specifiers) occurred
    var should_strlen = @call(.{}, c.snprintf, .{ buffer.ptr, buffer.len, fmt.ptr } ++ args);

    // reserve space for '\0'
    if (0 <= should_strlen and should_strlen <= buffer.len - 1)
        return buffer[0..to_usize(should_strlen) :0];

    // buffer space not enough
    if (should_strlen > 0)
        return buffer[0..(buffer.len - 1) :0];

    // encoding error
    buffer[0] = 0;
    return buffer[0..0 :0];
}

// ==============================================================

pub inline fn fopen(filename: [:0]const u8, modes: [:0]const u8) ?*c.FILE {
    return c.fopen(filename, modes);
}

pub inline fn fclose(file: *c.FILE) void {
    _ = c.fclose(file);
}

pub inline fn fgets(file: *c.FILE, buf: []u8) ?Str {
    return c.fgets(buf.ptr, to_int(buf.len), file);
}

pub inline fn feof(file: *c.FILE) bool {
    return c.feof(file) != 0;
}

pub inline fn fflush(file: ?*c.FILE) c_int {
    return c.fflush(file);
}

pub inline fn setvbuf(file: *c.FILE, buffer: ?[*]u8, mode: c_int, size: usize) c_int {
    return c.setvbuf(file, buffer, mode, size);
}

// ==============================================================

pub inline fn time() c.time_t {
    return c.time(null);
}

pub inline fn localtime(t: c.time_t) ?*c.struct_tm {
    return c.localtime(&t);
}

// ==============================================================

pub inline fn getenv(env_name: ConstStr) ?ConstStr {
    return c.getenv(env_name);
}

pub inline fn setenv(env_name: ConstStr, value: ConstStr, is_replace: bool) c_int {
    return c.setenv(env_name, value, if (is_replace) 1 else 0);
}

// ==============================================================

/// TODO: rewrite with net.zig
pub inline fn get_ipstr_family(ip: ConstStr) c_int {
    return c.get_ipstr_family(ip);
}

// ==============================================================

pub fn @"test: strdup"() !void {
    const org_str = "helloworld";

    const dup_str = strdup(org_str);
    defer free(dup_str);

    try testing.expectEqual(@as(usize, 10), org_str.len);
    try testing.expectEqual(org_str.len, dup_str.len);
    try testing.expectEqualStrings(org_str, dup_str);

    dup_str[dup_str.len - 1] = 'x';
    try testing.expectEqualStrings(org_str[0 .. org_str.len - 1], dup_str[0 .. dup_str.len - 1]);
}

pub fn @"test: malloc"() !void {
    {
        const p = malloc_one(u64);
        defer free(p);

        const p2 = malloc_many(u32, 10);
        defer free(p2);
    }

    const p_item = malloc_one(u32).?;
    defer free(p_item);

    const items = malloc_many(i64, 10).?;
    defer free(items);

    p_item.* = 99;
    try testing.expectEqual(@as(u32, 99), p_item.*);

    std.mem.set(i64, items, 'a');
    items[items.len - 1] = 'b';

    try testing.expectEqual(@as(usize, 10), items.len);
    try testing.expectEqual(@as(usize, 0), std.mem.indexOfScalar(i64, items, 'a').?);
    try testing.expectEqual(@as(usize, 8), std.mem.lastIndexOfScalar(i64, items, 'a').?);
    try testing.expectEqual(@as(usize, 9), std.mem.indexOfScalar(i64, items, 'b').?);
}

pub fn @"test: strslice"() !void {
    const hello = "hello";
    const N = hello.len;

    const slice = strslice(hello);
    try testing.expectEqual([:0]const u8, @TypeOf(slice));
    try testing.expectEqualStrings(hello, slice);
    try testing.expectEqual(hello.len, slice.len);
    try testing.expectEqual(hello.len, std.mem.indexOfSentinel(u8, 0, slice));

    const const_buf: [N]u8 = hello.*;
    try testing.expectEqual([]const u8, @TypeOf(strslice(&const_buf)));

    const const_buf_z: [N:0]u8 = hello.*;
    try testing.expectEqual([:0]const u8, @TypeOf(strslice(&const_buf_z)));

    var var_buf: [N]u8 = hello.*;
    try testing.expectEqual([]u8, @TypeOf(strslice(&var_buf)));

    var var_buf_z: [N:0]u8 = hello.*;
    try testing.expectEqual([:0]u8, @TypeOf(strslice(&var_buf_z)));
}

pub fn @"test: strslice_c"() !void {
    const hello = "hello";
    const N = hello.len;

    const slice = strslice_c(hello);
    try testing.expectEqual([:0]const u8, @TypeOf(slice));
    try testing.expectEqualStrings(hello, slice);
    try testing.expectEqual(hello.len, slice.len);
    try testing.expectEqual(hello.len, std.mem.indexOfSentinel(u8, 0, slice));

    const const_buf: [N]u8 = hello.*;
    try testing.expectEqual([]const u8, @TypeOf(strslice_c(&const_buf)));

    const const_buf_z: [N:0]u8 = hello.*;
    try testing.expectEqual([:0]const u8, @TypeOf(strslice_c(&const_buf_z)));

    var var_buf: [N]u8 = hello.*;
    try testing.expectEqual([]const u8, @TypeOf(strslice_c(&var_buf)));

    var var_buf_z: [N:0]u8 = hello.*;
    try testing.expectEqual([:0]const u8, @TypeOf(strslice_c(&var_buf_z)));
}

pub fn @"test: set_errno errno"() !void {
    set_errno(c.EAGAIN);
    try testing.expectEqual(c.EAGAIN, errno());
}

pub fn @"test: fopen fclose"() !void {
    // random string as filename
    const pool = "123456789-ABCDEF"; // string-literal => *const [16:0]u8
    var filename: [128:0]u8 = undefined;
    for (filename) |*ch| ch.* = pool[to_usize(c.rand()) % pool.len];
    filename[filename.len] = 0;

    try testing.expectEqual(*const [16:0]u8, @TypeOf(pool));
    try testing.expectEqual(@as(usize, 16), pool.len);
    try testing.expectEqual(@as(u8, 0), pool[pool.len]);
    try testing.expectEqual(16 + 1, @sizeOf(@TypeOf(pool.*))); // .len + sentinel(0)

    try testing.expectEqual(128, filename.len);
    try testing.expectEqual(@sizeOf(@TypeOf(filename)), filename.len + 1);
    try testing.expectEqual(@as(usize, 128), std.mem.indexOfSentinel(u8, 0, &filename));

    // open non-exist file
    {
        const file = fopen(&filename, "rb");
        defer if (file) |f| fclose(f);

        // assuming it fails because the file doesn's exist
        if (file == null)
            try testing.expectEqual(c.ENOENT, errno());
    }

    // open ./build.zig file
    {
        const file = fopen("./build.zig", "rb") orelse unreachable;
        defer fclose(file);
    }
}

pub fn @"test: snprintf normal"() !void {
    var buffer: [11]u8 = undefined;
    const helloworld = "helloworld";
    const str = snprintf(&buffer, "%s", .{helloworld});
    try testing.expect(helloworld.len == 10);
    try testing.expectEqual(helloworld.len, str.len);
    try testing.expectEqualStrings(helloworld, str);
    try testing.expectEqualSentinel(u8, 0, helloworld, str);
}

pub fn @"test: snprintf overflow"() !void {
    var buffer: [10]u8 = undefined;
    const helloworld = "helloworld";
    const str = snprintf(&buffer, "%s", .{helloworld});
    try testing.expectEqual(@as(usize, 9), str.len);
    try testing.expectEqualSlices(u8, helloworld[0..9], str);
    try testing.expectEqualStrings(helloworld[0..9 :'d'], str);
    try testing.expectEqual(@as(usize, 9), std.mem.indexOfSentinel(u8, 0, str));
}
