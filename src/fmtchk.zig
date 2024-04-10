const std = @import("std");
const c = @import("c.zig");
const cc = @import("cc.zig");
const Type = std.builtin.Type;
const StructField = Type.StructField;

fn SliceIterator(comptime T: type) type {
    return struct {
        slice: []const T, // ptr + len
        pos: usize = 0, // next pos

        const Self = @This();

        fn init(comptime slice: []const T) Self {
            return .{ .slice = slice };
        }

        fn empty(comptime self: *const Self) bool {
            return self.pos >= self.slice.len;
        }

        fn peek(comptime self: *const Self) ?T {
            if (self.empty()) return null;
            return self.slice[self.pos];
        }

        fn peek_force(comptime self: *const Self) T {
            if (self.empty()) unreachable;
            return self.slice[self.pos];
        }

        fn pop(comptime self: *Self) ?T {
            if (self.empty()) return null;
            defer self.pos += 1;
            return self.slice[self.pos];
        }

        fn pop_force(comptime self: *Self) T {
            return self.pop().?;
        }

        fn pop_force_void(comptime self: *Self) void {
            _ = self.pop_force();
        }
    };
}

const FormatIterator = SliceIterator(u8);
const ArgsIterator = SliceIterator(StructField);

// https://en.cppreference.com/w/c/io/fprintf
// https://cplusplus.com/reference/cstdio/printf/
// https://man7.org/linux/man-pages/man3/printf.3.html
fn parse_flags(comptime format: *FormatIterator) void {
    while (true) {
        const char = format.peek() orelse return;
        switch (char) {
            '-', '+', ' ', '#', '0' => format.pop_force_void(),
            else => return,
        }
    }
}

fn parse_width(comptime format: *FormatIterator, comptime args: *ArgsIterator) void {
    const char = format.peek() orelse return;
    if (char == '*') {
        // width in args
        format.pop_force_void();
        const arg = args.pop() orelse @compileError("expect a c_int for width '*'");
        if (arg.field_type != c_int) @compileError("expect a c_int for width '*', but got a " ++ @typeName(arg.field_type));
    } else {
        // width in format
        while (!format.empty() and '0' <= format.peek_force() and format.peek_force() <= '9')
            format.pop_force_void();
    }
}

/// return true if precision is specified
fn parse_precision(comptime format: *FormatIterator, comptime args: *ArgsIterator) bool {
    const char = format.peek() orelse return false;

    if (char == '.') {
        format.pop_force_void();

        // if neither a number nor * is used, the precision is taken as zero
        const next_char = format.peek() orelse return true;

        if (next_char == '*') {
            // width in args
            format.pop_force_void();
            const arg = args.pop() orelse @compileError("expect a c_int for precision '*'");
            if (arg.field_type != c_int) @compileError("expect a c_int for precision '*', but got a " ++ @typeName(arg.field_type));
        } else {
            // width in format
            while (!format.empty() and '0' <= format.peek_force() and format.peek_force() <= '9')
                format.pop_force_void();
        }

        return true;
    }

    return false;
}

const Modifier = enum {
    none,
    hh, // char
    h, // short
    l, // long
    ll, // long long
    j, // max
    z, // size
    t, // ptrdiff
    L, // long double

    fn desc(m: Modifier) [:0]const u8 {
        return if (m == .none) "" else @tagName(m);
    }
};

fn parse_modifier(comptime format: *FormatIterator) Modifier {
    const char = format.peek() orelse return .none;
    switch (char) {
        'h' => {
            format.pop_force_void();
            if (!format.empty() and format.peek_force() == 'h') {
                format.pop_force_void();
                return .hh;
            }
            return .h;
        },
        'l' => {
            format.pop_force_void();
            if (!format.empty() and format.peek_force() == 'l') {
                format.pop_force_void();
                return .ll;
            }
            return .l;
        },
        'j' => {
            format.pop_force_void();
            return .j;
        },
        'z' => {
            format.pop_force_void();
            return .z;
        },
        't' => {
            format.pop_force_void();
            return .t;
        },
        'L' => {
            format.pop_force_void();
            return .L;
        },
        else => return .none,
    }
}

fn parse_specifier(comptime format: *FormatIterator, comptime args: *ArgsIterator, modifier: Modifier, has_precision: bool) void {
    const c_float_or_double = struct {}; // float or double
    const c_string = struct {}; // const char *
    const c_pointer = struct {}; // const void *

    const specifier = format.pop() orelse @compileError("expect a specifier character");

    const expect_type: type = switch (specifier) {
        'd', 'i' => switch (modifier) {
            // signed integer
            .none => c_int,
            .hh => c.schar,
            .h => c_short,
            .l => c_long,
            .ll => c_longlong,
            .j => c.intmax_t,
            .z => isize,
            .t => c.ptrdiff_t,
            else => |m| @compileError("the length modifier '" ++ m.desc() ++ "' cannot be applied to %" ++ [_]u8{specifier}),
        },
        'u', 'o', 'x', 'X' => switch (modifier) {
            // unsigned integer
            .none => c_uint,
            .hh => c.uchar,
            .h => c_ushort,
            .l => c_ulong,
            .ll => c_ulonglong,
            .j => c.uintmax_t,
            .z => usize,
            .t => c.ptrdiff_t,
            else => |m| @compileError("the length modifier '" ++ m.desc() ++ "' cannot be applied to %" ++ [_]u8{specifier}),
        },
        'f', 'F', 'e', 'E', 'g', 'G', 'a', 'A' => switch (modifier) {
            // floating-point
            .none => c_float_or_double,
            .L => c_longdouble,
            else => |m| @compileError("the length modifier '" ++ m.desc() ++ "' cannot be applied to %" ++ [_]u8{specifier}),
        },
        'c' => switch (modifier) {
            // character
            .none => c.char,
            else => |m| @compileError("the length modifier '" ++ m.desc() ++ "' cannot be applied to %" ++ [_]u8{specifier}),
        },
        's' => switch (modifier) {
            // c string
            .none => c_string,
            else => |m| @compileError("the length modifier '" ++ m.desc() ++ "' cannot be applied to %" ++ [_]u8{specifier}),
        },
        'p' => switch (modifier) {
            // void *
            .none => c_pointer,
            else => |m| @compileError("the length modifier '" ++ m.desc() ++ "' cannot be applied to %" ++ [_]u8{specifier}),
        },
        'n' => switch (modifier) {
            // the number of characters written so far is stored into the integer pointed to by the corresponding argument.
            .none => *c_int,
            .hh => *c.schar,
            .h => *c_short,
            .l => *c_long,
            .ll => *c_longlong,
            .j => *c.intmax_t,
            .z => *isize,
            .t => *c.ptrdiff_t,
            else => |m| @compileError("the length modifier '" ++ m.desc() ++ "' cannot be applied to %" ++ [_]u8{specifier}),
        },
        'm' => switch (modifier) {
            // glibc extension; supported by uClibc and musl.
            // print output of strerror(errno).
            // no argument is required.
            .none => return,
            else => |m| @compileError("the length modifier '" ++ m.desc() ++ "' cannot be applied to %" ++ [_]u8{specifier}),
        },
        else => @compileError("invalid specifier character: %" ++ modifier.desc() ++ [_]u8{specifier}),
    };

    const arg = args.pop() orelse @compileError("expect a " ++ @typeName(expect_type) ++ " for specifier %" ++ modifier.desc() ++ [_]u8{specifier});
    const arg_type = arg.field_type;

    // checks the arg_type and return if it is correct
    switch (expect_type) {
        c_float_or_double => {
            if (arg_type == f32 or arg_type == f64) return;
        },
        c_string => {
            const info = @typeInfo(arg_type);
            if (info == .Pointer) switch (info.Pointer.size) {
                .One => {
                    // pointer to c.char array ?
                    const item_info = @typeInfo(info.Pointer.child);
                    if (item_info == .Array) {
                        if (item_info.Array.child == c.char and (has_precision or has_sentinel_0(arg_type))) return;
                    }
                },
                .Many => {
                    // pointer to c.char ?
                    if (info.Pointer.child == c.char and (has_precision or has_sentinel_0(arg_type))) return;
                },
                else => {},
            };
        },
        c_pointer => {
            const info = @typeInfo(arg_type);
            if (info == .Pointer) return;

            // sizeof(optional-pointer) == sizeof(pointer)
            // `null` of the optional-pointer is guaranteed to be address `0`
            if (info == .Optional) {
                const UnwrappedType = info.Optional.child;
                if (@typeInfo(UnwrappedType) == .Pointer) return;
            }
        },
        else => {
            if (arg_type == expect_type) return;
        },
    }

    @compileError("expect a " ++ @typeName(expect_type) ++ " for specifier %" ++ modifier.desc() ++ [_]u8{specifier} ++ ", but got a " ++ @typeName(arg_type));
}

fn has_sentinel_0(comptime T: type) bool {
    const end = std.meta.sentinel(T) orelse return false;
    return end == 0;
}

// ================================================================================

fn do_check(comptime in_format: [:0]const u8, comptime ArgsType: type) void {
    var format = FormatIterator.init(in_format);

    const typeinfo: Type = @typeInfo(ArgsType);

    if (typeinfo != .Struct)
        @compileError("args must be a tuple, got " ++ @typeName(ArgsType));

    const info = typeinfo.Struct;
    if (!info.is_tuple)
        @compileError("args must be a tuple, got " ++ @typeName(ArgsType));

    var args = ArgsIterator.init(info.fields);

    // %[flags][width][.precision][modifier]specifier
    while (format.pop()) |char| {
        if (char != '%') continue;

        // %% means % character
        const next_char = format.peek() orelse @compileError("expect a specifier character");
        if (next_char == '%') {
            format.pop_force_void();
            continue;
        }

        parse_flags(&format);
        parse_width(&format, &args);
        const has_precision = parse_precision(&format, &args);
        const modifier = parse_modifier(&format);
        parse_specifier(&format, &args, modifier, has_precision);
    }

    if (!args.empty()) {
        const pos = args.pos + 1;
        @compileError(std.fmt.comptimePrint("there is a redundant argument {s} at position {}", .{ @typeName(args.pop_force().field_type), pos }));
    }
}

/// check whether printf's format string and parameter type match each other (comptime)
pub fn check(comptime format: [:0]const u8, args: anytype) void {
    comptime do_check(format, @TypeOf(args));
}

pub fn @"test: checker"() !void {
    // integer
    var schar: c.schar = 10;
    var uchar: c.uchar = 10;
    var short: c_short = 10;
    var ushort: c_ushort = 10;
    var int: c_int = 10;
    var uint: c_uint = 10;
    var long: c_long = 10;
    var ulong: c_ulong = 10;
    var longlong: c_longlong = 10;
    var ulonglong: c_ulonglong = 10;
    var intmax: c.intmax_t = 10;
    var uintmax: c.uintmax_t = 10;
    var ssize: isize = 10; // signed
    var size: usize = 10; // unsigned
    var ptrdiff: c.ptrdiff_t = 10; // signed

    // floating-point
    var float: c.float = 10.32;
    var double: c.double = 3.14159;
    var longdouble: c_longdouble = 123.456;

    // character
    var char: c.char = 10;

    // string
    var string_p_array = "world"; // string literal: *const [N:0]u8
    var string_p_many: [*:0]const c.char = string_p_array;

    // pointer
    var pointer_optional: ?*const anyopaque = null;
    var pointer = &ptrdiff;

    // ========================================================

    check("hello, world\n", .{});

    // signed integer %d %i
    check("hello, %s %hhd %s\n", .{ "world", schar, string_p_many });
    check("hello, %s %hd %s\n", .{ "world", short, string_p_array });
    check("hello, %s %d %s\n", .{ "world", int, string_p_array });
    check("hello, %s %ld %s\n", .{ "world", long, string_p_many });
    check("hello, %s %lli %s\n", .{ "world", longlong, string_p_many });
    check("hello, %s %ji %s\n", .{ "world", intmax, string_p_array });
    check("hello, %s %zi %s\n", .{ "world", ssize, string_p_many });
    check("hello, %s %ti %s\n", .{ "world", ptrdiff, string_p_array });

    // unsigned integer %u %o %x %X
    check("hello, %s %hhu %s\n", .{ "world", uchar, string_p_many });
    check("hello, %s %hu %s\n", .{ "world", ushort, string_p_array });
    check("hello, %s %o %s\n", .{ "world", uint, string_p_array });
    check("hello, %s %lo %s\n", .{ "world", ulong, string_p_many });
    check("hello, %s %llx %s\n", .{ "world", ulonglong, string_p_array });
    check("hello, %s %jx %s\n", .{ "world", uintmax, string_p_many });
    check("hello, %s %zX %s\n", .{ "world", size, string_p_many });
    check("hello, %s %tX %s\n", .{ "world", ptrdiff, string_p_array });

    // float/double %f %F %e %E %g %G %a %A
    check("hello, %s %f %s\n", .{ "world", float, string_p_many });
    check("hello, %s %F %s\n", .{ "world", double, string_p_array });
    check("hello, %s %e %s\n", .{ "world", float, string_p_many });
    check("hello, %s %E %s\n", .{ "world", double, string_p_array });
    check("hello, %s %g %s\n", .{ "world", float, string_p_many });
    check("hello, %s %G %s\n", .{ "world", double, string_p_many });
    check("hello, %s %a %s\n", .{ "world", float, string_p_array });
    check("hello, %s %A %s\n", .{ "world", double, string_p_array });

    // long double %f %F %e %E %g %G %a %A
    check("hello, %s %Lf %s\n", .{ "world", longdouble, string_p_many });
    check("hello, %s %LF %s\n", .{ "world", longdouble, string_p_many });
    check("hello, %s %Le %s\n", .{ "world", longdouble, string_p_array });
    check("hello, %s %LE %s\n", .{ "world", longdouble, string_p_array });
    check("hello, %s %Lg %s\n", .{ "world", longdouble, string_p_array });
    check("hello, %s %LG %s\n", .{ "world", longdouble, string_p_many });
    check("hello, %s %La %s\n", .{ "world", longdouble, string_p_many });
    check("hello, %s %LA %s\n", .{ "world", longdouble, string_p_many });

    // character %c
    check("hello, %s %LA %s %c\n", .{ "world", longdouble, string_p_many, char });

    // string %s
    check("hello, %s %s %%\n", .{ "world", "foo" });
    check("hello, %s %s %%%%\n", .{ "world", string_p_array });
    check("hello, %s %s %%\n", .{ "world", string_p_many });
    check("hello, %s %s %%%%\n", .{ "world", string_p_array });
    check("hello, %s %s %%\n", .{ "world", string_p_many });

    // pointer %p
    check("hello, %s %s %% %p\n", .{ "world", string_p_array, pointer_optional });
    check("hello, %s %s %% %p\n", .{ "world", string_p_many, &pointer_optional });
    check("hello, %s %s %% %p\n", .{ "world", string_p_array, pointer });
    check("hello, %s %s %% %p\n", .{ "world", string_p_many, &pointer });

    // get the number of characters written %n
    check("hello, %s %hhn %s\n", .{ "world", &schar, string_p_array });
    check("hello, %s %hn %s\n", .{ "world", &short, string_p_array });
    check("hello, %s %n %s\n", .{ "world", &int, string_p_many });
    check("hello, %s %ln %s\n", .{ "world", &long, string_p_many });
    check("hello, %s %lln %s\n", .{ "world", &longlong, string_p_array });
    check("hello, %s %jn %s\n", .{ "world", &intmax, string_p_array });
    check("hello, %s %zn %s\n", .{ "world", &ssize, string_p_many });
    check("hello, %s %tn %s\n", .{ "world", &ptrdiff, string_p_many });

    // strerror(errno) %m
    check("failed to do something: (%d) %m\n", .{cc.errno()}); // supported by glibc and musl
    check("failed to do something: (%#m) %m\n", .{}); // supported by glibc only. in musl, %#m equals %m

    // flags
    // '#': alternate form
    // '-': left justified
    // '0': zero padded (for integer and floating-point)
    // '+': a sign (+ or -) should always be placed before a number produced by a signed conversion
    // ' ': if the result of a signed conversion does not start with a sign character, or is empty, space is prepended to the result.
    check("hello %% %+d % ld %+lli % hhd %%", .{ int, long, longlong, schar });
    check("hello %% %#o %#lx %#llX %%", .{ uint, ulong, ulonglong });
    check("hello %% %#-o %#lx %#-llX %%", .{ uint, ulong, ulonglong });
    check("hello %% %#f %#F %#e %#E %#g %#G %#a %#A %%", .{ float, double, float, double, float, double, float, double });
    check("hello %% %#Lf %#LF %#Le %#LE %%", .{ longdouble, longdouble, longdouble, longdouble });
    check("hello %% %#Lg %#LG %#La %#LA %%", .{ longdouble, longdouble, longdouble, longdouble });

    // width
    check("hello, %ld %123s %lld\n", .{ long, string_p_many, longlong });
    check("hello, %ld %*s %lld\n", .{ long, int, string_p_array, longlong });

    // precision
    check("hello, %lld %.12s %lld\n", .{ longlong, string_p_array, longlong });
    check("hello, %hhd %.*s %hu\n", .{ schar, int, string_p_array, ushort });
    check("hello, %hhd %.s %hu\n", .{ schar, string_p_many, ushort });

    // width + precision
    check("hello, %ld %20.33s %lld\n", .{ long, string_p_many, longlong });
    check("hello, %ld %20.*s %lld\n", .{ long, int, string_p_array, longlong });
    check("hello, %ld %20.s %lld\n", .{ long, string_p_many, longlong });
    check("hello, %ld %*.20s %lld\n", .{ long, int, string_p_array, longlong });
    check("hello, %ld %*.*s %lld\n", .{ long, int, int, string_p_array, longlong });
    check("hello, %ld %*.s %lld\n", .{ long, int, string_p_many, longlong });
}
