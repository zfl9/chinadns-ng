const std = @import("std");
const assert = std.debug.assert;

/// ```zig
/// const Flags = enum(u8) {
///     foo = 1 << 0,
///     bar = 1 << 1,
///     xyz = 1 << 2,
///     _,
///     usingnamespace flags_op.get(Flags);
/// };
/// ```
pub fn get(comptime Enum: type) type {
    comptime assert(@typeInfo(Enum) == .Enum);
    const enum_info = @typeInfo(Enum).Enum;
    const Int = enum_info.tag_type;
    comptime assert(!enum_info.is_exhaustive);

    return struct {
        /// ```zig
        /// const flags = Flags.from(.{.flag_a, .flag_b, .flag_c});
        /// ```
        pub inline fn from(comptime list: anytype) Enum {
            comptime {
                var res_enum = empty();
                for (list) |flags|
                    res_enum.add(flags);
                return res_enum;
            }
        }

        pub inline fn from_int(value: Int) Enum {
            return @intToEnum(Enum, value);
        }

        pub inline fn empty() Enum {
            return from_int(0);
        }

        pub inline fn full() Enum {
            return from_int(std.math.maxInt(Int));
        }

        pub inline fn int(self: Enum) Int {
            return @enumToInt(self);
        }

        pub inline fn add(self: *Enum, flags: Enum) void {
            self.* = from_int(self.int() | flags.int());
        }

        pub inline fn rm(self: *Enum, flags: Enum) void {
            self.* = from_int(self.int() & ~flags.int());
        }

        /// for single flag bit
        /// for multiple flag bits, equivalent to `has_all`
        pub inline fn has(self: Enum, flags: Enum) bool {
            return self.int() & flags.int() == flags.int();
        }

        /// for multiple flag bits
        pub const has_all = has;

        /// for multiple flag bits
        pub inline fn has_any(self: Enum, flags: Enum) bool {
            return self.int() & flags.int() != 0;
        }

        pub inline fn is_empty(self: Enum) bool {
            return self.int() == 0;
        }

        pub inline fn is_full(self: Enum) bool {
            return self.int() == std.math.maxInt(Int);
        }

        pub inline fn to_empty(self: *Enum) void {
            self.* = empty();
        }

        pub inline fn to_full(self: *Enum) void {
            self.* = full();
        }
    };
}
