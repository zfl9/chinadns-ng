const std = @import("std");
const Builder = std.build.Builder;
const CrossTarget = std.zig.CrossTarget;
const Mode = std.builtin.Mode;
const Step = std.build.Step;
const LibExeObjStep = std.build.LibExeObjStep;

var _b: *Builder = undefined;
var _target: CrossTarget = undefined;
var _build_mode: Mode = undefined;
var _first_error: bool = true;

fn printToStdErr(comptime format: []const u8, args: anytype) void {
    _ = std.io.getStdErr().write(_b.fmt(format ++ "\n", args)) catch unreachable;
}

fn err(comptime format: []const u8, args: anytype) void {
    if (_first_error) {
        _first_error = false;
        printToStdErr("", .{});
    }
    printToStdErr("> ERROR: " ++ format, args);
}

fn errAndExit(comptime format: []const u8, args: anytype) noreturn {
    err(format, args);
    printToStdErr("", .{});
    std.os.exit(1);
}

fn errAndMarkInvalid(comptime format: []const u8, args: anytype) void {
    err(format, args);
    _b.invalid_user_input = true;
}

fn stepLog(comptime format: []const u8, args: anytype) *Step {
    return &_b.addLog(format, args).step;
}

fn optionBuildMode() void {
    const M = enum { fast, small, safe, debug };
    const m = _b.option(M, "mode", "build mode, default: 'fast' (-O3/-OReleaseFast -flto)") orelse .fast;
    _build_mode = switch (m) {
        .fast => .ReleaseFast,
        .small => .ReleaseSmall,
        .safe => .ReleaseSafe,
        .debug => .Debug,
    };
}

/// zig_target="" means that it is `native`
/// return "" if the openssl_target is `native`
fn getOpenSSLTarget(zig_target: []const u8) []const u8 {
    if (zig_target.len == 0)
        return "";

    // {prefix, openssl_target}
    const prefix_target_map = .{
        .{ "native", "" },
        .{ "i386-", "linux-x86-clang" },
        .{ "x86_64-", "linux-x86_64-clang" },
        .{ "aarch64-", "linux-aarch64" },
    };

    inline for (prefix_target_map) |prefix_target| {
        if (std.mem.indexOf(u8, zig_target, prefix_target[0])) |idx| {
            if (idx == 0)
                return prefix_target[1];
        }
    }

    errAndExit("TODO: for targets other than x86, x86_64, aarch64, use wolfssl instead of openssl", .{});
}

fn stepOpenSSL() *Step {
    const openssl = _b.step("openssl", "build openssl dependency");

    // TODO: allow specifying openssl installation path (for different targets), or handle it automatically ?

    const zig_target: []const u8 = if (_b.user_input_options.getPtr("target")) |opt| opt.value.scalar else "";
    const zig_mcpu: []const u8 = if (_b.user_input_options.getPtr("cpu")) |opt| opt.value.scalar else "";

    const zig_target_mcpu = if (zig_target.len != 0 and zig_mcpu.len != 0)
        _b.fmt("-target {s} -mcpu={s}", .{ zig_target, zig_mcpu })
    else if (zig_target.len != 0)
        _b.fmt("-target {s}", .{zig_target})
    else if (zig_mcpu.len != 0)
        _b.fmt("-mcpu={s}", .{zig_mcpu})
    else
        "";
    openssl.dependOn(stepLog("[openssl] zig target: {s}", .{zig_target_mcpu}));

    var openssl_target = getOpenSSLTarget(zig_target);
    openssl.dependOn(stepLog("[openssl] openssl target: {s}", .{openssl_target}));

    const argv_fmt = [_][]const u8{
        "sh",
        "-c",
        \\  set -o nounset
        \\  set -o errexit
        \\  set -o pipefail
        \\  installdir=$(pwd)/dep/openssl
        \\  [ -f $installdir/lib/libssl.a ] && exit
        \\  set -x
        \\  mkdir -p dep
        \\  cd dep
        \\  version=3.1.4
        \\  tarball=openssl-$version.tar.gz
        \\  sourcedir=openssl-$version
        \\  [ -f $tarball ] || wget https://www.openssl.org/source/$tarball
        \\  rm -fr $sourcedir $installdir
        \\  tar -xf $tarball
        \\  cd $sourcedir
        \\  export CC="zig cc {s} -Xclang -O3"
        \\  export CFLAGS="-g0 -O3 -flto -fno-pie -fno-PIE -ffunction-sections -fdata-sections"
        \\  export AR='zig ar'
        \\  export RANLIB='zig ranlib'
        \\  sed -i '/my @disablables/a \    "apps",' ./Configure
        \\  ./Configure {s} --prefix=$installdir --libdir=lib --openssldir=/etc/ssl \
        \\      enable-ktls no-deprecated no-async no-comp no-dgram no-legacy no-pic \
        \\      no-psk no-dso no-shared no-srp no-srtp no-ssl-trace no-tests no-apps no-threads
        \\  make -j$(nproc) build_sw
        \\  make install_sw
    };

    const argv = [_][]const u8{
        argv_fmt[0],
        argv_fmt[1],
        _b.fmt(argv_fmt[2], .{ zig_target_mcpu, openssl_target }),
    };

    openssl.dependOn(&_b.addSystemCommand(&argv).step);

    return openssl;
}

fn addCFileMalloc(exe: *LibExeObjStep) void {
    const use_mimalloc = _b.option(bool, "mimalloc", "using the mimalloc allocator, default: false") orelse false;

    if (!use_mimalloc)
        return;

    exe.step.dependOn(stepLog("[mimalloc] using the mimalloc allocator instead of the default libc allocator", .{}));

    exe.addCSourceFile("dep/mimalloc/src/static.c", &.{
        "-std=gnu11",
        "-Wall",
        "-Wextra",
        "-Wpedantic",
        "-Wstrict-prototypes",
        "-Wno-unknown-pragmas",
        "-Wno-static-in-inline",
        "-DNDEBUG",
        "-DMI_MALLOC_OVERRIDE",
        "-g0",
        "-O3",
        "-flto",
        "-fno-pic",
        "-fno-PIC",
        "-fno-pie",
        "-fno-PIE",
        "-ffunction-sections",
        "-fdata-sections",
        "-fvisibility=hidden",
        "-fno-builtin-malloc",
        "-ftls-model=initial-exec",
    });
}

// chinadns-ng .c files
fn addCFileApp(exe: *LibExeObjStep, comptime files: []const []const u8) void {
    var flags = std.ArrayList([]const u8).init(_b.allocator);
    defer flags.deinit();

    flags.appendSlice(&.{
        "-std=c99",
        "-Wall",
        "-Wextra",
        "-Wvla",
        "-fno-pic",
        "-fno-PIC",
        "-fno-pie",
        "-fno-PIE",
        "-ffunction-sections",
        "-fdata-sections",
    }) catch unreachable;

    switch (_build_mode) {
        .ReleaseFast, .ReleaseSafe => flags.appendSlice(&.{ "-g0", "-O3", "-flto", "-DNDEBUG" }) catch unreachable,
        .ReleaseSmall => flags.appendSlice(&.{ "-g0", "-Os", "-flto", "-DNDEBUG" }) catch unreachable,
        .Debug => flags.appendSlice(&.{ "-ggdb3", "-Og" }) catch unreachable,
    }

    inline for (files) |file| {
        flags.append("-DFILENAME=\"" ++ file ++ "\"") catch unreachable;
        exe.addCSourceFile("src/" ++ file, flags.items);
        _ = flags.pop();
    }
}

pub fn build(b: *Builder) void {
    _build(b);

    if (b.invalid_user_input)
        printToStdErr("", .{});
}

fn _build(b: *Builder) void {
    _b = b;
    _target = b.standardTargetOptions(.{});
    optionBuildMode();

    // zig build openssl
    const openssl = stepOpenSSL();

    // TODO: automatically suffixed with target and mcpu ?
    const exe_name_raw = b.option([]const u8, "name", "executable filename, default: 'chinadns-ng'") orelse "chinadns-ng";
    const exe_name = std.mem.trim(u8, exe_name_raw, " \t\r\n");
    if (exe_name.len <= 0)
        errAndExit("invalid executable filename (-Dname): '{s}'", .{exe_name});

    // exe: chinadns-ng
    const exe = b.addExecutable(exe_name, null);
    exe.setTarget(_target);
    exe.setBuildMode(_build_mode);

    exe.step.dependOn(openssl);

    exe.use_stage1 = true; // async/await
    exe.want_lto = true;
    exe.single_threaded = true;
    exe.link_function_sections = true;
    exe.link_gc_sections = true;
    exe.pie = false;
    if (_target.getAbi().isMusl()) exe.force_pic = false;
    if (_build_mode != .Debug) exe.strip = true;

    exe.addIncludePath("dep/mimalloc/include");
    exe.addIncludePath("dep/openssl/include");

    // to ensure that the standard malloc interface resolves to the mimalloc library, link it as the first object file
    addCFileMalloc(exe);

    addCFileApp(exe, &.{ "main.c", "opt.c", "net.c", "dns.c", "dnl.c", "ipset.c", "nl.c" });

    exe.addLibraryPath("dep/openssl/lib");

    exe.linkSystemLibrary("ssl");
    exe.linkSystemLibrary("crypto");

    exe.linkLibC();

    exe.install();

    // zig build run [-- ARGS...]
    const run = exe.run();
    if (b.args) |args| run.addArgs(args);
    b.step("run", "run chinadns-ng with args").dependOn(&run.step);

    const rm_local_cache = b.addRemoveDirTree(b.cache_root);
    const rm_global_cache = b.addRemoveDirTree(b.global_cache_root);
    const rm_dep_openssl = b.addRemoveDirTree("dep/openssl");

    // zig build clean-local
    const clean_local = b.step("clean-local", b.fmt("clean local build cache: '{s}'", .{b.cache_root}));
    clean_local.dependOn(&rm_local_cache.step);

    // zig build clean-global
    const clean_global = b.step("clean-global", b.fmt("clean global build cache: '{s}'", .{b.global_cache_root}));
    clean_global.dependOn(&rm_global_cache.step);

    // zig build clean-openssl
    const clean_openssl = b.step("clean-openssl", b.fmt("clean openssl dependency: '{s}'", .{"dep/openssl"}));
    clean_openssl.dependOn(&rm_dep_openssl.step);

    // zig build clean
    const clean = b.step("clean", b.fmt("clean all build caches and all dependencies", .{}));
    clean.dependOn(clean_local);
    clean.dependOn(clean_global);
    clean.dependOn(clean_openssl);
}
