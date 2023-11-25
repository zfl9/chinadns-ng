const std = @import("std");
const Builder = std.build.Builder;
const CrossTarget = std.zig.CrossTarget;
const Mode = std.builtin.Mode;
const Step = std.build.Step;
const LibExeObjStep = std.build.LibExeObjStep;

var _b: *Builder = undefined;
var _target: CrossTarget = undefined;
var _build_mode: Mode = undefined;

fn buildModeOption() void {
    const M = enum { fast, small, safe, debug };
    const m = _b.option(M, "build", "build mode, default is `fast` (release-fast)") orelse .fast;
    _build_mode = switch (m) {
        .fast => .ReleaseFast,
        .small => .ReleaseSmall,
        .safe => .ReleaseSafe,
        .debug => .Debug,
    };
}

// chinadns-ng .c files
fn addAppCFiles(exe: *LibExeObjStep, comptime files: []const []const u8) !void {
    var flags = std.ArrayList([]const u8).init(_b.allocator);
    defer flags.deinit();

    try flags.appendSlice(&.{
        "-pipe",
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
    });

    switch (_build_mode) {
        .ReleaseFast, .ReleaseSafe => try flags.appendSlice(&.{ "-g0", "-O3", "-flto" }),
        .ReleaseSmall => try flags.appendSlice(&.{ "-g0", "-Os", "-flto" }),
        .Debug => try flags.appendSlice(&.{ "-Og", "-ggdb3" }),
    }

    inline for (files) |file| {
        try flags.append("-DFILENAME=\"" ++ file ++ "\"");
        exe.addCSourceFile("src/" ++ file, flags.items);
        _ = flags.pop();
    }
}

fn addMiMallocCFile(exe: *LibExeObjStep) void {
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

fn opensslTargetOption(zig_target: []const u8) ![]const u8 {
    const Target = enum {
        @"linux-x86-clang",
        @"linux-x86_64-clang",
        @"linux-armv4",
        @"linux-aarch64",
    };

    const openssl_target = _b.option(Target, "openssl_target", "./Configure <target> (default: auto-detection)");

    if (openssl_target) |target|
        return @tagName(target);

    if (std.mem.eql(u8, zig_target, "native"))
        return "";

    if (std.mem.indexOf(u8, zig_target, "i386-")) |idx|
        if (idx == 0)
            return @tagName(Target.@"linux-x86-clang");

    if (std.mem.indexOf(u8, zig_target, "x86_64-")) |idx|
        if (idx == 0)
            return @tagName(Target.@"linux-x86_64-clang");

    if (std.mem.indexOf(u8, zig_target, "arm-")) |idx|
        if (idx == 0)
            return @tagName(Target.@"linux-armv4");

    if (std.mem.indexOf(u8, zig_target, "aarch64-")) |idx|
        if (idx == 0)
            return @tagName(Target.@"linux-aarch64");

    std.log.err("{s} is not supported, only i386, x86_64, arm, aarch64 are supported.", .{zig_target});
    return error.UnsupportedTarget;
}

fn buildOpenSSL() !*Step {
    // TODO: support -Dcpu
    const zig_target = try _target.zigTriple(_b.allocator);
    const openssl_target = try opensslTargetOption(zig_target);

    // std.log.info("zig_target: {s}", .{zig_target});
    // std.log.info("openssl_target: {s}", .{openssl_target});

    const argv_fmt = [_][]const u8{
        "sh", "-c",
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
        \\  tar -xvf $tarball
        \\  cd $sourcedir
        \\  export CC="zig cc -target {s} -Xclang -O3"
        \\  export CFLAGS="-g0 -O3 -flto -fno-pie -fno-PIE -ffunction-sections -fdata-sections"
        \\  export AR='zig ar'
        \\  export RANLIB='zig ranlib'
        \\	./Configure {s} --prefix=$installdir --libdir=lib \
        \\      enable-ktls no-deprecated no-async no-comp no-dgram no-legacy no-pic \
        \\      no-psk no-dso no-shared no-srp no-srtp no-ssl-trace no-tests
        \\  make -j$(nproc) build_sw
        \\  make install_sw
    };

    const argv = [_][]const u8{
        argv_fmt[0],
        argv_fmt[1],
        _b.fmt(argv_fmt[2], .{ zig_target, openssl_target }),
    };

    const openssl = _b.step("openssl", "build `openssl` dependency lib");
    openssl.dependOn(&_b.addSystemCommand(&argv).step);

    return openssl;
}

pub fn build(b: *Builder) !void {
    _b = b;
    _target = b.standardTargetOptions(.{});
    buildModeOption();

    // zig build openssl
    const openssl = try buildOpenSSL();

    // exe: chinadns-ng
    const exe = b.addExecutable("chinadns-ng", null);
    exe.setTarget(_target);
    exe.setBuildMode(_build_mode);

    exe.step.dependOn(openssl);

    exe.unwind_tables = false;
    exe.link_function_sections = true;
    exe.link_gc_sections = true;
    exe.pie = false;
    // exe.force_pic = false;
    exe.want_lto = true;
    // exe.single_threaded = true;
    exe.use_stage1 = true; // async/await
    if (_build_mode != .Debug) exe.strip = true;
    // exe.bundle_compiler_rt = false;

    exe.addIncludePath("dep/mimalloc/include");
    exe.addIncludePath("dep/openssl/include");

    // to ensure that the standard malloc interface resolves to the mimalloc library, link it as the first object file
    addMiMallocCFile(exe);

    try addAppCFiles(exe, &.{ "main.c", "opt.c", "net.c", "dns.c", "dnl.c", "ipset.c", "nl.c" });

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

    // zig build clean-local-cache
    const clean_local_cache = b.step("clean-local-cache", b.fmt("rm local build cache: '{s}'", .{b.cache_root}));
    clean_local_cache.dependOn(&rm_local_cache.step);

    // zig build clean-global-cache
    const clean_global_cache = b.step("clean-global-cache", b.fmt("rm global build cache: '{s}'", .{b.global_cache_root}));
    clean_global_cache.dependOn(&rm_global_cache.step);

    // zig build clean-openssl-build
    const clean_openssl_build = b.step("clean-openssl-build", b.fmt("rm openssl build result: 'dep/openssl'", .{}));
    clean_openssl_build.dependOn(&rm_dep_openssl.step);

    // zig build clean
    const clean = b.step("clean", b.fmt("rm all build cache/result: local, global, openssl", .{}));
    clean.dependOn(clean_local_cache);
    clean.dependOn(clean_global_cache);
    clean.dependOn(clean_openssl_build);
}
