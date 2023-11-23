const std = @import("std");
const Builder = std.build.Builder;
const CrossTarget = std.zig.CrossTarget;
const Mode = std.builtin.Mode;
const Step = std.build.Step;
const LibExeObjStep = std.build.LibExeObjStep;

var _b: *Builder = undefined;
var _target: CrossTarget = undefined;
var _build_mode: Mode = undefined;

const _jemalloc_argv = [_][]const u8{
    "sh", "-c",
    \\  set -o nounset
    \\  set -o errexit
    \\  set -o pipefail
    \\  prefix=$(pwd)/zig-out
    \\  [ -f $prefix/lib/libjemalloc.a ] && exit
    \\  set -x
    \\  mkdir -p dep
    \\  cd dep
    \\  version=5.3.0
    \\  tarball=jemalloc-$version.tar.bz2
    \\  dirname=jemalloc-$version
    \\  [ -f $tarball ] || wget https://github.com/jemalloc/jemalloc/releases/download/$version/$tarball
    \\  rm -fr $dirname
    \\  tar -xvf $tarball -C .
    \\  cd $dirname
    \\  export CC="zig cc -Xclang -O3"
    \\  export CFLAGS="-g0 -O3 -flto -fno-pie -fno-PIE -ffunction-sections -fdata-sections"
    \\  export AR='zig ar'
    \\  export RANLIB='zig ranlib'
    \\  ./autogen.sh --prefix=$prefix --disable-cxx --disable-stats --disable-libdl --enable-static --disable-shared
    \\	make -j$(nproc) build_lib
    \\	make install_include install_lib
};

const _openssl_argv = [_][]const u8{
    "sh", "-c",
    \\  set -o nounset
    \\  set -o errexit
    \\  set -o pipefail
    \\  prefix=$(pwd)/zig-out
    \\  [ -f $prefix/lib/libssl.a ] && exit
    \\  set -x
    \\  mkdir -p dep
    \\  cd dep
    \\  version=3.1.4
    \\  tarball=openssl-$version.tar.gz
    \\  dirname=openssl-$version
    \\  [ -f $tarball ] || wget https://www.openssl.org/source/$tarball
    \\  rm -fr $dirname
    \\  tar -xvf $tarball -C .
    \\  cd $dirname
    \\  export CC="zig cc -Xclang -O3"
    \\  export CFLAGS="-g0 -O3 -flto -fno-pie -fno-PIE -ffunction-sections -fdata-sections"
    \\  export AR='zig ar'
    \\  export RANLIB='zig ranlib'
    \\	./Configure --prefix=$prefix --libdir=lib \
    \\      enable-ktls no-deprecated no-async no-comp no-dgram no-legacy no-pic \
    \\      no-psk no-dso no-shared no-srp no-srtp no-ssl-trace no-tests
    \\  make -j$(nproc) build_sw
    \\  make install_sw
};

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
fn addCFiles(exe: *LibExeObjStep, comptime files: []const []const u8) !void {
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

pub fn build(b: *Builder) !void {
    _b = b;
    _target = b.standardTargetOptions(.{});
    buildModeOption();

    // zig build jemalloc
    const jemalloc = b.step("jemalloc", "build `jemalloc` deplib lib");
    jemalloc.dependOn(&b.addSystemCommand(&_jemalloc_argv).step);

    // zig build openssl
    const openssl = b.step("openssl", "build `openssl` deplib lib");
    openssl.dependOn(&b.addSystemCommand(&_openssl_argv).step);

    // exe: chinadns-ng
    const exe = b.addExecutable("chinadns-ng", null);
    exe.setTarget(_target);
    exe.setBuildMode(_build_mode);

    exe.step.dependOn(jemalloc);
    exe.step.dependOn(openssl);

    exe.link_gc_sections = true;
    exe.pie = false;
    // exe.force_pic = false;
    exe.want_lto = true;
    // exe.single_threaded = true;
    exe.use_stage1 = true; // async/await
    if (_build_mode != .Debug) exe.strip = true;
    // exe.bundle_compiler_rt = false;

    exe.addIncludePath(b.getInstallPath(.header, "jemalloc"));
    exe.addIncludePath(b.getInstallPath(.header, "openssl"));

    try addCFiles(exe, &.{ "main.c", "opt.c", "net.c", "dns.c", "dnl.c", "ipset.c", "nl.c" });

    exe.addObjectFile(b.getInstallPath(.lib, "libjemalloc.a"));

    exe.addLibraryPath(b.getInstallPath(.lib, ""));

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

    // zig build clean
    const clean = b.step("clean", b.fmt("rm local cache dir: '{s}'", .{b.cache_root}));
    clean.dependOn(&rm_local_cache.step);

    // zig build distclean
    const distclean = b.step("distclean", b.fmt("rm all cache dir: '{s}', '{s}'", .{ b.cache_root, b.global_cache_root }));
    distclean.dependOn(&rm_local_cache.step);
    distclean.dependOn(&rm_global_cache.step);
}
