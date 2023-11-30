const std = @import("std");
const Builder = std.build.Builder;
const CrossTarget = std.zig.CrossTarget;
const BuildMode = std.builtin.Mode;
const Step = std.build.Step;
const LibExeObjStep = std.build.LibExeObjStep;

var _b: *Builder = undefined;
var _target: CrossTarget = undefined;
var _build_mode: BuildMode = undefined;

/////////////////////////////////////// helper BEGIN ///////////////////////////////////////

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

fn errExit(comptime format: []const u8, args: anytype) noreturn {
    err(format, args);
    printToStdErr("", .{});
    std.os.exit(1);
}

fn errInvalid(comptime format: []const u8, args: anytype) void {
    err(format, args);
    _b.invalid_user_input = true;
}

fn stepLog(comptime format: []const u8, args: anytype) *Step {
    return &_b.addLog(format, args).step;
}

fn getOptStr(name: []const u8) ?[]const u8 {
    return if (_b.user_input_options.getPtr(name)) |opt| opt.value.scalar else null;
}

fn getTargetOptStr() []const u8 {
    return getOptStr("target") orelse "native";
}

/// if mode is not given, then return ""
fn getCpuOptStr() []const u8 {
    return getOptStr("cpu") orelse ""; // no default value
}

/// used for command line arguments such as `zig cc` (for building dependencies)
fn getTargetCpuArg() []const u8 {
    const target = getTargetOptStr();
    const cpu = getCpuOptStr();

    return if (cpu.len > 0)
        _b.fmt("-target {s} -mcpu={s}", .{ target, cpu })
    else
        _b.fmt("-target {s}", .{target});
}

fn addSuffix(name: []const u8, in_mode: ?BuildMode) []const u8 {
    const target = getTargetOptStr();
    const cpu = if (getCpuOptStr().len <= 0) "default" else getCpuOptStr();
    const mode = in_mode orelse _build_mode;

    return if (mode != .ReleaseFast)
        _b.fmt("{s}:{s}:{s}:{s}", .{ name, target, cpu, descBuildMode(mode) })
    else
        _b.fmt("{s}:{s}:{s}", .{ name, target, cpu });
}

fn trimBlank(str: []const u8) []const u8 {
    return std.mem.trim(u8, str, " \t\r\n");
}

const ModeOption = enum { fast, small, safe, debug };

fn toBuildMode(opt: ModeOption) BuildMode {
    return switch (opt) {
        .fast => .ReleaseFast,
        .small => .ReleaseSmall,
        .safe => .ReleaseSafe,
        .debug => .Debug,
    };
}

fn toModeOption(mode: BuildMode) ModeOption {
    return switch (mode) {
        .ReleaseFast => .fast,
        .ReleaseSmall => .small,
        .ReleaseSafe => .safe,
        .Debug => .debug,
    };
}

fn descBuildMode(mode: BuildMode) []const u8 {
    return @tagName(toModeOption(mode));
}

/////////////////////////////////////// helper END ///////////////////////////////////////

fn optionBuildMode() BuildMode {
    const opt = _b.option(ModeOption, "mode", "build mode, default: 'fast' (-O3/-OReleaseFast -flto)") orelse .fast;
    return toBuildMode(opt);
}

/// return "" if the openssl_target is `native`
fn getOpenSSLTarget() []const u8 {
    const zig_target = getTargetOptStr();

    if (zig_target.len <= 0)
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

    errExit("TODO: for targets other than x86, x86_64, aarch64, use wolfssl instead of openssl", .{});
}

fn stepOpenSSL(p_openssl_dir: *[]const u8) *Step {
    const openssl_dir = addSuffix("dep/openssl", .ReleaseFast);
    p_openssl_dir.* = openssl_dir;

    const openssl = _b.step("openssl", "build openssl dependency");

    const zig_target_mcpu = getTargetCpuArg();
    openssl.dependOn(stepLog("[openssl] zig target: {s}", .{zig_target_mcpu}));

    var openssl_target = getOpenSSLTarget();
    openssl.dependOn(stepLog("[openssl] openssl target: {s}", .{openssl_target}));

    const argv_fmt = [_][]const u8{
        "sh",
        "-c",
        \\  set -o nounset
        \\  set -o errexit
        \\  set -o pipefail
        \\  installdir=$(pwd)/{s}
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
        _b.fmt(argv_fmt[2], .{ openssl_dir, zig_target_mcpu, openssl_target }),
    };

    openssl.dependOn(&_b.addSystemCommand(&argv).step);

    return openssl;
}

fn addCFileMalloc(exe: *LibExeObjStep) void {
    const use_mimalloc = _b.option(bool, "mimalloc", "using the mimalloc allocator (libc), default: false") orelse false;

    if (!use_mimalloc)
        return;

    exe.step.dependOn(stepLog("[mimalloc] using the mimalloc allocator instead of the default libc allocator", .{}));

    exe.addIncludePath("dep/mimalloc/include");

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

fn optionName() []const u8 {
    const exe_name_default = addSuffix("chinadns-ng", _build_mode);
    const exe_name_desc = _b.fmt("executable name, default: '{s}'", .{exe_name_default});
    const exe_name_orig = _b.option([]const u8, "name", exe_name_desc) orelse exe_name_default;
    const exe_name = trimBlank(exe_name_orig);
    if (exe_name.len <= 0 or !std.mem.eql(u8, exe_name, exe_name_orig))
        errExit("invalid executable name (-Dname): '{s}'", .{exe_name_orig});
    return exe_name;
}

fn _build(b: *Builder) void {
    _b = b;
    _target = b.standardTargetOptions(.{});
    _build_mode = optionBuildMode();

    b.verbose = true;
    b.verbose_cimport = true;
    b.verbose_llvm_cpu_features = true;
    b.prominent_compile_errors = true;

    // zig build openssl
    var openssl_dir: []const u8 = undefined;
    const openssl = stepOpenSSL(&openssl_dir);

    // exe: chinadns-ng
    const exe_name = optionName();
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

    exe.addIncludePath(b.fmt("{s}/include", .{openssl_dir}));
    exe.addLibraryPath(b.fmt("{s}/lib", .{openssl_dir}));

    // to ensure that the standard malloc interface resolves to the mimalloc library, link it as the first object file
    addCFileMalloc(exe);

    addCFileApp(exe, &.{ "main.c", "opt.c", "net.c", "dns.c", "dnl.c", "ipset.c", "nl.c" });

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
    const rm_openssl = b.addRemoveDirTree(openssl_dir); // current target
    const rm_openssl_all = b.addSystemCommand(&.{ "sh", "-c", "rm -fr dep/openssl:*" }); // all targets

    // zig build clean-local
    const clean_local = b.step("clean-local", b.fmt("clean local build cache: '{s}'", .{b.cache_root}));
    clean_local.dependOn(&rm_local_cache.step);

    // zig build clean-global
    const clean_global = b.step("clean-global", b.fmt("clean global build cache: '{s}'", .{b.global_cache_root}));
    clean_global.dependOn(&rm_global_cache.step);

    // zig build clean-openssl
    const clean_openssl = b.step("clean-openssl", b.fmt("clean openssl dependency: '{s}'", .{openssl_dir}));
    clean_openssl.dependOn(&rm_openssl.step);

    // zig build clean-openssl-all
    const clean_openssl_all = b.step("clean-openssl-all", b.fmt("clean openssl dependency: '{s}'", .{"dep/openssl:*"}));
    clean_openssl_all.dependOn(&rm_openssl_all.step);

    // zig build clean
    const clean = b.step("clean", b.fmt("clean all build caches and all dependencies", .{}));
    clean.dependOn(clean_local);
    clean.dependOn(clean_global);
    clean.dependOn(clean_openssl);

    // zig build clean-all
    const clean_all = b.step("clean-all", b.fmt("clean all build caches and all dependencies (*)", .{}));
    clean_all.dependOn(clean_local);
    clean_all.dependOn(clean_global);
    clean_all.dependOn(clean_openssl_all);
}

pub fn build(b: *Builder) void {
    _build(b);

    if (b.invalid_user_input)
        printToStdErr("", .{});
}
