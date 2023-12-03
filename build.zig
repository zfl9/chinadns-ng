const std = @import("std");
const Builder = std.build.Builder;
const CrossTarget = std.zig.CrossTarget;
const BuildMode = std.builtin.Mode;
const Step = std.build.Step;
const LibExeObjStep = std.build.LibExeObjStep;

var _b: *Builder = undefined;
var _target: CrossTarget = undefined;
var _build_mode: BuildMode = undefined;

// =========================================================================

const DependLib = struct {
    version: []const u8,
    tarball: []const u8, // src tarball file path
    srcdir: []const u8,
    srcdir_always_clean: bool,
    url: []const u8,
};

const _dep_openssl: DependLib = b: {
    const version = "3.2.0";
    break :b .{
        .version = version,
        .tarball = "dep/openssl-" ++ version ++ ".tar.gz",
        .srcdir = "dep/openssl-" ++ version,
        .srcdir_always_clean = false,
        .url = "https://www.openssl.org/source/openssl-" ++ version ++ ".tar.gz",
    };
};

const _dep_mimalloc: DependLib = b: {
    const version = "2.1.2";
    break :b .{
        .version = version,
        .tarball = "dep/mimalloc-" ++ version ++ ".tar.gz",
        .srcdir = "dep/mimalloc-" ++ version,
        .srcdir_always_clean = true,
        .url = "https://github.com/microsoft/mimalloc/archive/refs/tags/v" ++ version ++ ".tar.gz",
    };
};

var _use_mimalloc: bool = undefined;

// =========================================================================

const ModeOpt = enum { fast, small, safe, debug };

fn to_build_mode(opt: ModeOpt) BuildMode {
    return switch (opt) {
        .fast => .ReleaseFast,
        .small => .ReleaseSmall,
        .safe => .ReleaseSafe,
        .debug => .Debug,
    };
}

fn to_mode_opt(mode: BuildMode) ModeOpt {
    return switch (mode) {
        .ReleaseFast => .fast,
        .ReleaseSmall => .small,
        .ReleaseSafe => .safe,
        .Debug => .debug,
    };
}

/// fast | small | safe | debug
/// @mode: default is `_build_mode`
fn desc_build_mode(mode: ?BuildMode) []const u8 {
    return @tagName(to_mode_opt(mode orelse _build_mode));
}

// =========================================================================

var _first_error: bool = true;

/// print to stderr, auto append '\n'
fn _print(comptime format: []const u8, args: anytype) void {
    _ = std.io.getStdErr().write(_b.fmt(format ++ "\n", args)) catch unreachable;
}

fn newline() void {
    return _print("", .{});
}

fn _print_err(comptime format: []const u8, args: anytype) void {
    if (_first_error) {
        _first_error = false;
        newline();
    }
    _print("> ERROR: " ++ format, args);
}

/// print err msg and exit process with code 1
fn err_exit(comptime format: []const u8, args: anytype) noreturn {
    _print_err(format, args);
    newline();
    std.os.exit(1);
}

/// print err msg and mark user input as invalid
fn err_invalid(comptime format: []const u8, args: anytype) void {
    _print_err(format, args);
    _b.invalid_user_input = true;
}

fn string_concat(str_list: []const []const u8, sep: []const u8) []const u8 {
    return std.mem.join(_b.allocator, sep, str_list) catch unreachable;
}

// =========================================================================

/// step: log info
fn add_log(comptime format: []const u8, args: anytype) *Step {
    return &_b.addLog(format, args).step;
}

/// step: /bin/sh command
fn add_sh_cmd(sh_cmd: []const u8) *Step {
    const cmd = _b.fmt("set -o nounset; set -o errexit; set -o pipefail; {s}", .{sh_cmd});
    const run_step = _b.addSystemCommand(&.{ "sh", "-c", cmd });
    run_step.print = false; // disable print (use `set -x` instead)
    return &run_step.step;
}

/// step: remove dir or file
fn add_rm(path: []const u8) *Step {
    return &_b.addRemoveDirTree(path).step;
}

/// step: download file
fn add_download(url: []const u8, path: []const u8) *Step {
    const cmd_ =
        \\  url={s}; path={s}
        \\  mkdir -p $(dirname $path)
        \\  echo "[INFO] downloading from $url"
        \\  if type -P wget &>/dev/null; then
        \\      wget $url -O $path
        \\  elif type -P curl &>/dev/null; then
        \\      curl -fL $url -o $path
        \\  else
        \\      echo "[ERROR] please install 'wget' or 'curl'" 1>&2
        \\      exit 1
        \\  fi
    ;
    const cmd = _b.fmt(cmd_, .{ url, path });
    return add_sh_cmd(cmd);
}

/// step: tar xf $tarball -C $dir
fn add_tar_extract(tarball_path: []const u8, to_dir: []const u8) *Step {
    const cmd = _b.fmt("set -x; mkdir -p {s}; tar -xf {s} -C {s}", .{ to_dir, tarball_path, to_dir });
    return add_sh_cmd(cmd);
}

// =========================================================================

fn path_exists(rel_path: []const u8) bool {
    return if (std.fs.cwd().access(rel_path, .{})) true else |_| false;
}

fn init_dep(step: *Step, dep: DependLib) void {
    if (dep.srcdir_always_clean and path_exists(dep.srcdir))
        return;

    if (!path_exists(dep.tarball))
        step.dependOn(add_download(dep.url, dep.tarball));

    step.dependOn(add_rm(dep.srcdir));

    step.dependOn(add_tar_extract(dep.tarball, "dep"));
}

// =========================================================================

/// get cli option value (str)
fn optval(name: []const u8) ?[]const u8 {
    const opt = _b.user_input_options.getPtr(name) orelse return null;
    return switch (opt.value) {
        .scalar => |v| v,
        else => null,
    };
}

/// default is `native`
fn optval_target() []const u8 {
    return optval("target") orelse "native";
}

/// return "" if not given
fn optval_cpu() []const u8 {
    return optval("cpu") orelse "";
}

/// return "default" if not given
fn optval_cpu_or_default() []const u8 {
    return optval("cpu") orelse "default";
}

// =========================================================================

/// for building dependencies (zig cc)
fn cc_target_mcpu() []const u8 {
    const target = optval_target();
    const cpu = optval_cpu();

    return if (cpu.len > 0)
        _b.fmt("-target {s} -mcpu={s}", .{ target, cpu })
    else
        _b.fmt("-target {s}", .{target});
}

/// @in_mode: default is `_build_mode`
fn add_suffix(name: []const u8, in_mode: ?BuildMode) []const u8 {
    const target = optval_target();
    const cpu = optval_cpu_or_default();
    const mode = in_mode orelse _build_mode;

    return if (mode != .ReleaseFast)
        _b.fmt("{s}:{s}:{s}:{s}", .{ name, target, cpu, desc_build_mode(mode) })
    else
        _b.fmt("{s}:{s}:{s}", .{ name, target, cpu });
}

fn trim_whitespace(str: []const u8) []const u8 {
    return std.mem.trim(u8, str, " \t\r\n");
}

// =========================================================================

/// option: build mode
fn option_mode() BuildMode {
    const opt = _b.option(ModeOpt, "mode", "build mode, default: 'fast' (-O3/-OReleaseFast -flto)") orelse .fast;
    return to_build_mode(opt);
}

/// option: exe name
fn option_name() []const u8 {
    const name_default = add_suffix("chinadns-ng", null);
    const name_desc = _b.fmt("executable name, default: '{s}'", .{name_default});
    const name_orig = _b.option([]const u8, "name", name_desc) orelse name_default;
    const name = trim_whitespace(name_orig);
    if (name.len <= 0 or !std.mem.eql(u8, name, name_orig))
        err_exit("invalid executable name (-Dname): '{s}'", .{name_orig});
    return name;
}

// =========================================================================

/// return "" if the target is `native`
fn get_openssl_target() []const u8 {
    const zig_target = optval_target();

    // {prefix, openssl_target}
    const prefix_target_map = .{
        .{ "native", "" },
        .{ "i386-", "linux-x86-clang" },
        .{ "x86_64-", "linux-x86_64-clang" },
        .{ "aarch64-", "linux-aarch64" },
    };

    inline for (prefix_target_map) |prefix_target| {
        if (std.mem.startsWith(u8, zig_target, prefix_target[0]))
            return prefix_target[1];
    }

    err_exit("TODO: for targets other than x86, x86_64, aarch64, use wolfssl instead of openssl", .{});
}

/// toplevel step: openssl
fn step_openssl(p_openssl_dir: *[]const u8) *Step {
    const openssl = _b.step("openssl", "build openssl dependency");

    const openssl_dir = add_suffix(_dep_openssl.srcdir, .ReleaseFast);
    p_openssl_dir.* = openssl_dir;

    // already compiled ?
    if (path_exists(openssl_dir))
        return openssl;

    init_dep(openssl, _dep_openssl);

    const zig_target_mcpu = cc_target_mcpu();
    openssl.dependOn(add_log("[openssl] zig cc {s}", .{zig_target_mcpu}));

    const openssl_target = get_openssl_target();
    const openssl_target_display = if (openssl_target.len > 0) openssl_target else "<native>";
    openssl.dependOn(add_log("[openssl] ./Configure {s}", .{openssl_target_display}));

    const cmd_ =
        \\  set -x
        \\
        \\  installdir=$(pwd)/{s}
        \\  srcdir={s}
        \\  zig_target_mcpu="{s}"
        \\  openssl_target={s}
        \\
        \\  cd $srcdir
        \\
        \\  export CC="zig cc $zig_target_mcpu -Xclang -O3"
        \\  export CFLAGS="-g0 -O3 -flto -fno-pie -fno-PIE -ffunction-sections -fdata-sections"
        \\  export AR='zig ar'
        \\  export RANLIB='zig ranlib'
        \\
        \\  ./Configure $openssl_target --prefix=$installdir --libdir=lib --openssldir=/etc/ssl \
        \\      enable-ktls no-deprecated no-async no-comp no-dgram no-legacy no-pic \
        \\      no-psk no-dso no-shared no-srp no-srtp no-ssl-trace no-tests no-apps no-threads
        \\
        \\  make -j$(nproc) build_sw
        \\  make install_sw
    ;

    const cmd = _b.fmt(cmd_, .{ openssl_dir, _dep_openssl.srcdir, zig_target_mcpu, openssl_target });

    openssl.dependOn(add_sh_cmd(cmd));

    return openssl;
}

/// mimalloc .c files
fn add_src_malloc(exe: *LibExeObjStep) void {
    _use_mimalloc = _b.option(bool, "mimalloc", "using the mimalloc allocator (libc), default: false") orelse false;

    if (!_use_mimalloc)
        return;

    exe.step.dependOn(add_log("[mimalloc] using the mimalloc allocator instead of the default libc allocator", .{}));

    init_dep(&exe.step, _dep_mimalloc);

    exe.addIncludePath(_dep_mimalloc.srcdir ++ "/include");

    exe.addCSourceFile(_dep_mimalloc.srcdir ++ "/src/static.c", &.{
        "-std=gnu11",
        "-Werror", // https://github.com/ziglang/zig/issues/10800
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

/// chinadns-ng .c files
fn add_src_app(exe: *LibExeObjStep, comptime files: []const []const u8) void {
    var flags = std.ArrayList([]const u8).init(_b.allocator);
    defer flags.deinit();

    // generic cflags
    flags.appendSlice(&.{
        "-std=c99",
        "-Werror", // https://github.com/ziglang/zig/issues/10800
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

    // build_mode dependent cflags
    switch (_build_mode) {
        .ReleaseFast, .ReleaseSafe => flags.appendSlice(&.{ "-g0", "-O3", "-flto", "-DNDEBUG" }) catch unreachable,
        .ReleaseSmall => flags.appendSlice(&.{ "-g0", "-Os", "-flto", "-DNDEBUG" }) catch unreachable,
        .Debug => flags.appendSlice(&.{ "-ggdb3", "-Og" }) catch unreachable,
    }

    // openssl version
    flags.append("-DWITH_OPENSSL=\"" ++ _dep_openssl.version ++ "\"") catch unreachable;

    // mimalloc version
    if (_use_mimalloc)
        flags.append("-DWITH_MIMALLOC=\"" ++ _dep_mimalloc.version ++ "\"") catch unreachable;

    // target, cpu, mode
    flags.append(_b.fmt("-DCC_TARGET=\"{s}\"", .{optval_target()})) catch unreachable;
    flags.append(_b.fmt("-DCC_CPU=\"{s}\"", .{optval_cpu_or_default()})) catch unreachable;
    flags.append(_b.fmt("-DCC_MODE=\"{s}\"", .{desc_build_mode(null)})) catch unreachable;

    inline for (files) |file| {
        flags.append("-DFILENAME=\"" ++ file ++ "\"") catch unreachable; // log.h
        exe.addCSourceFile("src/" ++ file, flags.items);
        _ = flags.pop();
    }
}

fn _build(b: *Builder) void {
    _b = b;
    _target = b.standardTargetOptions(.{});
    _build_mode = option_mode();

    b.verbose = true;
    b.verbose_cimport = true;
    b.verbose_llvm_cpu_features = true;
    b.prominent_compile_errors = true;

    // zig build openssl
    var openssl_dir: []const u8 = undefined;
    const openssl = step_openssl(&openssl_dir);

    // exe: chinadns-ng
    const exe = b.addExecutable(option_name(), null);
    exe.setTarget(_target);
    exe.setBuildMode(_build_mode);

    exe.use_stage1 = true; // async/await
    exe.want_lto = true;
    exe.single_threaded = true;
    exe.link_function_sections = true;
    exe.link_gc_sections = true;
    exe.pie = false;
    if (_target.getAbi().isMusl()) exe.force_pic = false;
    if (_build_mode != .Debug) exe.strip = true;

    // openssl library
    exe.step.dependOn(openssl);

    exe.addIncludePath(b.fmt("{s}/include", .{openssl_dir}));
    exe.addLibraryPath(b.fmt("{s}/lib", .{openssl_dir}));

    // to ensure that the standard malloc interface resolves to the mimalloc library, link it as the first object file
    add_src_malloc(exe);

    add_src_app(exe, &.{ "main.c", "opt.c", "net.c", "dns.c", "dnl.c", "ipset.c", "nl.c" });

    exe.linkSystemLibrary("ssl");
    exe.linkSystemLibrary("crypto");

    exe.linkLibC();

    exe.install();

    const run_exe = exe.run();
    if (b.args) |args|
        run_exe.addArgs(args);

    // zig build run [-- ARGS...]
    const run = b.step("run", "run chinadns-ng with args");
    run.dependOn(b.getInstallStep());
    run.dependOn(&run_exe.step);

    const rm_local_cache = add_rm(b.cache_root);
    const rm_global_cache = add_rm(b.global_cache_root);
    const rm_openssl = add_rm(openssl_dir); // current target
    const rm_openssl_all = add_sh_cmd("rm -fr " ++ _dep_openssl.srcdir ++ ":*"); // all targets

    // zig build clean-local
    const clean_local = b.step("clean-local", b.fmt("clean local build cache: '{s}'", .{b.cache_root}));
    clean_local.dependOn(rm_local_cache);

    // zig build clean-global
    const clean_global = b.step("clean-global", b.fmt("clean global build cache: '{s}'", .{b.global_cache_root}));
    clean_global.dependOn(rm_global_cache);

    // zig build clean-openssl
    const clean_openssl = b.step("clean-openssl", b.fmt("clean openssl build cache: '{s}'", .{openssl_dir}));
    clean_openssl.dependOn(rm_openssl);

    // zig build clean-openssl-all
    const clean_openssl_all = b.step("clean-openssl-all", b.fmt("clean openssl build caches: '{s}:*'", .{_dep_openssl.srcdir}));
    clean_openssl_all.dependOn(rm_openssl_all);

    // zig build clean
    const clean = b.step("clean", b.fmt("clean all build caches", .{}));
    clean.dependOn(clean_local);
    clean.dependOn(clean_global);
    clean.dependOn(clean_openssl);

    // zig build clean-all
    const clean_all = b.step("clean-all", b.fmt("clean all build caches (*)", .{}));
    clean_all.dependOn(clean_local);
    clean_all.dependOn(clean_global);
    clean_all.dependOn(clean_openssl_all);

    // zig build clean-dep
    const clean_dep = b.step("clean-dep", b.fmt("clean all files in dep dir", .{}));
    clean_dep.dependOn(add_rm("dep"));
}

pub fn build(b: *Builder) void {
    _build(b);

    if (b.invalid_user_input)
        newline();
}
