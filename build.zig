const std = @import("std");
const Builder = std.build.Builder;
const CrossTarget = std.zig.CrossTarget;
const BuildMode = std.builtin.Mode;
const Step = std.build.Step;
const LibExeObjStep = std.build.LibExeObjStep;
const OptionsStep = std.build.OptionsStep;

var _b: *Builder = undefined;

// options
var _target: CrossTarget = undefined;
var _build_mode: BuildMode = undefined;
var _chinadns_name: []const u8 = undefined;
var _enable_openssl: bool = undefined;
var _enable_mimalloc: bool = undefined;

var _build_config: *OptionsStep = undefined;

const DependLib = struct {
    url: []const u8,
    version: []const u8,
    tarball: []const u8, // src tarball file path
    src_dir: []const u8,
    src_dir_always_clean: bool,
    base_dir: []const u8,
    include_dir: []const u8,
    lib_dir: []const u8,
};

var _dep_openssl: DependLib = b: {
    const version = "3.2.0";
    const src_dir = "dep/openssl-" ++ version;
    break :b .{
        .url = "https://www.openssl.org/source/openssl-" ++ version ++ ".tar.gz",
        .version = version,
        .tarball = src_dir ++ ".tar.gz",
        .src_dir = src_dir,
        .src_dir_always_clean = false,
        .base_dir = undefined, // set by init()
        .include_dir = undefined, // set by init()
        .lib_dir = undefined, // set by init()
    };
};

const _dep_mimalloc: DependLib = b: {
    const version = "2.1.2";
    const src_dir = "dep/mimalloc-" ++ version;
    break :b .{
        .url = "https://github.com/microsoft/mimalloc/archive/refs/tags/v" ++ version ++ ".tar.gz",
        .version = version,
        .tarball = src_dir ++ ".tar.gz",
        .src_dir = src_dir,
        .src_dir_always_clean = true,
        .base_dir = src_dir, // same as src_dir, since mimalloc is linked to the exe as an object
        .include_dir = src_dir ++ "/include",
        .lib_dir = src_dir, // there is actually no lib_dir
    };
};

fn init(b: *Builder) void {
    _b = b;

    if (_b.verbose) {
        _b.verbose_cimport = true;
        _b.verbose_llvm_cpu_features = true;
        _b.prominent_compile_errors = true;
    }

    // keep everything in a local directory
    _b.global_cache_root = _b.cache_root;

    // -Dxxx options
    option_target();
    option_mode();
    option_name();
    option_openssl();
    option_mimalloc();

    _dep_openssl.base_dir = with_suffix(_dep_openssl.src_dir, .ReleaseFast); // dependency lib always ReleaseFast
    _dep_openssl.include_dir = fmt("{s}/include", .{_dep_openssl.base_dir});
    _dep_openssl.lib_dir = fmt("{s}/lib", .{_dep_openssl.base_dir});

    // conditional compilation for zig source files
    _build_config = _b.addOptions();
    _build_config.addOption(bool, "enable_openssl", _enable_openssl);
    _build_config.addOption(bool, "enable_mimalloc", _enable_mimalloc);
    _build_config.addOption([]const u8, "openssl_version", _dep_openssl.version);
    _build_config.addOption([]const u8, "mimalloc_version", _dep_mimalloc.version);
    _build_config.addOption([]const u8, "cc_target", optval_target());
    _build_config.addOption([]const u8, "cc_cpu", optval_cpu_or_default());
    _build_config.addOption([]const u8, "cc_mode", desc_build_mode(null));
}

fn init_dep(step: *Step, dep: DependLib) void {
    if (dep.src_dir_always_clean and path_exists(dep.src_dir))
        return;

    if (!path_exists(dep.tarball))
        step.dependOn(add_download(dep.url, dep.tarball));

    step.dependOn(add_rm(dep.src_dir));

    step.dependOn(add_tar_extract(dep.tarball, "dep"));
}

fn option_target() void {
    _target = _b.standardTargetOptions(.{});
}

fn option_mode() void {
    const opt = _b.option(ModeOpt, "mode", "build mode, default: 'fast' (-O3/-OReleaseFast -flto)") orelse .fast;
    _build_mode = to_build_mode(opt);
}

fn option_name() void {
    const default = with_suffix("chinadns-ng", null);
    const desc = fmt("executable name, default: '{s}'", .{default});
    const name = _b.option([]const u8, "name", desc) orelse default;
    const trimmed = trim_whitespace(name);
    if (trimmed.len > 0 and std.mem.eql(u8, trimmed, name)) {
        _chinadns_name = name;
    } else {
        err_invalid("invalid executable name (-Dname): '{s}'", .{name});
        _chinadns_name = default;
    }
}

fn option_openssl() void {
    _enable_openssl = _b.option(bool, "openssl", "enable openssl to support DoH protocol, default: true") orelse true;
}

fn option_mimalloc() void {
    _enable_mimalloc = _b.option(bool, "mimalloc", "using the mimalloc allocator (libc), default: false") orelse false;
}

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
    _ = std.io.getStdErr().write(fmt(format ++ "\n", args)) catch unreachable;
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

/// print err msg and mark user input as invalid
fn err_invalid(comptime format: []const u8, args: anytype) void {
    _print_err(format, args);
    _b.invalid_user_input = true;
}

// =========================================================================

/// step: empty step to be used as a container
fn add_step(name: []const u8) *Step {
    const step = _b.allocator.create(Step) catch unreachable;
    step.* = Step.initNoOp(.custom, name, _b.allocator);
    return step;
}

/// step: log info
fn add_log(comptime format: []const u8, args: anytype) *Step {
    return &_b.addLog(format, args).step;
}

/// step: /bin/sh command
fn add_sh_cmd(sh_cmd: []const u8) *Step {
    const cmd = fmt("set -o nounset; set -o errexit; set -o pipefail; {s}", .{sh_cmd});
    const run_step = _b.addSystemCommand(&.{ "sh", "-c", cmd });
    run_step.print = false; // disable print (use `set -x` instead)
    return &run_step.step;
}

/// step: /bin/sh command (set -x)
fn add_sh_cmd_x(sh_cmd: []const u8) *Step {
    return add_sh_cmd(fmt("set -x; {s}", .{sh_cmd}));
}

/// step: remove dir or file
fn add_rm(path: []const u8) *Step {
    return &_b.addRemoveDirTree(path).step;
}

/// step: download file
fn add_download(url: []const u8, path: []const u8) *Step {
    const cmd_ =
        \\  url='{s}'; path='{s}'
        \\  mkdir -p "$(dirname "$path")"
        \\  echo "[INFO] downloading from $url"
        \\  if type -P wget &>/dev/null; then
        \\      wget "$url" -O "$path"
        \\  elif type -P curl &>/dev/null; then
        \\      curl -fL "$url" -o "$path"
        \\  else
        \\      echo "[ERROR] please install 'wget' or 'curl'" 1>&2
        \\      exit 1
        \\  fi
    ;
    const cmd = fmt(cmd_, .{ url, path });
    return add_sh_cmd(cmd);
}

/// step: tar -xf $tarball -C $dir
fn add_tar_extract(tarball_path: []const u8, to_dir: []const u8) *Step {
    const cmd = fmt("mkdir -p '{s}'; tar -xf '{s}' -C '{s}'", .{ to_dir, tarball_path, to_dir });
    return add_sh_cmd_x(cmd);
}

// =========================================================================

fn fmt(comptime format: []const u8, args: anytype) []const u8 {
    return _b.fmt(format, args);
}

fn path_exists(rel_path: []const u8) bool {
    return if (std.fs.cwd().access(rel_path, .{})) true else |_| false;
}

fn string_concat(str_list: []const []const u8, sep: []const u8) []const u8 {
    return std.mem.join(_b.allocator, sep, str_list) catch unreachable;
}

fn trim_whitespace(str: []const u8) []const u8 {
    return std.mem.trim(u8, str, " \t\r\n");
}

fn is_musl() bool {
    return _target.getAbi().isMusl();
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
fn get_target_mcpu() []const u8 {
    const target = optval_target();
    const cpu = optval_cpu();

    return if (cpu.len > 0)
        fmt("-target {s} -mcpu={s}", .{ target, cpu })
    else
        fmt("-target {s}", .{target});
}

/// @in_mode: default is `_build_mode`
fn with_suffix(name: []const u8, in_mode: ?BuildMode) []const u8 {
    const target = optval_target();
    const cpu = optval_cpu_or_default();
    const mode = in_mode orelse _build_mode;

    return if (mode != .ReleaseFast)
        fmt("{s}:{s}:{s}:{s}", .{ name, target, cpu, desc_build_mode(mode) })
    else
        fmt("{s}:{s}:{s}", .{ name, target, cpu });
}

// =========================================================================

fn get_openssl_target() []const u8 {
    return switch (_target.getCpuArch()) {
        .arm => "linux-armv4",
        .aarch64 => "linux-aarch64",
        .i386 => "linux-x86-clang",
        .x86_64 => "linux-x86_64-clang",
        .mips, .mipsel => b: {
            // [zig] https://github.com/ziglang/zig/issues/11829
            // [zig] https://github.com/ziglang/zig/commit/e1cc70ba11735b678430ffde348527a16287a744
            // [zig] I ported it to version 0.10.1 via a hack: https://www.zfl9.com/zig-mips.html
            // [openssl] Configure script adds minimally required -march for assembly support, if no -march/-mips* was specified at command line.
            const target = "linux-mips32";
            const march = _target.getCpuModel().llvm_name.?;
            break :b fmt("{s} -{s}", .{ target, march });
        },
        // .mips64, .mips64el => b: {
        //     // [zig] https://github.com/ziglang/zig/issues/8020
        //     // [openssl] Configure script adds minimally required -march for assembly support, if no -march/-mips* was specified at command line.
        //     const target = "linux64-mips64";
        //     const march = _target.getCpuModel().llvm_name.?;
        //     break :b fmt("{s} -{s}", .{ target, march });
        // },
        else => b: {
            err_invalid(
                "'{s}' is not supported, currently supports ['arm', 'aarch64', 'i386', 'x86_64', 'mips', 'mipsel']",
                .{@tagName(_target.getCpuArch())},
            );
            break :b "";
        },
    };
}

/// openssl dependency lib
fn build_openssl() *Step {
    const openssl = add_step("openssl");

    // already installed ?
    if (path_exists(_dep_openssl.base_dir))
        return openssl;

    init_dep(openssl, _dep_openssl);

    const target_mcpu = get_target_mcpu();

    const openssl_target = get_openssl_target();
    openssl.dependOn(add_log("[openssl] ./Configure {s}", .{openssl_target}));

    const cmd_ =
        \\  install_dir='{s}'
        \\  src_dir='{s}'
        \\  target_mcpu='{s}'
        \\  openssl_target='{s}'
        \\  zig_cache_dir='{s}'
        \\  is_musl={}
        \\
        \\  cd "$src_dir"
        \\
        \\  export ZIG_LOCAL_CACHE_DIR="$zig_cache_dir"
        \\  export ZIG_GLOBAL_CACHE_DIR="$zig_cache_dir"
        \\
        \\  ((is_musl)) && pic_flags='-fno-pic -fno-PIC' || pic_flags=''
        \\  export CC="zig cc $target_mcpu -g0 -O3 -Xclang -O3 -flto -fno-pie -fno-PIE $pic_flags -ffunction-sections -fdata-sections"
        \\
        \\  export AR='zig ar'
        \\  export RANLIB='zig ranlib'
        \\
        \\  ./Configure $openssl_target --prefix="$install_dir" --libdir=lib --openssldir=/etc/ssl \
        \\      enable-ktls no-deprecated no-async no-comp no-dgram no-legacy no-pic no-psk \
        \\      no-dso no-dynamic-engine no-shared no-srp no-srtp no-ssl-trace no-tests no-apps no-threads
        \\
        \\  make -j$(nproc) build_sw
        \\  make install_sw
    ;

    const cmd = fmt(cmd_, .{
        _b.pathFromRoot(_dep_openssl.base_dir),
        _dep_openssl.src_dir,
        target_mcpu,
        openssl_target,
        _b.pathFromRoot(_b.cache_root),
        @as(i32, if (is_musl()) 1 else 0),
    });

    openssl.dependOn(add_sh_cmd_x(cmd));

    return openssl;
}

fn setup_libexeobj_step(step: *LibExeObjStep) void {
    step.setTarget(_target);
    step.setBuildMode(_build_mode);

    if (step.kind == .obj) // compiling
        step.use_stage1 = true; // required by async/await (.zig)

    step.want_lto = true;
    step.single_threaded = true;

    step.link_function_sections = true;
    // step.link_data_sections = true; // not supported yet
    step.link_gc_sections = true;

    step.pie = false;

    if (is_musl())
        step.force_pic = false;

    if (_build_mode == .ReleaseFast or _build_mode == .ReleaseSmall)
        step.strip = true;

    // conditional compilation for zig source files
    step.addOptions("build_config", _build_config);

    step.linkLibC();
}

/// zig build-obj -cflags <CFLAGS...>
fn get_cflags(ex_cflags: []const []const u8) []const []const u8 {
    var cflags = std.ArrayList([]const u8).init(_b.allocator);
    defer cflags.deinit();

    cflags.appendSlice(&.{
        "-Werror", // https://github.com/ziglang/zig/issues/10800
        "-fno-pic",
        "-fno-PIC",
        "-fno-pie",
        "-fno-PIE",
        "-ffunction-sections",
        "-fdata-sections",
        "-fcolor-diagnostics",
        "-fcaret-diagnostics",
    }) catch unreachable;

    if (_build_mode == .ReleaseFast)
        cflags.append("-O3") catch unreachable; // default is -O2

    // append ex cflags
    cflags.appendSlice(ex_cflags) catch unreachable;

    return cflags.toOwnedSlice();
}

fn link_obj_mimalloc(exe: *LibExeObjStep) void {
    const obj = _b.addObject("mimalloc.c", null);
    setup_libexeobj_step(obj);

    init_dep(&exe.step, _dep_mimalloc);

    obj.addIncludePath(_dep_mimalloc.include_dir);

    obj.defineCMacro("NDEBUG", null);
    obj.defineCMacro("MI_MALLOC_OVERRIDE", null);

    const src_file = fmt("{s}/src/static.c", .{_dep_mimalloc.src_dir});

    const cflags = get_cflags(&.{
        "-std=gnu11",
        "-Wall",
        "-Wextra",
        "-Wpedantic",
        "-Wstrict-prototypes",
        "-Wno-unknown-pragmas",
        "-Wno-static-in-inline",
        "-fvisibility=hidden",
        "-fno-builtin-malloc",
        "-ftls-model=initial-exec",
    });

    obj.addCSourceFile(src_file, cflags);

    // link to exe
    exe.addObject(obj);
}

fn link_obj_chinadns(exe: *LibExeObjStep) void {
    // generic cflags
    const cflags = get_cflags(&.{
        "-std=c99",
        "-Wall",
        "-Wextra",
        "-Wvla",
    });

    // dependency lib
    const macro_enable_openssl = fmt("ENABLE_OPENSSL=\"{s}\"", .{_dep_openssl.version});
    const macro_enable_mimalloc = fmt("ENABLE_MIMALLOC=\"{s}\"", .{_dep_mimalloc.version});

    // target, cpu, mode
    const macro_cc_target = fmt("CC_TARGET=\"{s}\"", .{optval_target()});
    const macro_cc_cpu = fmt("CC_CPU=\"{s}\"", .{optval_cpu_or_default()});
    const macro_cc_mode = fmt("CC_MODE=\"{s}\"", .{desc_build_mode(null)});

    var dir = std.fs.cwd().openIterableDir("src", .{}) catch unreachable;
    defer dir.close();

    var it = dir.iterate();

    while (it.next() catch unreachable) |file| {
        if (file.kind != .File)
            continue;

        if (!std.mem.endsWith(u8, file.name, ".c") and !std.mem.endsWith(u8, file.name, ".zig"))
            continue;

        const obj = _b.addObject(file.name, null);
        setup_libexeobj_step(obj);

        // for .zig file
        obj.addIncludePath("src");

        // openssl lib
        if (_enable_openssl) {
            obj.defineCMacroRaw(macro_enable_openssl);
            obj.addIncludePath(_dep_openssl.include_dir);
        }

        // mimalloc lib
        if (_enable_mimalloc)
            obj.defineCMacroRaw(macro_enable_mimalloc);

        // target, cpu, mode
        obj.defineCMacroRaw(macro_cc_target);
        obj.defineCMacroRaw(macro_cc_cpu);
        obj.defineCMacroRaw(macro_cc_mode);

        // for log.h
        obj.defineCMacroRaw(fmt("LOG_FILENAME=\"{s}\"", .{file.name}));

        obj.addCSourceFile(fmt("src/{s}", .{file.name}), cflags);

        // link to exe
        exe.addObject(obj);
    }
}

fn configure() void {
    // exe: chinadns-ng
    const exe = _b.addExecutable(_chinadns_name, null);
    setup_libexeobj_step(exe);

    // build the dependency library first
    if (_enable_openssl)
        exe.step.dependOn(build_openssl());

    // to ensure that the standard malloc interface resolves to the mimalloc library, link it as the first object file
    if (_enable_mimalloc)
        link_obj_mimalloc(exe);

    link_obj_chinadns(exe);

    // link openssl library
    if (_enable_openssl) {
        exe.addLibraryPath(_dep_openssl.lib_dir);
        exe.linkSystemLibrary("ssl");
        exe.linkSystemLibrary("crypto");
    }

    // install to dest dir
    exe.install();

    const run_exe = exe.run();
    if (_b.args) |args|
        run_exe.addArgs(args);

    // zig build run [-- ARGS...]
    const run = _b.step("run", "run chinadns-ng: [-- ARGS...]");
    run.dependOn(_b.getInstallStep());
    run.dependOn(&run_exe.step);

    const rm_cache = add_rm(_b.cache_root);
    const rm_openssl = add_rm(_dep_openssl.base_dir); // current target
    const rm_openssl_all = add_sh_cmd(fmt("rm -fr {s}:*", .{_dep_openssl.src_dir})); // all targets

    // zig build clean-cache
    const clean_cache = _b.step("clean-cache", fmt("clean zig build cache: '{s}'", .{_b.cache_root}));
    clean_cache.dependOn(rm_cache);

    // zig build clean-openssl
    const clean_openssl = _b.step("clean-openssl", fmt("clean openssl build cache: '{s}'", .{_dep_openssl.base_dir}));
    clean_openssl.dependOn(rm_openssl);

    // zig build clean-openssl-all
    const clean_openssl_all = _b.step("clean-openssl-all", fmt("clean openssl build caches: '{s}:*'", .{_dep_openssl.src_dir}));
    clean_openssl_all.dependOn(rm_openssl_all);

    // zig build clean
    const clean = _b.step("clean", fmt("clean all build caches", .{}));
    clean.dependOn(clean_cache);
    clean.dependOn(clean_openssl);

    // zig build clean-all
    const clean_all = _b.step("clean-all", fmt("clean all build caches (*)", .{}));
    clean_all.dependOn(clean_cache);
    clean_all.dependOn(clean_openssl_all);
}

/// build.zig just generates the build steps (and the dependency graph), the real running is done by build_runner.zig
pub fn build(b: *Builder) void {
    init(b);

    configure();

    if (_b.invalid_user_input)
        newline();
}
