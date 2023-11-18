const std = @import("std");
const builtin = std.builtin;
const Mode = builtin.Mode;
const Builder = std.build.Builder;
const LibExeObjStep = std.build.LibExeObjStep;

fn buildModeOption(b: *Builder) Mode {
    const M = enum { fast, small, safe, debug };
    return switch (b.option(M, "build", "Build mode, default is `fast` (release-fast)") orelse .fast) {
        .fast => .ReleaseFast,
        .small => .ReleaseSmall,
        .safe => .ReleaseSafe,
        .debug => .Debug,
    };
}

fn addCFiles(exe: *LibExeObjStep, build_mode: Mode, comptime files: []const []const u8) !void {
    var flags = std.ArrayList([]const u8).init(exe.builder.allocator);
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
    });

    switch (build_mode) {
        .ReleaseFast, .ReleaseSafe => try flags.appendSlice(&.{ "-O3", "-flto" }),
        .ReleaseSmall => try flags.appendSlice(&.{ "-Os", "-flto" }),
        .Debug => try flags.appendSlice(&.{ "-Og", "-ggdb3" }),
    }

    inline for (files) |file| {
        try flags.append("-DFILENAME=" ++ file);
        exe.addCSourceFile("src/" ++ file, flags.items);
        _ = flags.pop();
    }
}

pub fn build(b: *std.build.Builder) !void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    // const mode = b.standardReleaseOptions();
    const mode = buildModeOption(b);

    const exe = b.addExecutable("chinadns-ng", null);
    try addCFiles(exe, mode, &.{ "main.c", "opt.c", "net.c", "dns.c", "dnl.c", "ipset.c", "nl.c" });
    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.linkLibC();
    exe.install();
    exe.pie = false;
    // exe.force_pic = false;
    exe.want_lto = true;
    exe.single_threaded = true;
    exe.use_stage1 = true; // async/await
    if (mode != .Debug) exe.strip = true;

    // exe.verbose_cc = true;
    // exe.verbose_link = true;

    const clean_cmd = b.addSystemCommand(&.{ "rm", "-fr", b.cache_root });
    const clean_step = b.step("clean", "rm local zig cache files");
    clean_step.dependOn(&clean_cmd.step);

    const distclean_cmd = b.addSystemCommand(&.{ "rm", "-fr", b.global_cache_root });
    const distclean_step = b.step("distclean", "rm all zig cache files");
    distclean_step.dependOn(clean_step);
    distclean_step.dependOn(&distclean_cmd.step);
}
