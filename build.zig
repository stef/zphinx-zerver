const Builder = @import("std").Build;

pub fn build(b: *Builder) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const pie = b.option(bool, "pie", "Build a Position Independent Executable") orelse true;
    const relro = b.option(bool, "relro", "Force all relocations to be read-only after processing") orelse true;

    const exe = b.addExecutable(.{
        .name = "oracle",
        .root_module = b.createModule(.{
            .root_source_file = b.path("oracle.zig"),
            .target = target,
            .optimize = optimize,
        }),
        .linkage = .static,
    });

    // load the "zig-toml" dependency from build.zig.zon
    const toml_package = b.dependency("zig_toml", .{
        .target = target,
        .optimize = optimize,
    });
    const toml_module = toml_package.module("toml");
    exe.root_module.addImport("toml", toml_module);

    const bearssl_package = b.dependency("zig_bearssl", .{
        .target = target,
        .optimize = optimize,
    });
    const bearssl_module = bearssl_package.module("bearssl");
    exe.root_module.addImport("bearssl", bearssl_module);

    const liboprf_package = b.dependency("liboprf", .{
        .target = target,
        .optimize = optimize,
    });
    exe.root_module.linkLibrary(liboprf_package.artifact("liboprf"));
    exe.root_module.addIncludePath(liboprf_package.path("src"));
    exe.root_module.addIncludePath(liboprf_package.path("src/noise_xk/include"));
    exe.root_module.addIncludePath(liboprf_package.path("src/noise_xk/include/karmel"));
    exe.root_module.addIncludePath(liboprf_package.path("src/noise_xk/include/karmel/minimal"));

    const libequihash_package = b.dependency("libequihash", .{
        .target = target,
        .optimize = optimize,
    });
    exe.root_module.linkLibrary(libequihash_package.artifact("libequihash"));

    exe.pie = pie;
    exe.link_z_relro = relro;
    exe.bundle_compiler_rt = true;
    exe.root_module.addIncludePath(b.path("."));
    exe.root_module.addCSourceFile(.{ .file = b.path("workaround.c"), .flags = &[_][]const u8{"-Wall"} });

    const run_cmd = b.addRunArtifact(exe);

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    b.default_step.dependOn(&exe.step);
    b.installArtifact(exe);
}
