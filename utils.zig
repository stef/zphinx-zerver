const std = @import("std");
const warn = std.debug.warn;

pub fn hexdump(buf: []const u8) void {
    for (buf) |C| {
        warn("{x:0>2}", .{C});
    }
    warn("\n", .{});
}


pub fn concat(allocator: *std.mem.Allocator, a: []const u8, b: []const u8) ![]u8 {
    const result = try allocator.alloc(u8, a.len + b.len);
    std.mem.copy(u8, result, a);
    std.mem.copy(u8, result[a.len..], b);
    return result;
}

pub fn dir_exists(path: []const u8) bool {
    var cwd = std.fs.cwd();
    const args: std.fs.Dir.OpenDirOptions = undefined;
    var dir = cwd.openDir(path, args) catch return false;
    dir.close();
    return true;
}
