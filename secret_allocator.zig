const std = @import("std");
const mem = std.mem;
const debug = std.debug;
const c = std.c;
const assert = debug.assert;

pub const sodium = @cImport({
    @cInclude("sodium.h");
});

const Allocator = mem.Allocator;

pub const secret_allocator = &secret_allocator_state;

// todo you're using the now kinda old allocator interface, are you compiling with an old compiler?
var secret_allocator_state = Allocator{
    .reallocFn = secretRealloc,
    .shrinkFn = secretShrink,
};

fn secretRealloc(self: *Allocator, old_mem: []u8, old_align: u29, new_size: usize, new_align: u29) ![]u8 {
    assert(new_align <= @alignOf(c_longdouble));
    const old_ptr = if (old_mem.len == 0) null else @ptrCast(*c_void, old_mem.ptr);
    if(old_mem.len>0) if(0!=sodium.sodium_munlock(old_ptr,old_mem.len)) return mem.Allocator.Error.OutOfMemory;
    const buf = c.realloc(old_ptr, new_size) orelse return error.OutOfMemory;
    if(new_size>0) if(0!=sodium.sodium_mlock(buf,new_size)) return mem.Allocator.Error.OutOfMemory;
    return @ptrCast([*]u8, buf)[0..new_size];
}

fn secretShrink(self: *Allocator, old_mem: []u8, old_align: u29, new_size: usize, new_align: u29) []u8 {
    const old_ptr = @ptrCast(*c_void, old_mem.ptr);
    if(old_mem.len>0) _=sodium.sodium_munlock(old_ptr,old_mem.len);
    const buf = c.realloc(old_ptr, new_size) orelse return old_mem[0..new_size];
    if(new_size>0) _=sodium.sodium_mlock(buf,new_size);
    return @ptrCast([*]u8, buf)[0..new_size];
}
