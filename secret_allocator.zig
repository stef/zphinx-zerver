const std = @import("std");
const mem = std.mem;
const debug = std.debug;
const c = std.c;
const assert = debug.assert;

pub const sodium = @cImport({
    @cInclude("sodium.h");
});

const Allocator = mem.Allocator;

pub fn SecretAllocator() type {
    return struct {
        parent: Allocator,
        const Self = @This();

        pub fn init(parent: Allocator) Self {
            return .{
                .parent= parent,
            };
        }

        pub fn allocator(self: *Self) Allocator {
            return Allocator.init(self, alloc, resize, free);
        }

        fn alloc(self: *Self, len: usize, alignment: u29, len_align: u29, return_address: usize,) error{OutOfMemory}![]u8 {
           if(self.parent.rawAlloc(len, alignment, len_align, return_address)) |buff| {
              if(buff.len >0) if(0!=sodium.sodium_mlock(@ptrCast(*anyopaque, buff),buff.len)) return mem.Allocator.Error.OutOfMemory;
              return buff;
           } else |err| {
              return err;
           }
        }

        fn resize(self: *Self, buf: []u8, buf_align: u29, new_len: usize, len_align: u29, return_address: usize,) ?usize {
           if(new_len==0) _=sodium.sodium_munlock(@ptrCast(*anyopaque, buf),buf.len);
           // TODO FIXME what if new_len != buf.len != 0 // shrink or expand?
           if(self.parent.rawResize(buf, buf_align, new_len, len_align, return_address)) |bsize| {
              if(buf.len>0) _=sodium.sodium_mlock(buf.ptr, bsize);
              return bsize;
           }
           return null;
        }

        fn free(self: *Self, buf: []u8, buf_align: u29, return_address: usize) void {
           _ = buf_align;
           _ = return_address;
           _ = sodium.sodium_munlock(buf.ptr,buf.len);
           self.parent.rawFree(buf, buf_align, return_address);
        }
    };
}

pub fn secretAllocator(parent: Allocator) SecretAllocator() {
    return SecretAllocator().init(parent);
}
