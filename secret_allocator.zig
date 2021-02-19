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
        allocator: Allocator,
        parent_allocator: *Allocator,

        const Self = @This();

        pub fn init(parent_allocator: *Allocator) Self {
            return Self{
                .allocator = Allocator{
                    .allocFn = alloc,
                    .resizeFn = resize,
                },
                .parent_allocator = parent_allocator,
            };
        }


       fn alloc(allocator: *Allocator, len: usize, ptr_align: u29, len_align: u29, ra: usize,) error{OutOfMemory}![]u8 {
           const self = @fieldParentPtr(Self, "allocator", allocator);
           if(self.parent_allocator.allocFn(self.parent_allocator, len, ptr_align, len_align, ra)) |buff| {
              if(buff.len >0) if(0!=sodium.sodium_mlock(@ptrCast(*c_void, buff),buff.len)) return mem.Allocator.Error.OutOfMemory;
              return buff;
           } else |err| {
              return err;
           }
       }

       fn resize( allocator: *Allocator, buf: []u8, buf_align: u29, new_len: usize, len_align: u29, ra: usize,) error{OutOfMemory}!usize {
           const self = @fieldParentPtr(Self, "allocator", allocator);
           if(new_len==0) _=sodium.sodium_munlock(@ptrCast(*c_void, buf),buf.len);
           // TODO FIXME what if new_len != buf.len != 0 // shrink or expand?
           if(self.parent_allocator.resizeFn(self.parent_allocator, buf, buf_align, new_len, len_align, ra)) |bsize| {
              if(buf.len>0) _=sodium.sodium_mlock(@ptrCast(*c_void, buf),bsize);
              return bsize;
           } else |err| {
              return err;
           }
       }
   };
}

pub fn secretAllocator(parent_allocator: *Allocator) SecretAllocator() {
   return SecretAllocator().init(parent_allocator);
}
