const std = @import("std");
// Export C for advanced interfacing
pub const c = @cImport({
    @cInclude("bearssl.h");
    @cInclude("brssl.h");
    @cInclude("unistd.h");
});

pub const BearError = error{
    BAD_PARAM,
    BAD_STATE,
    UNSUPPORTED_VERSION,
    BAD_VERSION,
    BAD_LENGTH,
    TOO_LARGE,
    BAD_MAC,
    NO_RANDOM,
    UNKNOWN_TYPE,
    UNEXPECTED,
    BAD_CCS,
    BAD_ALERT,
    BAD_HANDSHAKE,
    OVERSIZED_ID,
    BAD_CIPHER_SUITE,
    BAD_COMPRESSION,
    BAD_FRAGLEN,
    BAD_SECRENEG,
    EXTRA_EXTENSION,
    BAD_SNI,
    BAD_HELLO_DONE,
    LIMIT_EXCEEDED,
    BAD_FINISHED,
    RESUME_MISMATCH,
    INVALID_ALGORITHM,
    BAD_SIGNATURE,
    WRONG_KEY_USAGE,
    NO_CLIENT_AUTH,
    IO,
    X509_INVALID_VALUE,
    X509_TRUNCATED,
    X509_EMPTY_CHAIN,
    X509_INNER_TRUNC,
    X509_BAD_TAG_CLASS,
    X509_BAD_TAG_VALUE,
    X509_INDEFINITE_LENGTH,
    X509_EXTRA_ELEMENT,
    X509_UNEXPECTED,
    X509_NOT_CONSTRUCTED,
    X509_NOT_PRIMITIVE,
    X509_PARTIAL_BYTE,
    X509_BAD_BOOLEAN,
    X509_OVERFLOW,
    X509_BAD_DN,
    X509_BAD_TIME,
    X509_UNSUPPORTED,
    X509_LIMIT_EXCEEDED,
    X509_WRONG_KEY_TYPE,
    X509_BAD_SIGNATURE,
    X509_TIME_UNKNOWN,
    X509_EXPIRED,
    X509_DN_MISMATCH,
    X509_BAD_SERVER_NAME,
    X509_CRITICAL_EXTENSION,
    X509_NOT_CA,
    X509_FORBIDDEN_KEY_USAGE,
    X509_WEAK_PUBLIC_KEY,
    X509_NOT_TRUSTED,
    UNKNOWN_ERROR_552,
    UNKNOWN_ERROR_582,
};

pub fn convertError(err: c_int) BearError {
    return switch (err) {
        c.BR_ERR_BAD_PARAM => error.BAD_PARAM,
        c.BR_ERR_BAD_STATE => error.BAD_STATE,
        c.BR_ERR_UNSUPPORTED_VERSION => error.UNSUPPORTED_VERSION,
        c.BR_ERR_BAD_VERSION => error.BAD_VERSION,
        c.BR_ERR_BAD_LENGTH => error.BAD_LENGTH,
        c.BR_ERR_TOO_LARGE => error.TOO_LARGE,
        c.BR_ERR_BAD_MAC => error.BAD_MAC,
        c.BR_ERR_NO_RANDOM => error.NO_RANDOM,
        c.BR_ERR_UNKNOWN_TYPE => error.UNKNOWN_TYPE,
        c.BR_ERR_UNEXPECTED => error.UNEXPECTED,
        c.BR_ERR_BAD_CCS => error.BAD_CCS,
        c.BR_ERR_BAD_ALERT => error.BAD_ALERT,
        c.BR_ERR_BAD_HANDSHAKE => error.BAD_HANDSHAKE,
        c.BR_ERR_OVERSIZED_ID => error.OVERSIZED_ID,
        c.BR_ERR_BAD_CIPHER_SUITE => error.BAD_CIPHER_SUITE,
        c.BR_ERR_BAD_COMPRESSION => error.BAD_COMPRESSION,
        c.BR_ERR_BAD_FRAGLEN => error.BAD_FRAGLEN,
        c.BR_ERR_BAD_SECRENEG => error.BAD_SECRENEG,
        c.BR_ERR_EXTRA_EXTENSION => error.EXTRA_EXTENSION,
        c.BR_ERR_BAD_SNI => error.BAD_SNI,
        c.BR_ERR_BAD_HELLO_DONE => error.BAD_HELLO_DONE,
        c.BR_ERR_LIMIT_EXCEEDED => error.LIMIT_EXCEEDED,
        c.BR_ERR_BAD_FINISHED => error.BAD_FINISHED,
        c.BR_ERR_RESUME_MISMATCH => error.RESUME_MISMATCH,
        c.BR_ERR_INVALID_ALGORITHM => error.INVALID_ALGORITHM,
        c.BR_ERR_BAD_SIGNATURE => error.BAD_SIGNATURE,
        c.BR_ERR_WRONG_KEY_USAGE => error.WRONG_KEY_USAGE,
        c.BR_ERR_NO_CLIENT_AUTH => error.NO_CLIENT_AUTH,
        c.BR_ERR_IO => error.IO,
        c.BR_ERR_X509_INVALID_VALUE => error.X509_INVALID_VALUE,
        c.BR_ERR_X509_TRUNCATED => error.X509_TRUNCATED,
        c.BR_ERR_X509_EMPTY_CHAIN => error.X509_EMPTY_CHAIN,
        c.BR_ERR_X509_INNER_TRUNC => error.X509_INNER_TRUNC,
        c.BR_ERR_X509_BAD_TAG_CLASS => error.X509_BAD_TAG_CLASS,
        c.BR_ERR_X509_BAD_TAG_VALUE => error.X509_BAD_TAG_VALUE,
        c.BR_ERR_X509_INDEFINITE_LENGTH => error.X509_INDEFINITE_LENGTH,
        c.BR_ERR_X509_EXTRA_ELEMENT => error.X509_EXTRA_ELEMENT,
        c.BR_ERR_X509_UNEXPECTED => error.X509_UNEXPECTED,
        c.BR_ERR_X509_NOT_CONSTRUCTED => error.X509_NOT_CONSTRUCTED,
        c.BR_ERR_X509_NOT_PRIMITIVE => error.X509_NOT_PRIMITIVE,
        c.BR_ERR_X509_PARTIAL_BYTE => error.X509_PARTIAL_BYTE,
        c.BR_ERR_X509_BAD_BOOLEAN => error.X509_BAD_BOOLEAN,
        c.BR_ERR_X509_OVERFLOW => error.X509_OVERFLOW,
        c.BR_ERR_X509_BAD_DN => error.X509_BAD_DN,
        c.BR_ERR_X509_BAD_TIME => error.X509_BAD_TIME,
        c.BR_ERR_X509_UNSUPPORTED => error.X509_UNSUPPORTED,
        c.BR_ERR_X509_LIMIT_EXCEEDED => error.X509_LIMIT_EXCEEDED,
        c.BR_ERR_X509_WRONG_KEY_TYPE => error.X509_WRONG_KEY_TYPE,
        c.BR_ERR_X509_BAD_SIGNATURE => error.X509_BAD_SIGNATURE,
        c.BR_ERR_X509_TIME_UNKNOWN => error.X509_TIME_UNKNOWN,
        c.BR_ERR_X509_EXPIRED => error.X509_EXPIRED,
        c.BR_ERR_X509_DN_MISMATCH => error.X509_DN_MISMATCH,
        c.BR_ERR_X509_BAD_SERVER_NAME => error.X509_BAD_SERVER_NAME,
        c.BR_ERR_X509_CRITICAL_EXTENSION => error.X509_CRITICAL_EXTENSION,
        c.BR_ERR_X509_NOT_CA => error.X509_NOT_CA,
        c.BR_ERR_X509_FORBIDDEN_KEY_USAGE => error.X509_FORBIDDEN_KEY_USAGE,
        c.BR_ERR_X509_WEAK_PUBLIC_KEY => error.X509_WEAK_PUBLIC_KEY,
        c.BR_ERR_X509_NOT_TRUSTED => error.X509_NOT_TRUSTED,
        552 => error.UNKNOWN_ERROR_552,
        582 => error.UNKNOWN_ERROR_582,
        else => std.debug.panic("missing error code: {}", .{err}),
    };
}

pub fn initStream(engine: *c.br_ssl_engine_context, in_stream: anytype, out_stream: anytype) Stream(@TypeOf(in_stream), @TypeOf(out_stream)) {
    std.debug.assert(@typeInfo(@TypeOf(in_stream)) == .Pointer);
    std.debug.assert(@typeInfo(@TypeOf(out_stream)) == .Pointer);
    return Stream(@TypeOf(in_stream), @TypeOf(out_stream)).init(engine, in_stream, out_stream);
}

pub fn Stream(comptime SrcInStream: type, comptime SrcOutStream: type) type {
    return struct {
        const Self = @This();

        engine: *c.br_ssl_engine_context,
        ioc: c.br_sslio_context,

        /// Initializes a new SSLStream backed by the ssl engine and file descriptor.
        pub fn init(engine: *c.br_ssl_engine_context, in_stream: SrcInStream, out_stream: SrcOutStream) Self {
            var stream = Self{
                .engine = engine,
                .ioc = undefined,
            };
            c.br_sslio_init(
                &stream.ioc,
                stream.engine,
                sockRead,
                @ptrCast(*c_void, in_stream),
                sockWrite,
                @ptrCast(*c_void, out_stream),
            );
            return stream;
        }

        /// Closes the connection. Note that this may fail when the remote part does not terminate the SSL stream correctly.
        pub fn close(self: *Self) !void {
            if (c.br_sslio_close(&self.ioc) < 0)
                return convertError(c.br_ssl_engine_last_error(self.engine));
        }

        /// Flushes all pending data into the fd.
        pub fn flush(self: *Self) !void {
            if (c.br_sslio_flush(&self.ioc) < 0)
                return convertError(c.br_ssl_engine_last_error(self.engine));
        }

        /// low level read from fd to ssl library
        fn sockRead(ctx: ?*c_void, buf: [*c]u8, len: usize) callconv(.C) c_int {
            var input = @ptrCast(SrcInStream, @alignCast(@alignOf(std.meta.Child(SrcInStream)), ctx.?));
            return if (input.read(buf[0..len])) |num|
                if (num > 0) @intCast(c_int, num) else -1
            else |err|
                -1;
        }

        /// low level  write from ssl library to fd
        fn sockWrite(ctx: ?*c_void, buf: [*c]const u8, len: usize) callconv(.C) c_int {
            var output = @ptrCast(SrcOutStream, @alignCast(@alignOf(std.meta.Child(SrcOutStream)), ctx.?));
            return if (output.write(buf[0..len])) |num|
                if (num > 0) @intCast(c_int, num) else -1
            else |err|
                -1;
        }

        const ReadError = error{EndOfStream} || BearError;

        /// reads some data from the ssl stream.
        pub fn read(self: *Self, buffer: []u8) ReadError!usize {
            var result = c.br_sslio_read(&self.ioc, buffer.ptr, buffer.len);
            if (result < 0) {
                const errc = c.br_ssl_engine_last_error(self.engine);
                if (errc == c.BR_ERR_OK)
                    return 0;
                return convertError(errc);
            }
            return @intCast(usize, result);
        }

        const WriteError = error{EndOfStream} || BearError;

        /// writes some data to the ssl stream.
        pub fn write(self: *Self, bytes: []const u8) WriteError!usize {
            var result = c.br_sslio_write(&self.ioc, bytes.ptr, bytes.len);
            if (result < 0) {
                const errc = c.br_ssl_engine_last_error(self.engine);
                if (errc == c.BR_ERR_OK)
                    return 0;
                return convertError(errc);
            }
            return @intCast(usize, result);
        }

        pub const DstInStream = std.io.InStream(*Self, ReadError, read);
        // todo inStream and outStream are deprecated, it's reader and writer now
        pub fn inStream(self: *Self) DstInStream {
            return .{ .context = self };
        }

        pub const DstOutStream = std.io.OutStream(*Self, WriteError, write);
        pub fn outStream(self: *Self) DstOutStream {
            return .{ .context = self };
        }
    };
}
