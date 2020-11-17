const builtin = @import("builtin");
const std = @import("std");
const net = std.net;
const os = std.os;
const fs = std.fs;
const mem = std.mem;
const BufSet = std.BufSet;
const warn = std.debug.warn;
const toml = @import("zig-toml/src/toml.zig");
const ssl = @import("ssl.zig");
const utils = @import("utils.zig");
const secret_allocator = @import("secret_allocator.zig");
pub const sodium = @cImport({
    @cInclude("sodium.h");
});
pub const sphinx = @cImport({
    @cInclude("sphinx.h");
});

// todo bug: create, write, delete, read - should read still work?

/// The size of an encrypted pwd gen rule
///    2 - the size of the rule itself
///   24 - the nonce for encryption
///   16 - the mac of the data
///------
/// + 42
const RULE_SIZE = 42;

/// normal non-sensitive allocator
const allocator = std.heap.c_allocator;
/// c_allocator for sensitive data, wrapping sodium_m(un)lock()
const s_allocator = secret_allocator.secret_allocator;

/// server config data
const Config = struct {
    verbose: bool,
    /// the ipv4 address the server is listening on
    address: []const u8,
    port: u16,
    /// timeout is currently unused
    timeout: u16,
    /// the root directory where all data is stored
    datadir: []const u8,
    /// how many processes can run in parallel
    max_kids: u16,
    /// server key in DER format
    ssl_key: [:0]const u8,
    /// server cert in PEM format
    ssl_cert: [:0]const u8,
};

/// the first byte of a request from a client marks the op
const ReqType = enum(u8) {
    CREATE = 0x00,
    READ = 0x33,
    UNDO = 0x55,
    GET = 0x66,
    COMMIT = 0x99,
    CHANGE = 0xaa,
    WRITE = 0xcc,
    DELETE = 0xff,
};

/// initial request sent from client
const Request = struct {
    op: ReqType, /// id is the hex string representation of the original [32]u8 id sent by the client
    id: [64]u8, /// the blinded password sent by the client.
    has_alpha: bool = true,
    alpha: [32]u8
};

const SphinxError = error{Error};

const LoadBlobError = error{
    WrongSize,
    WrongRead,
};

var conn: net.StreamServer.Connection = undefined;

/// workaround for std.net.StreamServer.accept not being able to handle SO_*TIMEO
fn accept(self: *net.StreamServer) !net.StreamServer.Connection {
    const accept_flags = os.SOCK_CLOEXEC;
    var accepted_addr: net.Address = undefined;
    var adr_len: os.socklen_t = @sizeOf(net.Address);
    if (os.accept4(self.sockfd.?, &accepted_addr.any, &adr_len, accept_flags)) |fd| {
        return net.StreamServer.Connection{
            .file = fs.File{
                .handle = fd,
                .io_mode = std.io.mode,
            },
            .address = accepted_addr,
        };
    } else |err| return err;
}

/// classical forking server with tcp connection wrapped by bear ssl
/// number of childs is configurable, as is the listening IPv4 address and port
pub fn main() anyerror!void {
    const cfg = try loadcfg();
    const sk: *ssl.c.private_key = ssl.c.read_private_key(@ptrCast([*c]const u8, cfg.ssl_key));
    var certs_len: usize = undefined;
    const certs: *ssl.c.br_x509_certificate = ssl.c.read_certificates(@ptrCast([*c]const u8, cfg.ssl_cert), &certs_len);

    var opt = net.StreamServer.Options{
        .kernel_backlog = 128,
        .reuse_address = true,
    };

    var srv = net.StreamServer.init(opt);
    var addr = try net.Address.parseIp4(cfg.address, cfg.port);

    srv.listen(addr) catch unreachable;

    const to = os.timeval{
        .tv_sec = cfg.timeout,
        .tv_usec = 0
    };
    try os.setsockopt(srv.sockfd.?, os.SOL_SOCKET, os.SO_SNDTIMEO, mem.asBytes(&to));
    try os.setsockopt(srv.sockfd.?, os.SOL_SOCKET, os.SO_RCVTIMEO, mem.asBytes(&to));

    var kids = BufSet.init(allocator);

    while (true) {
        //conn = try srv.accept();
        if(accept(&srv)) |c| {
            conn = c;
        } else |e| {
            if(e==error.WouldBlock) {
                const Status = if (builtin.link_libc) c_uint else u32;
                var status: Status = undefined;
                const rc = os.system.waitpid(-1, &status, os.WNOHANG);
                if(rc>0) {
                    kids.delete(mem.asBytes(&rc));
                    if(cfg.verbose) warn("removing done kid {} from pool\n",.{rc});
                }
                continue;
            }
            unreachable;
        }

        while (kids.count() >= cfg.max_kids) {
            if (cfg.verbose) warn("waiting for kid to die\n", .{});
            const pid = std.os.waitpid(-1, 0).pid;
            if (cfg.verbose) warn("wait returned: {}\n", .{pid});
            kids.delete(mem.asBytes(&pid));
        }

        var pid = try os.fork();
        switch (pid) {
            0 => {
                var sc: ssl.c.br_ssl_server_context = undefined;
                //c.br_ssl_server_init_full_ec(&sc, certs, certs_len, c.BR_KEYTYPE_EC, &sk.key.ec);
                ssl.c.br_ssl_server_init_minf2c(&sc, certs, certs_len, &sk.key.ec);
                var iobuf: [ssl.c.BR_SSL_BUFSIZE_BIDI]u8 = undefined;
                ssl.c.br_ssl_engine_set_buffer(&sc.eng, &iobuf, iobuf.len, 1);
                // * Reset the server context, for a new handshake.
                if (ssl.c.br_ssl_server_reset(&sc) == 0) {
                    return ssl.convertError(ssl.c.br_ssl_engine_last_error(&sc.eng));
                }
                var s = ssl.initStream(&sc.eng, &conn.file, &conn.file);
                try handler(&cfg, &s);
            },
            else => {
                try kids.put(mem.asBytes(&pid));
                conn.file.close();
            },
        }
    }
}

/// parse incoming requests into a Request structure
/// most importantly convert raw id into hex id
fn parse_req(cfg: *const Config, s: var, msg: []u8) *Request {
    if(@intToEnum(ReqType, msg[0]) == ReqType.READ and msg.len == 33) {
        var req = allocator.create(Request) catch fail(s, cfg);
        req.op = ReqType.READ;
        req.has_alpha = false;
        _ = std.fmt.bufPrint(req.id[0..], "{x:0>64}", .{msg[1..]}) catch fail(s, cfg);
        return req;
    }

    if (msg.len != 65) fail(s, cfg);

    const RawRequest = packed struct {
        op: ReqType, id: [32]u8, alpha: [32]u8
    };
    const rreq: *RawRequest = @ptrCast(*RawRequest, msg[0..65]);

    var req = allocator.create(Request) catch fail(s, cfg);
    req.op = rreq.op;
    mem.copy(u8, req.alpha[0..], rreq.alpha[0..]);
    _ = std.fmt.bufPrint(req.id[0..], "{x:0>64}", .{rreq.id}) catch fail(s, cfg);
    return req;
}

/// dispatcher for incoming client requests
/// parses incoming request and calls appropriate op
fn handler(cfg: *const Config, s: var) anyerror!void {
    var buf: [128]u8 = undefined; // all requests are 65B initially
    const msglen = try s.read(buf[0..buf.len]);

    const req = parse_req(cfg, s, buf[0..msglen]);

    if (cfg.verbose) {
        warn("received: {}B: ", .{msglen});
        utils.hexdump(buf[0..msglen]);
    }
    switch (@intToEnum(ReqType, buf[0])) {
        ReqType.CREATE => {
            try create(cfg, s, req);
        },
        ReqType.GET => {
            try get(cfg, s, req);
        },
        ReqType.CHANGE => {
            try change(cfg, s, req);
        },
        ReqType.DELETE => {
            try delete(cfg, s, req);
        },
        ReqType.COMMIT => {
            try commit_undo(cfg, s, req, "new", "old");
        },
        ReqType.UNDO => {
            try commit_undo(cfg, s, req, "old", "new");
        },
        ReqType.READ => {
            try read(cfg, s, req);
        },
        ReqType.WRITE => {
            try write(cfg, s, req);
        },
        else => {
            unreachable;
        },
    }
    try s.close();
    allocator.destroy(req);
    os.exit(0);
}

/// whenever anything fails during the execution of the protocol the server sends
/// "\x00\x04fail" to the client and terminates.
fn fail(s: var, cfg: *const Config) noreturn {
    @setCold(true);
    if (cfg.verbose) {
        std.debug.dumpCurrentStackTrace(@frameAddress());
        warn("fail\n", .{});
        std.debug.dumpCurrentStackTrace(null);
    }
    _ = s.write("\x00\x04fail") catch unreachable;
    s.flush() catch unreachable;
    _ = std.os.linux.shutdown(conn.file.handle, std.os.linux.SHUT_RDWR);
    s.close() catch unreachable;
    os.exit(0);
}

/// tries to load the config from
///   - /etc/sphinx/config
///   - ~/.config/sphinx/config
///   - ~/.sphinxrc
///   - ./sphinx.cfg
/// and in this process updated the values of the default Config structure
fn loadcfg() anyerror!Config {
    @setCold(true);
    var parser: toml.Parser = undefined;
    defer parser.deinit();

    const home = std.os.getenv("HOME") orelse "/nonexistant";
    const cfg1 = mem.concat(allocator, u8, &[_][]const u8{ home, "/.config/sphinx/config" }) catch unreachable;
    defer allocator.free(cfg1);
    const cfg2 = mem.concat(allocator, u8, &[_][]const u8{ home, "/.sphinxrc" }) catch unreachable;
    defer allocator.free(cfg2);

    const paths = [_][]const u8{
        "/etc/sphinx/config",
        cfg1,
        cfg2,
        "sphinx.cfg",
    };

    // default values for the Config structure
    var cfg = Config{
        .verbose = true,
        .address = "127.0.0.1",
        .port = 8080,
        .timeout = 3,
        .datadir = "/var/lib/sphinx",
        .max_kids = 5,
        .ssl_key = "server.der",
        .ssl_cert = "certs.pem",
    };

    for (paths) |filename| {
        var t = toml.parseFile(allocator, filename, &parser);
        if (t) |table| {
            defer table.deinit();

            if (table.keys.getValue("server")) |server| {
                cfg.verbose = if (server.Table.keys.getValue("verbose")) |v| v.Boolean else cfg.verbose;
                cfg.address = if (server.Table.keys.getValue("address")) |v| try mem.dupe(allocator, u8, v.String) else cfg.address;
                cfg.port = if (server.Table.keys.getValue("port")) |v| @intCast(u16, v.Integer) else cfg.port;
                cfg.timeout = if (server.Table.keys.getValue("timeout")) |v| @intCast(u16, v.Integer) else cfg.timeout;
                cfg.datadir = if (server.Table.keys.getValue("datadir")) |v| try mem.dupe(allocator, u8, v.String) else cfg.datadir;
                cfg.max_kids = if (server.Table.keys.getValue("max_kids")) |v| @intCast(u16, v.Integer) else cfg.max_kids;
                cfg.ssl_key = if (server.Table.keys.getValue("ssl_key")) |v| try std.cstr.addNullByte(allocator, v.String) else cfg.ssl_key;
                cfg.ssl_cert = if (server.Table.keys.getValue("ssl_cert")) |v| try std.cstr.addNullByte(allocator, v.String) else cfg.ssl_cert;
            }
        } else |err| {
            if (err == error.FileNotFound) continue;
            warn("error loading config {}: {}\n", .{ filename, err });
        }
    }
    if (cfg.verbose) {
        warn("cfg.address: {}\n", .{cfg.address});
        warn("cfg.port: {}\n", .{cfg.port});
        warn("cfg.datadir: {}\n", .{cfg.datadir});
        warn("cfg.ssl_key: {}\n", .{cfg.ssl_key});
        warn("cfg.ssl_cert: {}\n", .{cfg.ssl_cert});
    }
    return cfg;
}

/// loads a blob from cfg.datadir/_path/fname, can enforce that the blob has an expected _size
/// returned blob is allocated and must be freed by caller
fn load_blob(balloc: *mem.Allocator, cfg: *const Config, _path: []const u8, fname: []const u8, _size: ?usize) anyerror![]u8 {
    const path = try mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", _path, "/", fname });
    defer allocator.free(path);
    if (std.os.open(path, std.os.O_RDONLY, 0)) |f| {
        defer std.os.close(f);
        const s = try std.os.fstat(f);
        const fsize = s.size;
        if (_size) |size| {
            if (fsize != size) {
                if (cfg.verbose) warn("{} has not expected size of {}B instead has {}B\n", .{ path, size, fsize });
                return LoadBlobError.WrongSize;
            }
        }

        var buf: []u8 = try balloc.alloc(u8, @intCast(usize, fsize));
        const rs = try std.os.read(f, buf);
        if (rs != fsize) {
            balloc.free(buf);
            return LoadBlobError.WrongRead;
        }
        return buf;
    } else |err| {
        return err;
    }
}

/// converts a 32B string to a 64B hex string
/// caller is responsible to free returned string
fn tohexid(id: [32]u8) anyerror![]u8 {
    const hexbuf = try allocator.alloc(u8, 64);
    return std.fmt.bufPrint(hexbuf, "{x:0>64}", .{id});
}

/// verifies an ed25519 signed message using libsodiums crypto_sign_verify_detached
/// expects a msg to be postfixed by ed25519 signature
/// returns a slice to the verified blob or an error
fn verify_blob(msg: []u8, pk: [32]u8) SphinxError![]u8 {
    const sig = msg[msg.len - 64 ..];
    const blob = msg[0 .. msg.len - 64];
    if (0 != sodium.crypto_sign_verify_detached(sig.ptr, blob.ptr, blob.len, &pk)) return SphinxError.Error;
    return blob;
}

/// saves a blob to cfg.datadir/path/fname using strict accessrights
fn save_blob(cfg: *const Config, path: []const u8, fname: []const u8, blob: []const u8) anyerror!void {
    const fpath = try mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", path, "/", fname });
    defer allocator.free(fpath);
    if (std.os.open(fpath, std.os.O_WRONLY | std.os.O_CREAT, 0o600)) |f| {
        defer std.os.close(f);
        const w = try std.os.write(f, blob);
        if (w != blob.len) return SphinxError.Error;
    } else |err| {
        warn("saveblob: {}\n", .{err});
        return SphinxError.Error;
    }
}

/// some operations in the protocol store a encrypted blob under an id
/// when such a blob is being updated it is first returned - if it
/// exists - to the client the client then updates the blob and sends
/// back the updated blob the steps differ slightly depending on the
/// existance of the blob first the client sends over the ID of the
/// blob it wants to update, the server tries to load it, and if found
/// sends it back, the client then replies with the signed updated
/// blob - which we verify and store. otherwise - in case there is no
/// blob under this id, the sends back a zero-sized blob, to which the
/// client responds with a pubkey for this id, and the signed
/// blob. using the pubkey we verify the signed blob and store it.
fn update_blob(cfg: *const Config, s: var) anyerror!void {
    // the id under which the blob is stored.
    var idbuf = [_]u8{0} ** 32;
    //# wait for auth signing pubkey and rules
    const idlen = try s.read(idbuf[0..idbuf.len]);
    if (idlen != idbuf.len) fail(s, cfg);

    const hexid = try tohexid(idbuf[0..].*);
    defer allocator.free(hexid);

    var blob: []u8 = undefined;
    var new = false;
    if (load_blob(allocator, cfg, hexid[0..], "blob"[0..], null)) |b| {
        blob = b;
    } else |err| {
        if (err != error.FileNotFound) {
            if (cfg.verbose) warn("cannot open {}/{}/blob error: {}\n", .{ cfg.datadir, hexid, err });
            fail(s, cfg);
        }
        blob = try allocator.alloc(u8, 2);
        std.mem.set(u8, blob, 0);
        new = true;
    }
    const bw = s.write(blob) catch fail(s, cfg);
    allocator.free(blob);
    if (bw != blob.len) fail(s, cfg);
    try s.flush();

    if (new) {
        var buf = [_]u8{0} ** (2 + 32 + 64 + 65536);
        // read pubkey
        const pklen = try s.read(buf[0..32]);
        if (pklen != 32) fail(s, cfg);
        const pk = buf[0..32];

        // read blob size
        const x = try s.read(buf[32..34]);
        if (x != 2) fail(s, cfg);
        const bloblen = std.mem.readIntBig(u16, buf[32..34]);
        // read blob
        const blobsize = try s.read(buf[34 .. 34 + bloblen + 64]);
        if (bloblen + 64 != blobsize) fail(s, cfg);
        const msg = buf[0 .. 32 + 2 + bloblen + 64];
        const tmp = verify_blob(msg, pk.*) catch fail(s, cfg);
        const new_blob = tmp[32 .. 32 + 2 + bloblen];
        if (!utils.dir_exists(cfg.datadir)) {
            std.os.mkdir(cfg.datadir, 0o700) catch fail(s, cfg);
        }

        const tdir = try mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", hexid });
        defer allocator.free(tdir);

        if (!utils.dir_exists(tdir)) {
            std.os.mkdir(tdir, 0o700) catch fail(s, cfg);
        }
        save_blob(cfg, hexid[0..], "pub", pk) catch fail(s, cfg);
        save_blob(cfg, hexid[0..], "blob", new_blob) catch fail(s, cfg);
    } else {
        // read pubkey
        var pk: []u8 = undefined;
        if (load_blob(allocator, cfg, hexid[0..], "pub"[0..], 32)) |k| {
            pk = k;
        } else |err| {
            // fake pubkey
            pk = try allocator.alloc(u8, 32);
            sodium.randombytes_buf(pk[0..].ptr, pk.len);
        }
        defer allocator.free(pk);

        var buf = [_]u8{0} ** (2 + 64 + 65536);
        // read blob size
        const x = try s.read(buf[0..2]);
        if (x != 2) fail(s, cfg);
        const bloblen = std.mem.readIntBig(u16, buf[0..2]);
        // read blob
        const blobsize = try s.read(buf[2 .. 2 + bloblen + 64]);
        if (bloblen + 64 != blobsize) fail(s, cfg);
        const msg = buf[0 .. 2 + bloblen + 64];
        const tmp = verify_blob(msg, pk[0..32].*) catch fail(s, cfg);
        const new_blob = tmp[0 .. 2 + bloblen];
        save_blob(cfg, hexid[0..], "blob", new_blob) catch fail(s, cfg);
    }
}

/// auth is used in all (but create and get) operations it evaluates
/// the oprf, sends back beta and a nonce, which needs to be signed
/// correctly to authorize whatever operation follows. the pubkey for
/// the signature is stored in the directory indicated by the ID in
/// the initial request from the client.
fn auth(cfg: *const Config, s: var, req: *Request) anyerror!void {
    var pk: []u8 = undefined;
    if (load_blob(allocator, cfg, req.id[0..], "pub"[0..], 32)) |k| {
        pk = k;
    } else |err| {
        fail(s, cfg);
    }

    var resp : []u8 = undefined;
    if (load_blob(s_allocator, cfg, req.id[0..], "key"[0..], 32)) |k| {
        resp = try allocator.alloc(u8, 64);

        if (-1 == sphinx.sphinx_respond(&req.alpha, k.ptr, resp[0..32])) fail(s, cfg);
        s_allocator.free(k);

        sodium.randombytes_buf(resp[32..].ptr, resp.len - 32); // nonce to sign
    } else |err| {
        resp = try allocator.alloc(u8, 32);
        sodium.randombytes_buf(resp[0..].ptr, resp.len); // nonce to sign
    }
    defer allocator.free(resp);

    const rlen = try s.write(resp[0..]);
    try s.flush();
    if (rlen != resp.len) fail(s, cfg);
    if(cfg.verbose) {
        warn("[auth] sent ",.{});
        utils.hexdump(resp[0..]);
    }
    var sig = [_]u8{0} ** 64;
    const siglen = try s.read(sig[0..sig.len]);
    if (siglen != sig.len) fail(s, cfg);
    if(cfg.verbose) {
        warn("[auth] sig ",.{});
        utils.hexdump(sig[0..]);
    }
    if (0 != sodium.crypto_sign_verify_detached(&sig, resp[resp.len - 32..].ptr, 32, pk[0..].ptr)) {
        warn("bad sig\n", .{});
        if(cfg.verbose) warn("pk: ",.{});
        utils.hexdump(pk);
        fail(s, cfg);
    }
}

/// this op creates an oprf key, stores it with an associated pubkey
/// of the client, and updates a blob.
fn create(cfg: *const Config, s: var, req: *Request) anyerror!void {
    const rulespath = try mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", req.id[0..], "/rules" });
    defer allocator.free(rulespath);

    if (cfg.verbose) warn("rulespath: {}\n", .{rulespath});
    //# check if id is unique
    if (std.os.open(rulespath, 0, 0)) |f| {
        std.os.close(f);
        fail(s, cfg);
    } else |err| {
        if (err != error.FileNotFound) {
            warn("fd: {}\n", .{err});
            fail(s, cfg);
        }
    }

    var key: []u8 = undefined;
    // 1st step OPRF with a new seed
    // this might be if the user already has stored a blob for this id
    // and now also wants a sphinx rwd
    if (load_blob(s_allocator, cfg, req.id[0..], "key"[0..], 32)) |k| {
        key = k;
    } else |err| {
        if (err != error.FileNotFound) {
            if (cfg.verbose) warn("cannot open {}/{}/key error: {}\n", .{ cfg.datadir, req.id, err });
            fail(s, cfg);
        }
        key = try s_allocator.alloc(u8, 32);
        sodium.randombytes_buf(key.ptr, key.len);
    }
    defer s_allocator.free(key);

    var beta = [_]u8{0} ** 32;

    if (-1 == sphinx.sphinx_respond(&req.alpha, key.ptr, &beta)) fail(s, cfg);

    _ = try s.write(beta[0..]);
    try s.flush();

    var buf: [32 + RULE_SIZE + 64]u8 = undefined; // pubkey, rule, signature
    //# wait for auth signing pubkey and rules
    const msglen = try s.read(buf[0..buf.len]);
    if (msglen != buf.len) fail(s, cfg);

    const CreateResp = packed struct {
        pk: [32]u8, rule: [RULE_SIZE]u8, signature: [64]u8
    };
    const resp: *CreateResp = @ptrCast(*CreateResp, buf[0..]);

    const blob = verify_blob(buf[0..], resp.pk) catch fail(s, cfg);
    const rules = blob[32..];

    // check if pubkey already exists, then we can skip the
    // following mkdirs, and we *must* verify that the pubkey in the
    // storage is the same as in the response.
    if (load_blob(s_allocator, cfg, req.id[0..], "pub"[0..], 32)) |pk| {
        if(sodium.sodium_memcmp(pk.ptr,resp.pk[0..], pk.len)!=0) fail(s,cfg);
    } else |err| {
        if (!utils.dir_exists(cfg.datadir)) {
            std.os.mkdir(cfg.datadir, 0o700) catch fail(s, cfg);
        }
        const tdir = rulespath[0 .. rulespath.len - 6];
        if (!utils.dir_exists(tdir)) {
            std.os.mkdir(tdir, 0o700) catch fail(s, cfg);
        }
        save_blob(cfg, req.id[0..], "pub", resp.pk[0..]) catch fail(s, cfg);
    }
    save_blob(cfg, req.id[0..], "key", key) catch fail(s, cfg);
    save_blob(cfg, req.id[0..], "rules", rules) catch fail(s, cfg);

    // 3rd phase
    // add user to host record
    update_blob(cfg, s) catch fail(s, cfg);

    _ = try s.write("ok");
    try s.flush();
}

/// this function evaluates the oprf and sends back beta
fn get(cfg: *const Config, s: var, req: *Request) anyerror!void {
    var bail = false;

    var key: []u8 = undefined;
    //# 1st step OPRF with a new seed
    //# this might be if the user already has stored a blob for this id
    //# and now also wants a sphinx rwd
    if (load_blob(s_allocator, cfg, req.id[0..], "key"[0..], 32)) |k| {
        key = k;
    } else |err| {
        // todo?
        //key = try s_allocator.alloc(u8, 32);
        // todo should actually be always the same for repeated alphas
        // possibly use an hmac to calculate this. but that introduces a timing side chan....
        //sodium.randombytes_buf(&key, key.len);
        bail = true;
    }

    var rules: []u8 = undefined;
    //# 1st step OPRF with a new seed
    //# this might be if the user already has stored a blob for this id
    //# and now also wants a sphinx rwd
    if (load_blob(allocator, cfg, req.id[0..], "rules"[0..], null)) |r| {
        rules = r;
    } else |err| {
        bail = true;
    }

    //var beta: [32]u8 = undefined;
    var beta = [_]u8{0} ** 32;

    if (bail) fail(s, cfg);

    if (-1 == sphinx.sphinx_respond(&req.alpha, key.ptr, &beta)) fail(s, cfg);
    s_allocator.free(key); // sanitize

    var resp = try allocator.alloc(u8, beta.len + rules.len);
    defer allocator.free(resp);

    mem.copy(u8, resp[0..beta.len], beta[0..]);
    mem.copy(u8, resp[beta.len..], rules[0..]);

    allocator.free(rules);

    _ = try s.write(resp[0..]);

    try s.flush();
}

/// this op creates a new oprf key under the id, but stores it as "new", it must be "commited" to be set active
fn change(cfg: *const Config, s: var, req: *Request) anyerror!void {
    auth(cfg, s, req) catch fail(s, cfg);

    var key = [_]u8{0} ** 32;
    if(0!=sodium.sodium_mlock(&key,32)) fail(s,cfg);
    sodium.randombytes_buf(&key, 32);

    //var beta: [32]u8 = undefined;
    var beta = [_]u8{0} ** 32;

    if (-1 == sphinx.sphinx_respond(&req.alpha, &key, &beta)) fail(s, cfg);

    var rules: []u8 = undefined;
    //# 1st step OPRF with a new seed
    //# this might be if the user already has stored a blob for this id
    //# and now also wants a sphinx rwd
    if (load_blob(allocator, cfg, req.id[0..], "rules"[0..], null)) |r| {
        rules = r;
    } else |err| {
        fail(s, cfg);
    }

    var resp = try allocator.alloc(u8, beta.len + rules.len);
    defer allocator.free(resp);

    std.mem.copy(u8, resp[0..beta.len], beta[0..]);
    std.mem.copy(u8, resp[beta.len..], rules[0..]);

    allocator.free(rules);

    save_blob(cfg, req.id[0..], "new", key[0..]) catch fail(s, cfg);
    _ = sodium.sodium_munlock(&key,32);

    _ = try s.write(resp[0..]);
    try s.flush();
}

/// this op deletes a complete id if it is authenticated, a host-username blob is also updated.
fn delete(cfg: *const Config, s: var, req: *Request) anyerror!void {
    const path = try mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", req.id[0..] });
    defer allocator.free(path);

    if (!utils.dir_exists(path)) fail(s, cfg);

    auth(cfg, s, req) catch fail(s, cfg);

    update_blob(cfg, s) catch fail(s, cfg);

    std.fs.cwd().deleteTree(path) catch fail(s, cfg);

    _ = try s.write("ok");
    try s.flush();
}

/// this generic function implements both commit and undo. essentially
/// it sets the one in "new" as the new key, and stores the old key
/// under "old"
fn commit_undo(cfg: *const Config, s: var, req: *Request, new: *const [3:0]u8, old: *const [3:0]u8) anyerror!void {
    const path = try mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", req.id[0..] });
    defer allocator.free(path);

    if (!utils.dir_exists(path)) fail(s, cfg);

    auth(cfg, s, req) catch fail(s, cfg);

    var bail = false;

    var k: []u8 = undefined;
    if (load_blob(s_allocator, cfg, req.id[0..], new[0..], null)) |r| {
        k = r;
    } else |err| {
        bail = true;
    }

    var key: []u8 = undefined;
    if (load_blob(s_allocator, cfg, req.id[0..], "key"[0..], 32)) |r| {
        key = r;
    } else |err| {
        bail = true;
    }

    var rules: []u8 = undefined;
    if (load_blob(allocator, cfg, req.id[0..], "rules"[0..], null)) |r| {
        rules = r;
    } else |err| {
        bail = true;
    }

    if (bail) fail(s, cfg);

    var beta = [_]u8{0} ** 32;

    if (-1 == sphinx.sphinx_respond(&req.alpha, k.ptr, &beta)) fail(s, cfg);

    var resp = try allocator.alloc(u8, beta.len + rules.len);
    defer allocator.free(resp);

    std.mem.copy(u8, resp[0..beta.len], beta[0..]);
    std.mem.copy(u8, resp[beta.len..], rules[0..]);
    allocator.free(rules);

    _ = try s.write(resp[0..]);
    try s.flush();

    var buf: [32 + RULE_SIZE + 64]u8 = undefined; // pubkey, rule, signature
    //# wait for auth signing pubkey and rules
    const msglen = try s.read(buf[0..buf.len]);
    if (msglen != buf.len) fail(s, cfg);

    const ChangeResp = packed struct {
        pk: [32]u8, rule: [RULE_SIZE]u8, signature: [64]u8
    };
    const cresp: *ChangeResp = @ptrCast(*ChangeResp, buf[0..]);

    const blob = verify_blob(buf[0..], cresp.pk) catch fail(s, cfg);
    rules = blob[32..];

    save_blob(cfg, req.id[0..], old, key) catch fail(s, cfg);
    s_allocator.free(key);
    save_blob(cfg, req.id[0..], "key", k) catch fail(s, cfg);
    s_allocator.free(k);
    save_blob(cfg, req.id[0..], "pub", cresp.pk[0..]) catch fail(s, cfg);
    save_blob(cfg, req.id[0..], "rules", rules) catch fail(s, cfg);

    const npath = try mem.concat(allocator, u8, &[_][]const u8{ path, "/", new });
    defer allocator.free(npath);

    std.os.unlink(npath) catch fail(s, cfg);

    _ = try s.write("ok");
    try s.flush();
}

/// this op creates or updates an existing blob
fn write(cfg: *const Config, s: var, req: *Request) anyerror!void {
    const path = try mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", req.id[0..] });
    defer allocator.free(path);

    if (!utils.dir_exists(path)) {
        _ = try s.write("new");
        try s.flush();

        var key = [_]u8{0} ** 32;
        if(0!=sodium.sodium_mlock(&key,32)) fail(s,cfg);
        sodium.randombytes_buf(&key, 32);

        //var beta: [32]u8 = undefined;
        var beta = [_]u8{0} ** 32;

        if (-1 == sphinx.sphinx_respond(&req.alpha, &key, &beta)) fail(s, cfg);

        _ = try s.write(beta[0..]);
        try s.flush();

        // (8192+32+64+48) = pubkey, signature, max 8192B sealed(+48B) blob
        var buf: [8192 + 32 + 64 + 48]u8 = undefined; // pubkey, rule, signature
        //# wait for auth signing pubkey and rules
        const msglen = try s.read(buf[0..buf.len]);
        if (msglen <= 32 + 64 + 48) fail(s, cfg);
        const pk = buf[0..32];
        const tmp = verify_blob(buf[0..msglen], pk.*) catch fail(s, cfg);
        const blob = tmp[32..];
        if (!utils.dir_exists(cfg.datadir)) {
            std.os.mkdir(cfg.datadir, 0o700) catch fail(s, cfg);
        }
        if (!utils.dir_exists(path[0..])) {
            std.os.mkdir(path, 0o700) catch fail(s, cfg);
        }
        save_blob(cfg, req.id[0..], "key", key[0..]) catch fail(s, cfg);
        _ = sodium.sodium_munlock(&key,32);
        save_blob(cfg, req.id[0..], "pub", pk) catch fail(s, cfg);
        save_blob(cfg, req.id[0..], "blob", blob) catch fail(s, cfg);
        update_blob(cfg, s) catch fail(s, cfg);
    } else {
        _ = try s.write("old");
        try s.flush();
        auth(cfg, s, req) catch fail(s, cfg);

        var blob: [8192 + 48]u8 = undefined; // max 8192B sealed(+48B) blob
        //# wait for auth signing pubkey and rules
        const msglen = try s.read(blob[0..blob.len]);
        if (msglen <= 48) fail(s, cfg);
        save_blob(cfg, req.id[0..], "blob", blob[0..]) catch fail(s, cfg);
    }
    _ = try s.write("ok");
    try s.flush();
}

/// this op returns a requested blob
fn read(cfg: *const Config, s: var, req: *Request) anyerror!void {
    auth(cfg, s, req) catch fail(s, cfg);

    var blob: []u8 = undefined;
    if (load_blob(allocator, cfg, req.id[0..], "blob", null)) |r| {
        _ = try s.write(r);
        allocator.free(r);
    } else |err| {
        _ = try s.write("");
    }
    try s.flush();
}
