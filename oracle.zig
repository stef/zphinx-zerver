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
pub const equihash = @cImport({
    @cInclude("equihash.h");
});
pub const wordexp = @cImport({
    @cInclude("wordexp.h");
});

// todo bug: create, write, delete, read - should read still work?

/// The size of an encrypted pwd gen rule
///    6 - the size of the rule itself
///   24 - the nonce for encryption
///   32 - the xor_mask
///   16 - the auth tag
///------
/// + 78
const RULE_SIZE = 78;

/// normal non-sensitive allocator
const allocator = std.heap.c_allocator;
/// c_allocator for sensitive data, wrapping sodium_m(un)lock()
var s_state = secret_allocator.secretAllocator(allocator);
const s_allocator = &s_state.allocator;

/// server config data
const Config = struct {
    verbose: bool,
    /// the ipv4 address the server is listening on
    address: []const u8,
    port: u16,
    /// tcp connection timeouts
    timeout: u16,
    /// the root directory where all data is stored
    datadir: [:0]const u8,
    /// how many processes can run in parallel
    max_kids: u16,
    /// server key in PEM format
    ssl_key: [:0]const u8,
    /// server cert in PEM format
    ssl_cert: [:0]const u8,
    // decay ratelimit after rl_decay seconds
    rl_decay: i64,
    // increase hardness after rl_threshold attempts if not decaying
    rl_threshold: u8,
    // when checking freshness of puzzle solution, allow this extra
    // gracetime in addition to the hardness max solution time
    rl_gracetime: u16,
};

const ChallengeOp = enum(u8) {
    SPHINX_CREATE = 0,
    CHALLENGE_CREATE = 0x5a,
    VERIFY = 0xa5,
};

const Hardness = struct {
    n: u8,
    k: u8,
    timeout: u16,
};

const Difficulties = [_]Hardness{
    Hardness{ .n = 60,  .k = 4, .timeout =  1    }, // 320KiB, ~0.02
    Hardness{ .n = 65,  .k = 4, .timeout =  2    }, // 640KiB, ~0.04
    Hardness{ .n = 70,  .k = 4, .timeout =  4    }, // 1MiB, ~0.08
    Hardness{ .n = 75,  .k = 4, .timeout =  9    }, // 2MiB, ~0.2
    Hardness{ .n = 80,  .k = 4, .timeout =  16   }, // 5MiB, ~0.5
    Hardness{ .n = 85,  .k = 4, .timeout =  32   }, // 10MiB, ~0.9
    Hardness{ .n = 90,  .k = 4, .timeout =  80   }, // 20MiB, ~2.4
    Hardness{ .n = 95,  .k = 4, .timeout =  160  }, // 40MiB, ~4.6
    Hardness{ .n = 100, .k = 4, .timeout =  320  }, // 80MiB, ~7.8
    Hardness{ .n = 105, .k = 4, .timeout =  640  }, // 160MiB, ~25
    Hardness{ .n = 110, .k = 4, .timeout =  1280 }, // 320MiB, ~57
    Hardness{ .n = 115, .k = 4, .timeout =  2560 }, // 640MiB, ~70
    Hardness{ .n = 120, .k = 4, .timeout =  5120 }, // 1GiB, ~109
};


/// the first byte of a request from a client marks the op
const ReqType = enum(u8) {
    CREATE = 0x00,              // 0000 0000
    READ = 0x33,                // 0011 0011
    UNDO = 0x55,                // 0101 0101
    GET = 0x66,                 // 0110 0110
    COMMIT = 0x99,              // 1001 1001
    CHANGE = 0xaa,              // 1010 1010
    DELETE = 0xff,              // 1111 1111
};

/// initial request sent from client
const Request = struct {
    op: ReqType,   /// see enum above
    id: [64]u8,     /// id is the hex string representation of the original [32]u8 id sent by the client
    has_alpha: bool = true,
    alpha: [32]u8,  /// the blinded password sent by the client.
};

const ChallengeRequest = packed struct {
    n: u8,
    k: u8,
    ts: i64,
    sig: [32]u8,
};

const RatelimitCTX = packed struct {
    level: u8,
    count: u32,
    ts: i64,
};

const SphinxError = error{Error};

const LoadBlobError = error{
    WrongSize,
    WrongRead,
};

const LoadCfgError = error{
    InvalidRLDecay,
};


var conn: net.StreamServer.Connection = undefined;

/// workaround for std.net.StreamServer.accept not being able to handle SO_*TIMEO
fn accept(self: *net.StreamServer) !net.StreamServer.Connection {
    var accepted_addr: net.Address = undefined;
    var adr_len: os.socklen_t = @sizeOf(net.Address);
    if (os.accept(self.sockfd.?, &accepted_addr.any, &adr_len, os.SOCK_CLOEXEC)) |fd| {
        return net.StreamServer.Connection{
            .file = fs.File{ .handle = fd },
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
                ratelimit(&cfg, &s) catch |err| {
                    if(err==error.WouldBlock or err==error.IO) {
                        if(cfg.verbose) warn("timeout, abort.\n",.{});
                        _ = std.os.linux.shutdown(conn.file.handle, std.os.linux.SHUT_RDWR);
                        conn.file.close();
                    } else {
                        return err;
                    }
                };
                os.exit(0);

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
fn parse_req(cfg: *const Config, s: anytype, msg: []u8) *Request {
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

fn ratelimit(cfg: *const Config, s: anytype) anyerror!void {
    warn("ratelimit start\n", .{});
    var op: [1]u8 = undefined;
    _ = try s.read(op[0..]);

    warn("rl op {x}\n", .{op[0]});

    switch (@intToEnum(ChallengeOp, op[0])) {
        ChallengeOp.SPHINX_CREATE => {
            var req = [_]u8{0} ** 65;
            const reqlen = try s.read(req[1..]);
            if(reqlen+1 != req.len) {
                warn("invalid create request. aborting.\n",.{});
            }
            const request = parse_req(cfg, s, req[0..]);
            try handler(cfg, s, request);
        },
        ChallengeOp.CHALLENGE_CREATE => {
            try create_challenge(cfg, s);
        },
        ChallengeOp.VERIFY => {
            try verify_challenge(cfg, s);
        }
    }
    try s.close();
    os.exit(0);
}

fn create_challenge(cfg: *const Config, s: anytype) anyerror!void {
    warn("create puzzle start\n", .{});
    // read request
    var req = [_]u8{0} ** 65;
    var reqlen : usize = 0;
    _ = try s.read(req[0..1]);

    warn("req op {x}\n", .{@intToEnum(ReqType, req[0])});

    if(@intToEnum(ReqType, req[0])==ReqType.READ) {
        _ = try s.read(req[1..33]);
        reqlen = 33;
        warn("cc: {x:0>66}", .{req[0..33]});
    } else {
        _ = try s.read(req[1..65]);
        reqlen = 65;
        warn("cc: {x:0>130}", .{req[0..65]});
    }

    // load MAC key
    var key: []u8 = undefined;
    if (load_blob(s_allocator, cfg, ""[0..], "key"[0..], 32)) |k| {
        key = k;
    } else |err| {
        if (err != error.FileNotFound) {
            if (cfg.verbose) warn("cannot open {}/key error: {}\n", .{ cfg.datadir, err });
            fail(s, cfg);
        }
        key = try s_allocator.alloc(u8, 32);
        sodium.randombytes_buf(key.ptr, key.len);
        save_blob(cfg, "", "key", key) catch fail(s, cfg);
    }
    defer s_allocator.free(key);

    // assemble challenge
    var challenge : ChallengeRequest = undefined;
    const now = std.time.timestamp();
    challenge.ts = now;

    const request = parse_req(cfg, s, req[0..reqlen]);
    if(cfg.verbose) warn("id: {}\n", .{request.id[0..]});
    // figure out n & k params and set them in challenge
    if (load_blob(s_allocator, cfg, request.id[0..], "difficulty"[0..], @sizeOf(RatelimitCTX))) |diff| {
        var ctx: *RatelimitCTX = @ptrCast(*RatelimitCTX, diff[0..]);
        warn("rl ctx {}\n", .{ctx});
        if(ctx.level >= Difficulties.len) {
            // invalid rl context, punish hard
            if (cfg.verbose) warn("invalid difficulty: {}\n", .{ ctx.level });
            ctx.level = Difficulties.len - 1;
            ctx.count=0;
        } else if(now - cfg.rl_decay > ctx.ts and ctx.level>0) { // timestamp too long ago, let's decay
            const periods = @divTrunc((now - ctx.ts), cfg.rl_decay);
            if(ctx.level >= periods) {
                ctx.level = ctx.level - @intCast(u8, periods);
            } else {
                ctx.level = 0;
            }
            ctx.count=0;
        } else { // let's slowly turn up the rate limiting
            if(ctx.count >= cfg.rl_threshold and (ctx.level < Difficulties.len - 1)) {
                ctx.count=0;
                ctx.level+=1;
            } else {
                ctx.count+=1;
            }
        }
        ctx.ts = now;
        if(cfg.verbose) warn("rl difficulty: {}\n", .{ctx});
        save_blob(cfg, request.id[0..], "difficulty"[0..], diff) catch fail(s, cfg);
        challenge.n=Difficulties[ctx.level].n;
        challenge.k=Difficulties[ctx.level].k;

        if((ctx.level == Difficulties.len - 1) and ctx.count>cfg.rl_threshold*2) {
            warn("\x1b[38;5;196malert\x1b[38;5;253m: someones trying ({}) really hard at: {}\n", .{ctx.count, request.id});
        }

    } else |err| {
        if (err != error.FileNotFound) {
            if (cfg.verbose) warn("cannot open {}/{}/difficulty error: {}\n", .{ cfg.datadir, request.id[0..], err });
            fail(s, cfg);
        }
        challenge.n = Difficulties[0].n;
        challenge.k = Difficulties[0].k;
        var ctx = RatelimitCTX{
            .level = 0,
            .count = 1,
            .ts = now,
        };
        save_blob(cfg, request.id[0..], "difficulty"[0..], mem.asBytes(&ctx)[0..]) catch fail(s, cfg);
    }

    // sign challenge
    const tosign = mem.asBytes(&challenge)[0..@byteOffsetOf(ChallengeRequest, "sig")];

    var state : sodium.crypto_generichash_state = undefined;
    _ = sodium.crypto_generichash_init(&state, key.ptr, 32, 32);
    _ = sodium.crypto_generichash_update(&state, @as([*c]u8, &req), reqlen);
    _ = sodium.crypto_generichash_update(&state, tosign, tosign.len);
    _ = sodium.crypto_generichash_final(&state, &challenge.sig, challenge.sig.len);

    // return challenge
    _ = s.write(mem.asBytes(&challenge)[0..]) catch fail(s, cfg);
}

fn verify_challenge(cfg: *const Config, s: anytype) anyerror!void {
    warn("verify puzzle start\n", .{});
    // first read challenge record
    var challenge : ChallengeRequest = undefined;
    var challenge_bytes = mem.asBytes(&challenge)[0..];
    const challenge_len = try s.read(challenge_bytes);
    if(challenge_len!=challenge_bytes.len) {
        warn("challenge record to short\n", .{});
        fail(s,cfg);
    }
    // also read original request
    var req = [_]u8{0} ** 65;
    var reqlen : usize = 0;
    _ = try s.read(req[0..1]);
    if(@intToEnum(ReqType, req[0])==ReqType.READ) {
        _ = try s.read(req[1..33]);
        reqlen = 33;
    } else {
        _ = try s.read(req[1..65]);
        reqlen = 65;
    }
    // read mac key
    var key: []u8 = undefined;
    if (load_blob(s_allocator, cfg, ""[0..], "key"[0..], 32)) |k| {
        key = k;
    } else |err| {
        if (cfg.verbose) warn("cannot open {}/key error: {}\n", .{ cfg.datadir, err });
        fail(s, cfg);
    }
    defer s_allocator.free(key);

    const tosign = mem.asBytes(&challenge)[0..@byteOffsetOf(ChallengeRequest, "sig")];
    // todo check freshness of timestamp!

    var sig = [_]u8{0} ** challenge.sig.len;
    var state : sodium.crypto_generichash_state = undefined;
    _ = sodium.crypto_generichash_init(&state, key.ptr, 32, 32);
    _ = sodium.crypto_generichash_update(&state, @as([*c]u8, &req), reqlen);
    _ = sodium.crypto_generichash_update(&state, tosign, tosign.len);
    _ = sodium.crypto_generichash_final(&state, &sig, sig.len);
    if(0!=sodium.sodium_memcmp(&sig, &challenge.sig, sig.len)) {
        warn("bad sig on challenge\n", .{});
        fail(s,cfg);
    }

    // check if the puzzle has expired
    const now = std.time.timestamp();
    var expired = true;
    for(Difficulties) |diff| {
        if(diff.n==challenge.n and
               diff.k==challenge.k and
               (now - @intCast(i32, diff.timeout+cfg.rl_gracetime)) < challenge.ts) {
            expired = false;
            break;
        }
    }
    if(expired) {
        warn("puzzle expired. reject\n",.{});
        fail(s,cfg);
    }

    // valid challenge record, let's read the solution
    const solsize = equihash.solsize(challenge.n, challenge.k);
    var solution: []u8 = try allocator.alloc(u8, @intCast(usize, solsize));
    defer allocator.free(solution);
    const sollen = try s.read(solution[0..]);
    if(sollen!=solsize) {
        warn("truncated solution\n",.{});
        fail(s,cfg);
    }
    var seed: []u8 = try allocator.alloc(u8, challenge_len + reqlen);
    mem.copy(u8, seed[0..challenge_len], challenge_bytes);
    mem.copy(u8, seed[challenge_len..challenge_len+reqlen], req[0..reqlen]);
    if(0==equihash.verify(challenge.n, challenge.k, seed.ptr, seed.len, solution.ptr, solsize)) {
        warn("bad challenge solution\n",.{});
        fail(s,cfg);
    }
    // call handler with request
    const request = parse_req(cfg, s, req[0..reqlen]);
    return handler(cfg, s, request);
}

/// dispatcher for incoming client requests
/// parses incoming request and calls appropriate op
fn handler(cfg: *const Config, s: anytype, req : *const Request) anyerror!void {
    switch (req.op) {
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
    }
    try s.close();
    allocator.destroy(req);
    os.exit(0);
}

/// whenever anything fails during the execution of the protocol the server sends
/// "\x00\x04fail" to the client and terminates.
fn fail(s: anytype, cfg: *const Config) noreturn {
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

fn expandpath(path: []const u8) [:0]u8 {
    var w: wordexp.wordexp_t=undefined;
    const s = std.cstr.addNullByte(allocator, path) catch unreachable;
    defer allocator.free(s);
    const r = wordexp.wordexp(s,&w, wordexp.WRDE_NOCMD|wordexp.WRDE_UNDEF);
    if(r!=0) {
        warn("wordexp(\"{}\") returned error: {} - string not expanded\n", .{ s, r});
        return allocator.dupeZ(u8, path) catch unreachable;
    }
    defer wordexp.wordfree(&w);
    if(w.we_wordc!=1) {
        warn("wordexp({}) not one word: {}\n", .{ s, w.we_wordc });
        os.exit(1);
    }
    const word = std.mem.spanZ(@as([*c]u8, w.we_wordv[0]));
    var cpy = allocator.dupeZ(u8, word) catch unreachable;
    return cpy;
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
        .ssl_key = "server.pem",
        .ssl_cert = "certs.pem",
        .rl_decay = 1800,
        .rl_threshold = 1,
        .rl_gracetime = 10,
    };

    for (paths) |filename| {
        var t = toml.parseFile(allocator, filename, &parser);
        if (t) |table| {
            defer table.deinit();

            if (table.keys.get("server")) |server| {
                cfg.verbose = if (server.Table.keys.get("verbose")) |v| v.Boolean else cfg.verbose;
                cfg.address = if (server.Table.keys.get("address")) |v| try allocator.dupe(u8, v.String) else cfg.address;
                cfg.port = if (server.Table.keys.get("port")) |v| @intCast(u16, v.Integer) else cfg.port;
                cfg.timeout = if (server.Table.keys.get("timeout")) |v| @intCast(u16, v.Integer) else cfg.timeout;
                cfg.datadir = if (server.Table.keys.get("datadir")) |v| expandpath(v.String) else cfg.datadir;
                cfg.max_kids = if (server.Table.keys.get("max_kids")) |v| @intCast(u16, v.Integer) else cfg.max_kids;
                cfg.ssl_key = if (server.Table.keys.get("ssl_key")) |v| expandpath(v.String) else cfg.ssl_key;
                cfg.ssl_cert = if (server.Table.keys.get("ssl_cert")) |v| expandpath(v.String) else cfg.ssl_cert;
                cfg.rl_decay = if (server.Table.keys.get("rl_decay")) |v| @intCast(i64, v.Integer) else cfg.rl_decay;
                cfg.rl_threshold = if (server.Table.keys.get("rl_threshold")) |v| @intCast(u8, v.Integer) else cfg.rl_threshold;
                cfg.rl_gracetime = if (server.Table.keys.get("rl_gracetime")) |v| @intCast(u16, v.Integer) else cfg.rl_gracetime;
            }
        } else |err| {
            if (err == error.FileNotFound) continue;
            warn("error loading config {}: {}\n", .{ filename, err });
        }
    }
    if(cfg.rl_decay<1) {
        warn("rl_decay must be positive number, please check your config.",.{});
        return LoadCfgError.InvalidRLDecay;
    }
    if (cfg.verbose) {
        warn("cfg.address: {}\n", .{cfg.address});
        warn("cfg.port: {}\n", .{cfg.port});
        warn("cfg.datadir: {}\n", .{cfg.datadir});
        warn("cfg.ssl_key: {}\n", .{cfg.ssl_key});
        warn("cfg.ssl_cert: {}\n", .{cfg.ssl_cert});
        warn("cfg.verbose: {}\n", .{cfg.verbose});
        warn("cfg.rl_decay: {}\n", .{cfg.rl_decay});
        warn("cfg.rl_threshold: {}\n", .{cfg.rl_threshold});
        warn("cfg.rl_gracetime: {}\n", .{cfg.rl_gracetime});
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

fn read_pkt(s: anytype, buf: []u8) anyerror!usize {
    var i: usize = 0;
    while(i<buf.len) {
        var r = try s.read(buf[i..]);
        i+=r;
    }
    return i;
}

fn write_pkt(s: anytype, buf: []const u8) anyerror!usize {
    var i: usize = 0;
    while(i<buf.len) {
        var r = try s.write(buf[i..]);
        i+=r;
    }
    return i;
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
fn update_blob(cfg: *const Config, s: anytype) anyerror!void {
    // the id under which the blob is stored.
    var signedid = [_]u8{0} ** (32+64);
    //# wait for auth signing pubkey and rules
    const idlen = try s.read(signedid[0..signedid.len]);
    if (idlen != signedid.len) fail(s, cfg);

    warn("ub: {x:0>192}", .{signedid});

    const hexid = try tohexid(signedid[0..32].*);
    defer allocator.free(hexid);

    var blob: []u8 = undefined;
    var new = false;

    var pk: [32]u8 = undefined;
    if (load_blob(allocator, cfg, hexid[0..], "pub"[0..], 32)) |k| {
        pk = k[0..32].*;
        // verify sig on id
        _ = verify_blob(signedid[0..], pk) catch fail(s, cfg);

        if (load_blob(allocator, cfg, hexid[0..], "blob"[0..], null)) |b| {
            blob = b;
        } else |err| {
            if (err != error.FileNotFound) {
                if (cfg.verbose) warn("cannot open {}/{}/blob error: {}\n", .{ cfg.datadir, hexid, err });
                fail(s, cfg);
            }
            warn("user blob authkey fund, but no blob for id: {}\n", .{hexid});
            fail(s,cfg);
        }
    } else |err| {
        if (err != error.FileNotFound) {
            if (cfg.verbose) warn("cannot open {}/{}/blob error: {}\n", .{ cfg.datadir, hexid, err });
            fail(s, cfg);
        }
        // ensure that the blob record directory also doesn't exist
        const tdir = try mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", hexid });
        defer allocator.free(tdir);
        if (utils.dir_exists(tdir)) {
            warn("user blob authkey not found, but dir exists: {}\n", .{hexid});
            fail(s,cfg);
        }

        blob = try allocator.alloc(u8, 2);
        std.mem.set(u8, blob, 0);
        new = true;
        // fake pubkey
        //pk = try allocator.alloc(u8, 32);
        //sodium.randombytes_buf(pk[0..].ptr, pk.len);
    }

    const bw = write_pkt(s, blob) catch fail(s, cfg);
    allocator.free(blob);
    if (bw != blob.len) fail(s, cfg);
    try s.flush();

    if (new) {
        var buf = [_]u8{0} ** (2 + 32 + 64 + 65536);
        // read pubkey
        const pklen = try s.read(buf[0..32]);
        if (pklen != 32) fail(s, cfg);
        pk = buf[0..32].*;

        // read blob size
        const x = try s.read(buf[32..34]);
        if (x != 2) fail(s, cfg);
        const bloblen = std.mem.readIntBig(u16, buf[32..34]);
        // read blob
        const end = 34 + @as(u17,bloblen) + 64;
        const recvd = read_pkt(s, buf[34..end]) catch fail(s,cfg);
        if(recvd != end - 34) fail(s,cfg);
        const msg = buf[0 .. end];
        const tmp = verify_blob(msg, pk) catch fail(s, cfg);
        const new_blob = tmp[32 .. end - 64];
        if (!utils.dir_exists(cfg.datadir)) {
            std.os.mkdir(cfg.datadir, 0o700) catch fail(s, cfg);
        }

        const tdir = try mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", hexid });
        defer allocator.free(tdir);

        if (!utils.dir_exists(tdir)) {
            std.os.mkdir(tdir, 0o700) catch fail(s, cfg);
        }
        save_blob(cfg, hexid[0..], "pub", pk[0..]) catch fail(s, cfg);
        save_blob(cfg, hexid[0..], "blob", new_blob) catch fail(s, cfg);
    } else {
        // read pubkey
        var buf = [_]u8{0} ** (2 + 64 + 65536);
        // read blob size
        const x = try s.read(buf[0..2]);
        if (x != 2) fail(s, cfg);
        const bloblen = std.mem.readIntBig(u16, buf[0..2]);
        const end = 2 + @as(u17,bloblen) + 64;
        // read blob
        const recvd = read_pkt(s, buf[2..end]) catch fail(s,cfg);
        if(recvd != end - 2) fail(s,cfg);
        const msg = buf[0 .. end];
        const tmp = verify_blob(msg, pk[0..32].*) catch fail(s, cfg);
        const new_blob = tmp[0 .. end - 64];
        save_blob(cfg, hexid[0..], "blob", new_blob) catch fail(s, cfg);
    }
}

/// auth is used in all (but create and get) operations it evaluates
/// the oprf, sends back beta and a nonce, which needs to be signed
/// correctly to authorize whatever operation follows. the pubkey for
/// the signature is stored in the directory indicated by the ID in
/// the initial request from the client.
fn auth(cfg: *const Config, s: anytype, req: *const Request) anyerror!void {
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
fn create(cfg: *const Config, s: anytype, req: *const Request) anyerror!void {
    const tdir = mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", req.id[0..]}) catch fail(s,cfg);
    defer allocator.free(tdir);
    if (utils.dir_exists(tdir)) fail(s,cfg);

    var key: []u8 = try s_allocator.alloc(u8, 32);
    defer s_allocator.free(key);
    sodium.randombytes_buf(key.ptr, key.len);

    var beta = [_]u8{0} ** 32;

    if (-1 == sphinx.sphinx_respond(&req.alpha, key.ptr, &beta)) fail(s, cfg);

    _ = try s.write(beta[0..]);
    try s.flush();

    var buf: [32 + RULE_SIZE + 64]u8 = undefined; // pubkey, rule, signature
    //# wait for auth signing pubkey and rules
    const msglen = try s.read(buf[0..buf.len]);
    if (msglen != buf.len) {
         fail(s, cfg);
    }

    const CreateResp = packed struct {
        pk: [32]u8, rule: [RULE_SIZE]u8, signature: [64]u8
    };
    const resp: *CreateResp = @ptrCast(*CreateResp, buf[0..]);

    const blob = verify_blob(buf[0..], resp.pk) catch fail(s, cfg);
    const rules = blob[32..];

    // 3rd phase
    // add user to host record
    update_blob(cfg, s) catch fail(s, cfg);

    if (!utils.dir_exists(cfg.datadir)) {
        std.os.mkdir(cfg.datadir, 0o700) catch fail(s, cfg);
    }
    std.os.mkdir(tdir, 0o700) catch fail(s, cfg);

    save_blob(cfg, req.id[0..], "pub", resp.pk[0..]) catch fail(s, cfg);
    save_blob(cfg, req.id[0..], "key", key) catch fail(s, cfg);
    save_blob(cfg, req.id[0..], "rules", rules) catch fail(s, cfg);

    _ = try s.write("ok");
    try s.flush();
}

/// this function evaluates the oprf and sends back beta
fn get(cfg: *const Config, s: anytype, req: *const Request) anyerror!void {
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
fn change(cfg: *const Config, s: anytype, req: *const Request) anyerror!void {
    auth(cfg, s, req) catch fail(s, cfg);

    var alpha: [32]u8 = undefined;
    // wait for alpha
    const msglen = try s.read(alpha[0..]);
    if (msglen != alpha.len) {
         fail(s, cfg);
    }


    var key = [_]u8{0} ** 32;
    if(0!=sodium.sodium_mlock(&key,32)) fail(s,cfg);
    sodium.randombytes_buf(&key, 32);

    //var beta: [32]u8 = undefined;
    var beta = [_]u8{0} ** 32;
    if (-1 == sphinx.sphinx_respond(&alpha, &key, &beta)) fail(s, cfg);

    const betalen = try s.write(beta[0..]);
    try s.flush();
    if(betalen!=beta.len) fail(s,cfg);

    var signedpub: [32 + RULE_SIZE + 64]u8 = undefined; // pubkey, rules, sig
    const signedpublen = try s.read(signedpub[0..]);
    if(signedpublen != signedpub.len) fail(s,cfg);
    const pk = signedpub[0..32];
    _ = verify_blob(signedpub[0..], pk.*) catch fail(s, cfg);

    const rules = signedpub[32..32+RULE_SIZE];

    save_blob(cfg, req.id[0..], "new", key[0..]) catch fail(s, cfg);
    _ = sodium.sodium_munlock(&key,32);
    save_blob(cfg, req.id[0..], "rules.new", rules[0..]) catch fail(s, cfg);
    save_blob(cfg, req.id[0..], "pub.new", pk[0..]) catch fail(s, cfg);

    _ = try s.write("ok");
    try s.flush();
}

/// this op deletes a complete id if it is authenticated, a host-username blob is also updated.
fn delete(cfg: *const Config, s: anytype, req: *const Request) anyerror!void {
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
fn commit_undo(cfg: *const Config, s: anytype, req: *const Request, new: *const [3:0]u8, old: *const [3:0]u8) anyerror!void {
    const path = try mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", req.id[0..] });
    defer allocator.free(path);

    if (!utils.dir_exists(path)) fail(s, cfg);

    auth(cfg, s, req) catch fail(s, cfg);

    // load all files to be shuffled around
    // start with the rules
    var new_rules: []u8 = undefined;
    const new_rulespath = try mem.concat(allocator, u8, &[_][]const u8{ "rules.", new[0..] });
    defer allocator.free(new_rulespath);
    if (load_blob(allocator, cfg, req.id[0..], new_rulespath, RULE_SIZE)) |r| {
        new_rules = r;
    } else |err| {
        fail(s,cfg);
    }
    defer allocator.free(new_rules);
    var cur_rules: []u8 = undefined;
    if (load_blob(allocator, cfg, req.id[0..], "rules"[0..], RULE_SIZE)) |r| {
        cur_rules = r;
    } else |err| {
        fail(s,cfg);
    }
    defer allocator.free(cur_rules);

    // load the auth pub keys
    var new_pub: []u8 = undefined;
    const new_pubpath = try mem.concat(allocator, u8, &[_][]const u8{ "pub.", new[0..] });
    defer allocator.free(new_pubpath);
    if (load_blob(allocator, cfg, req.id[0..], new_pubpath, 32)) |r| {
        new_pub = r;
    } else |err| {
        fail(s,cfg);
    }
    defer allocator.free(new_pub);
    var cur_pub: []u8 = undefined;
    if (load_blob(allocator, cfg, req.id[0..], "pub"[0..], 32)) |r| {
        cur_pub = r;
    } else |err| {
        fail(s,cfg);
    }
    defer allocator.free(cur_pub);

    // and last the keys
    var new_key: []u8 = undefined;
    if (load_blob(s_allocator, cfg, req.id[0..], new[0..], 32)) |r| {
        new_key = r;
    } else |err| {
        fail(s,cfg);
    }
    var cur_key: []u8 = undefined;
    if (load_blob(s_allocator, cfg, req.id[0..], "key"[0..], 32)) |r| {
        cur_key = r;
    } else |err| {
        s_allocator.free(new_key);
        fail(s,cfg);
    }

    // we need to construct the filenames of the old rules/authpubkey
    const old_pubpath = try mem.concat(allocator, u8, &[_][]const u8{ "pub.", old[0..] });
    defer allocator.free(old_pubpath);
    const old_rulespath = try mem.concat(allocator, u8, &[_][]const u8{ "rules.", old[0..] });
    defer allocator.free(old_rulespath);

    // first save the keys
    save_blob(cfg, req.id[0..], old, cur_key) catch {
        s_allocator.free(cur_key);
        s_allocator.free(new_key);
        fail(s, cfg);
    };
    s_allocator.free(cur_key);

    save_blob(cfg, req.id[0..], "key", new_key) catch {
        s_allocator.free(new_key);
        fail(s, cfg);
    };
    s_allocator.free(new_key);

    // now save the rules and pubkeys
    save_blob(cfg, req.id[0..], old_rulespath, cur_rules) catch fail(s, cfg);
    save_blob(cfg, req.id[0..], old_pubpath, cur_pub) catch fail(s, cfg);

    save_blob(cfg, req.id[0..], "rules"[0..], new_rules) catch fail(s, cfg);
    save_blob(cfg, req.id[0..], "pub"[0..], new_pub) catch fail(s, cfg);

    // delete the previously "new" files
    const nkpath = try mem.concat(allocator, u8, &[_][]const u8{ path, "/", new });
    std.os.unlink(nkpath) catch fail(s, cfg);
    allocator.free(nkpath);

    const nppath = try mem.concat(allocator, u8, &[_][]const u8{ path, "/", "pub.", new });
    std.os.unlink(nppath) catch fail(s, cfg);
    allocator.free(nppath);

    const nrpath = try mem.concat(allocator, u8, &[_][]const u8{ path, "/", "rules.", new });
    std.os.unlink(nrpath) catch fail(s, cfg);
    allocator.free(nrpath);

    // send ack
    _ = try s.write("ok");
    try s.flush();
}

/// this op returns a requested blob
fn read(cfg: *const Config, s: anytype, req: *const Request) anyerror!void {
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
