const builtin = @import("builtin");
const std = @import("std");
const net = std.net;
const os = std.os;
const posix = std.posix;
const fs = std.fs;
const mem = std.mem;
const BufSet = std.BufSet;
const warn = std.debug.print;
const toml = @import("zig-toml/src/toml.zig");
const ssl = @import("ssl.zig");
const utils = @import("utils.zig");
const secret_allocator = @import("secret_allocator.zig");

pub const DEBUG = (builtin.mode == std.builtin.OptimizeMode.Debug);

pub const sodium = @cImport({
    @cInclude("sodium.h");
});
pub const oprf = @cImport({
    @cInclude("liboprf/src/oprf.h");
});
pub const toprf = @cImport({
    @cInclude("liboprf/src/toprf.h");
});
pub const tp_dkg = @cImport({
    @cInclude("liboprf/src/tp-dkg.h");
});
pub const workaround = @cImport({
    @cInclude("workaround.h");
});
pub const equihash = @cImport({
    @cInclude("equihash.h");
});
pub const wordexp = @cImport({
    @cInclude("wordexp.h");
});

/// The size of an encrypted pwd gen rule
///    6 - the size of the rule itself
///   24 - the nonce for encryption
///   32 - the xor_mask
///   16 - the auth tag
///------
/// + 78
const RULE_SIZE = 79;

/// normal non-sensitive allocator
const allocator = std.heap.c_allocator;
/// c_allocator for sensitive data, wrapping sodium_m(un)lock()
var s_state = secret_allocator.secretAllocator(allocator);
const s_allocator = s_state.allocator();

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
    /// server long-term signature key for DKG
    ltsigkey: [:0]const u8,
    /// maximum age still considered fresh, in seconds
    ts_epsilon: u64,
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
    SPHINX_DKG_CREATE = 0xf0,
    CHALLENGE_CREATE = 0x5a,
    VERIFY = 0xa5,
    _,
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
    CHANGE_DKG = 0xa0,
    CHANGE = 0xaa,              // 1010 1010
    CREATE_DKG = 0xf0,
    DELETE = 0xff,              // 1111 1111
};

/// initial request sent from client
const Request = struct {
    /// see enum above
    op: ReqType align(1),
    /// id is the hex string representation of the original [32]u8 id sent by the client
    id: [64]u8 align(1),
    has_alpha: bool align(1) = true,
    /// the blinded password sent by the client.
    alpha: [32]u8 align(1),
};

const ChallengeRequest = extern struct {
    n: u8 align(1),
    k: u8 align(1),
    ts: i64 align(1) ,
    sig: [32]u8 align(1),
};

const RatelimitCTX = extern struct {
    level: u8 align(1),
    count: u32 align(1),
    ts: i64 align(1),
};

const SphinxError = error{Error};

const LoadBlobError = error{
    WrongSize,
    WrongRead,
};

const LoadCfgError = error{
    InvalidRLDecay,
};


var conn: net.Server.Connection = undefined;

/// classical forking server with tcp connection wrapped by bear ssl
/// number of childs is configurable, as is the listening IP address and port
pub fn main() anyerror!void {
    const cfg = try loadcfg();
    const sk: *ssl.c.private_key = ssl.c.read_private_key(@ptrCast(cfg.ssl_key));
    var certs_len: usize = undefined;
    const certs: *ssl.c.br_x509_certificate = ssl.c.read_certificates(@ptrCast(cfg.ssl_cert), &certs_len);

    const addr = try net.Address.parseIp(cfg.address, cfg.port);

    var srv = addr.listen(.{.reuse_address = true }) catch |err| switch (err) {
        error.AddressInUse => {
            warn("port {} already in use.", .{cfg.port});
            posix.exit(1);
        },
        else => {
           return err;
           //unreachable,
        }
    };

    const to = posix.timeval{
        .tv_sec = cfg.timeout,
        .tv_usec = 0
    };
    try posix.setsockopt(srv.stream.handle, posix.SOL.SOCKET, posix.SO.SNDTIMEO, mem.asBytes(&to));
    try posix.setsockopt(srv.stream.handle, posix.SOL.SOCKET, posix.SO.RCVTIMEO, mem.asBytes(&to));

    var kids = BufSet.init(allocator);

    while (true) {
        if(srv.accept()) |c| {
            conn = c;
        } else |e| {
            if(e==error.WouldBlock) {
                const Status = if (builtin.link_libc) c_int else u32;
                var status: Status = undefined;
                const rc = posix.system.waitpid(-1, &status, posix.system.W.NOHANG);
                if(rc>0) {
                    kids.remove(mem.asBytes(&rc));
                    if(cfg.verbose) warn("removing kid {} from pool\n",.{rc});
                }
                continue;
            }
            unreachable;
        }

        while (kids.count() >= cfg.max_kids) {
            if (cfg.verbose) warn("waiting for kid to die\n", .{});
            const pid = posix.waitpid(-1, 0).pid;
            if (cfg.verbose) warn("wait returned: {}\n", .{pid});
            kids.remove(mem.asBytes(&pid));
        }

        var pid = try posix.fork();
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
                var s = ssl.initStream(&sc.eng, &conn.stream, &conn.stream);
                ratelimit(&cfg, &s) catch |err| {
                    if(err==error.WouldBlock or err==error.IO) {
                        if(cfg.verbose) warn("timeout, abort.\n",.{});
                        _ = std.os.linux.shutdown(conn.stream.handle, std.os.linux.SHUT.RDWR);
                        conn.stream.close();
                    } else {
                        return err;
                    }
                };
                posix.exit(0);

            },
            else => {
                try kids.insert(mem.asBytes(&pid));
                conn.stream.close();
            },
        }
    }
}

/// parse incoming requests into a Request structure
/// most importantly convert raw id into hex id
fn parse_req(cfg: *const Config, s: anytype, msg: []u8) *Request {
    if(@as(ReqType, @enumFromInt(msg[0])) == ReqType.READ and msg.len == 33) {
        var req = allocator.create(Request) catch fail(s, cfg);
        req.op = ReqType.READ;
        req.has_alpha = false;
        _ = std.fmt.bufPrint(req.id[0..], "{x:0>64}", .{std.fmt.fmtSliceHexLower(msg[1..])}) catch fail(s, cfg);
        return req;
    }

    if (msg.len != 65) fail(s, cfg);

    const RawRequest = extern struct {
        op: ReqType align(1), id: [32]u8 align(1), alpha: [32]u8 align(1)
    };
    const rreq: *RawRequest = @ptrCast(msg[0..65]);

    var req = allocator.create(Request) catch fail(s, cfg);
    req.op = rreq.op;
    @memcpy(req.alpha[0..], rreq.alpha[0..]);
    _ = std.fmt.bufPrint(req.id[0..], "{x:0>64}", .{std.fmt.fmtSliceHexLower(rreq.id[0..])}) catch fail(s, cfg);
    return req;
}

fn ratelimit(cfg: *const Config, s: anytype) anyerror!void {
    //warn("ratelimit start\n", .{});
    var op: [1]u8 = undefined;
    _ = s.read(op[0..]) catch |err| {
        if(err==ssl.BearError.UNSUPPORTED_VERSION) {
           warn("{} unsupported TLS version. aborting.\n",.{conn.address});
           try s.close();
           posix.exit(0);
        } else if(err==ssl.BearError.UNKNOWN_ERROR_582 or err==ssl.BearError.UNKNOWN_ERROR_552) {
           warn("{} unknown TLS error: {}. aborting.\n",.{conn.address, err});
           try s.close();
           posix.exit(0);
        } else if(err==ssl.BearError.BAD_VERSION) {
           warn("{} bad TLS version. aborting.\n",.{conn.address});
           try s.close();
           posix.exit(0);
        }
    };

    //if (cfg.verbose) warn("rl op {x}\n", .{op[0]});

    switch (@as(ChallengeOp, @enumFromInt(op[0]))) {
        ChallengeOp.SPHINX_CREATE => {
            var req = [_]u8{0} ** 65;
            const reqlen = try s.read(req[1..]);
            if(reqlen+1 != req.len) {
                warn("invalid create request. aborting.\n",.{});
            }
            const request = parse_req(cfg, s, req[0..]);
            if (cfg.verbose) warn("{} sphinx op create {s}\n", .{conn.address, request.id});
            try handler(cfg, s, request);
        },
        ChallengeOp.SPHINX_DKG_CREATE => {
            var req = [_]u8{0} ** 65;
            const reqlen = try s.read(req[1..]);
            if(reqlen+1 != req.len) {
                warn("invalid dkg create request. aborting.\n",.{});
            }
            req[0] = op[0];
            const request = parse_req(cfg, s, req[0..]);
            if (cfg.verbose) warn("{} sphinx op dkg create {s}\n", .{conn.address, request.id});
            try handler(cfg, s, request);
        },
        ChallengeOp.CHALLENGE_CREATE => {
            if (cfg.verbose) warn("{} rl op challenge\n", .{conn.address});
            try create_challenge(cfg, s);
        },
        ChallengeOp.VERIFY => {
            if (cfg.verbose) warn("{} rl op solve\n", .{conn.address});
            try verify_challenge(cfg, s);
        },
        _ => {
            if (cfg.verbose) warn("{} invalid ratelimit op. aborting.\n",.{conn.address});
        }
    }
    try s.close();
    posix.exit(0);
}

fn create_challenge(cfg: *const Config, s: anytype) anyerror!void {
    warn("create puzzle start\n", .{});
    // read request
    var req = [_]u8{0} ** 65;
    var reqlen : usize = 0;
    _ = try s.read(req[0..1]);

    warn("create_challenge for req op {x} ", .{req[0]});

    if(@as(ReqType, @enumFromInt(req[0]))==ReqType.READ) {
        _ = try s.read(req[1..33]);
        reqlen = 33;
        //if (cfg.verbose) warn("cc: {x:0>66} ", .{req[0..33]});
    } else {
        _ = try s.read(req[1..65]);
        reqlen = 65;
        //if (cfg.verbose) warn("cc: {x:0>130} ", .{req[0..65]});
    }

    // load MAC key
    var key: []u8 = undefined;
    if (load_blob(s_allocator, cfg, ""[0..], "key"[0..], 32)) |k| {
        key = k;
    } else |err| {
        if (err != error.FileNotFound) {
            if (cfg.verbose) warn("\ncannot open {s}/key error: {}\n", .{ cfg.datadir, err });
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
    if(cfg.verbose) warn("id: {s}\n", .{request.id[0..]});
    // figure out n & k params and set them in challenge
    if (load_blob(s_allocator, cfg, request.id[0..], "difficulty"[0..], @sizeOf(RatelimitCTX))) |diff| {
        var ctx: *RatelimitCTX = @ptrCast(@alignCast(diff[0..]));
        //if (cfg.verbose) warn("rl ctx {}\n", .{ctx});
        if(ctx.level >= Difficulties.len) {
            // invalid rl context, punish hard
            if (cfg.verbose) warn("invalid difficulty: {}\n", .{ ctx.level });
            ctx.level = Difficulties.len - 1;
            ctx.count=0;
        } else if(now - cfg.rl_decay > ctx.ts and ctx.level>0) { // timestamp too long ago, let's decay
            const periods = @divTrunc((now - ctx.ts), cfg.rl_decay);
            if(ctx.level >= periods) {
                ctx.level = ctx.level - @as(u8, @intCast(periods));
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

        if(ctx.level > 0) {
           if(ctx.level < Difficulties.len / 2) {
               warn("\x1b[38;5;196malert\x1b[38;5;253m: {} someones re-trying ({}) at: {s}\n", .{conn.address, ctx.level, request.id});
           } else if((ctx.level > Difficulties.len / 2) and ctx.level < (Difficulties.len - 1)) {
               warn("\x1b[38;5;196malert\x1b[38;5;253m: {} someones trying ({}) hard at: {s}\n", .{conn.address, ctx.level, request.id});
           } else {
               warn("\x1b[38;5;196malert\x1b[38;5;253m: {} someones trying ({}/{}) really hard at: {s}\n", .{conn.address, ctx.level, ctx.count, request.id});
           }
        }

    } else |err| {
        if (err != error.FileNotFound) {
            if (cfg.verbose) warn("cannot open {s}/{s}/difficulty error: {}\n", .{ cfg.datadir, request.id[0..], err });
            fail(s, cfg);
        }
        challenge.n = Difficulties[0].n;
        challenge.k = Difficulties[0].k;
        var ctx = RatelimitCTX{
            .level = 0,
            .count = 1,
            .ts = now,
        };

        save_blob(cfg, request.id[0..], "difficulty"[0..], mem.asBytes(&ctx)[0..]) catch |err2| if (err2!=error.FileNotFound ) {
            if (cfg.verbose) warn("cannot save {s}/{s}/difficulty error: {}\n", .{ cfg.datadir, request.id[0..], err });
            fail(s, cfg);
        };
    }

    // sign challenge
    const tosign = mem.asBytes(&challenge)[0..@offsetOf(ChallengeRequest, "sig")];

    var state : sodium.crypto_generichash_state = undefined;
    _ = sodium.crypto_generichash_init(&state, key.ptr, key.len, 32);
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
    const challenge_bytes = mem.asBytes(&challenge)[0..];
    const challenge_len = try s.read(challenge_bytes);
    if(challenge_len!=challenge_bytes.len) {
        warn("challenge record to short {} != {}\n", .{challenge_len, challenge_bytes.len});
        fail(s,cfg);
    }
    // also read original request
    var req = [_]u8{0} ** 65;
    var reqlen : usize = 0;
    _ = try s.read(req[0..1]);
    if(@as(ReqType, @enumFromInt(req[0]))==ReqType.READ) {
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
        if (cfg.verbose) warn("cannot open {s}/key error: {}\n", .{ cfg.datadir, err });
        fail(s, cfg);
    }
    defer s_allocator.free(key);

    const tosign = mem.asBytes(&challenge)[0..@offsetOf(ChallengeRequest, "sig")];
    // todo check freshness of timestamp!

    var sig = [_]u8{0} ** 32; // challenge.sig.len == 32
    var state : sodium.crypto_generichash_state = undefined;
    _ = sodium.crypto_generichash_init(&state, key.ptr, key.len, 32);
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
               (now - @as(i32, @intCast(diff.timeout+cfg.rl_gracetime))) < challenge.ts) {
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
    var solution: []u8 = try allocator.alloc(u8, @as(usize, @intCast(solsize)));
    defer allocator.free(solution);
    const sollen = try s.read(solution[0..]);
    if(sollen!=solsize) {
        warn("truncated solution\n",.{});
        fail(s,cfg);
    }
    var seed: []u8 = try allocator.alloc(u8, challenge_len + reqlen);
    @memcpy(seed[0..challenge_len], challenge_bytes);
    @memcpy(seed[challenge_len..challenge_len+reqlen], req[0..reqlen]);
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
    if (cfg.verbose) warn("{} sphinx op {} {s}\n", .{conn.address, req.op, req.id});
    switch (req.op) {
        ReqType.CREATE => {
            try create(cfg, s, req);
        },
        ReqType.CREATE_DKG => {
            try create_dkg(cfg, s, req);
        },
        ReqType.GET => {
            try get(cfg, s, req);
        },
        ReqType.CHANGE => {
            try change(cfg, s, req);
        },
        ReqType.CHANGE_DKG => {
            try change_dkg(cfg, s, req);
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
    posix.exit(0);
}

/// whenever anything fails during the execution of the protocol the server sends
/// "\x00\x04fail" to the client and terminates.
fn fail(s: anytype, cfg: *const Config) noreturn {
    @setCold(true);
    if (cfg.verbose) {
        std.debug.dumpCurrentStackTrace(@frameAddress());
        warn("fail\n", .{});
        std.debug.dumpCurrentStackTrace(@returnAddress());
    }
    _ = s.write("\x00\x04fail") catch null;
    _ = s.flush() catch null;
    _ = std.os.linux.shutdown(conn.stream.handle, std.os.linux.SHUT.RDWR);
    _ = s.close() catch null;
    posix.exit(0);
}

fn expandpath(path: []const u8) [:0]u8 {
    var w: wordexp.wordexp_t=undefined;
    const s = allocator.dupeZ(u8, path) catch unreachable;
    defer allocator.free(s);
    const r = wordexp.wordexp(s,&w, wordexp.WRDE_NOCMD|wordexp.WRDE_UNDEF);
    if(r!=0) {
        warn("wordexp(\"{s}\") returned error: {} - string not expanded\n", .{ s, r});
        return allocator.dupeZ(u8, path) catch unreachable;
    }
    defer wordexp.wordfree(&w);
    if(w.we_wordc!=1) {
        warn("wordexp({s}) not one word: {}\n", .{ s, w.we_wordc });
        posix.exit(1);
    }
    const word = std.mem.sliceTo(@as([*c]u8, w.we_wordv[0]),0);
    const cpy = allocator.dupeZ(u8, word) catch unreachable;
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

    const home = posix.getenv("HOME") orelse "/nonexistant";
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
        .ltsigkey = "ltsig.key",
        .ts_epsilon = 600,
        .rl_decay = 1800,
        .rl_threshold = 1,
        .rl_gracetime = 10,
    };

    //var parser: toml.Parser = undefined;
    for (paths) |filename| {
        if(toml.parseFile(allocator, filename)) |p| {
            var parser: toml.Parser = p;
            defer parser.deinit();
            const t = parser.parse();
            if (t) |table| {
                defer table.deinit();

                if (table.keys.get("server")) |server| {
                    cfg.verbose = if (server.Table.keys.get("verbose")) |v| v.Boolean else cfg.verbose;
                    cfg.address = if (server.Table.keys.get("address")) |v| try allocator.dupe(u8, v.String) else cfg.address;
                    cfg.port = if (server.Table.keys.get("port")) |v| @intCast(v.Integer) else cfg.port;
                    cfg.timeout = if (server.Table.keys.get("timeout")) |v| @intCast(v.Integer) else cfg.timeout;
                    cfg.datadir = if (server.Table.keys.get("datadir")) |v| expandpath(v.String) else cfg.datadir;
                    cfg.max_kids = if (server.Table.keys.get("max_kids")) |v| @intCast(v.Integer) else cfg.max_kids;
                    cfg.ssl_key = if (server.Table.keys.get("ssl_key")) |v| expandpath(v.String) else cfg.ssl_key;
                    cfg.ssl_cert = if (server.Table.keys.get("ssl_cert")) |v| expandpath(v.String) else cfg.ssl_cert;
                    cfg.ltsigkey = if (server.Table.keys.get("ltsigkey")) |v| expandpath(v.String) else cfg.ltsigkey;
                    cfg.ts_epsilon = if (server.Table.keys.get("ts_epsilon")) |v| @intCast(v.Integer) else cfg.ts_epsilon;
                    cfg.rl_decay = if (server.Table.keys.get("rl_decay")) |v| @intCast(v.Integer) else cfg.rl_decay;
                    cfg.rl_threshold = if (server.Table.keys.get("rl_threshold")) |v| @intCast(v.Integer) else cfg.rl_threshold;
                    cfg.rl_gracetime = if (server.Table.keys.get("rl_gracetime")) |v| @intCast(v.Integer) else cfg.rl_gracetime;
                }
            } else |err| {
                if (err == error.FileNotFound) continue;
                warn("error loading config {s}: {}\n", .{ filename, err });
            }
        } else |err| {
            if (err == error.FileNotFound) continue;
            warn("error loading config {s}: {}\n", .{ filename, err });
            return err;
        }
    }
    if(cfg.rl_decay<1) {
        warn("rl_decay must be positive number, please check your config.\n",.{});
        return LoadCfgError.InvalidRLDecay;
    }
    if (cfg.verbose) {
        warn("cfg.address: {s}\n", .{cfg.address});
        warn("cfg.port: {}\n", .{cfg.port});
        warn("cfg.datadir: {s}\n", .{cfg.datadir});
        warn("cfg.ssl_key: {s}\n", .{cfg.ssl_key});
        warn("cfg.ssl_cert: {s}\n", .{cfg.ssl_cert});
        warn("cfg.ltsigkey: {s}\n", .{cfg.ltsigkey});
        warn("cfg.ts_epsilon: {}\n", .{cfg.ts_epsilon});
        warn("cfg.verbose: {}\n", .{cfg.verbose});
        warn("cfg.rl_decay: {}\n", .{cfg.rl_decay});
        warn("cfg.rl_threshold: {}\n", .{cfg.rl_threshold});
        warn("cfg.rl_gracetime: {}\n", .{cfg.rl_gracetime});
    }
    return cfg;
}

/// loads a blob from cfg.datadir/_path/fname, can enforce that the blob has an expected _size
/// returned blob is allocated and must be freed by caller
fn load_blob(balloc: mem.Allocator, cfg: *const Config, _path: []const u8, fname: []const u8, _size: ?usize) anyerror![]u8 {
    const path = try mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", _path, "/", fname });
    defer allocator.free(path);
    if (posix.open(path, .{.ACCMODE = .RDONLY }, 0)) |f| {
        defer posix.close(f);
        const s = try posix.fstat(f);
        const fsize = s.size;
        if (_size) |size| {
            if (fsize != size) {
                if (cfg.verbose) warn("{s} has not expected size of {}B instead has {}B\n", .{ path, size, fsize });
                return LoadBlobError.WrongSize;
            }
        }

        const buf: []u8 = try balloc.alloc(u8, @intCast(fsize));
        const rs = try posix.read(f, buf);
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
    return std.fmt.bufPrint(hexbuf, "{x:0>64}", .{std.fmt.fmtSliceHexLower(id[0..])});
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
    if (posix.open(fpath, .{.ACCMODE=.WRONLY, .CREAT = true }, 0o600)) |f| {
        defer posix.close(f);
        const w = try posix.write(f, blob);
        if (w != blob.len) return SphinxError.Error;
    } else |err| {
        warn("saveblob: {}\n", .{err});
        return SphinxError.Error;
    }
}

fn read_pkt(s: anytype, buf: []u8) anyerror!usize {
    var i: usize = 0;
    while(i<buf.len) {
        const r = try s.read(buf[i..]);
        if (r == 0) break;
        i+=r;
    }
    return i;
}

fn write_pkt(s: anytype, buf: []const u8) anyerror!usize {
    var i: usize = 0;
    while(i<buf.len) {
        const r = try s.write(buf[i..]);
        if (r == 0) break;
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

    //if(cfg.verbose) warn("ub: {x:0>192}\n", .{signedid});

    const idvec: @Vector(32, u8) = signedid[0..32].*;
    if(@reduce(std.builtin.ReduceOp.Or, idvec) == 0) return;


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
                if (cfg.verbose) warn("cannot open {s}/{s}/blob error: {}\n", .{ cfg.datadir, hexid, err });
                fail(s, cfg);
            }
            warn("user blob authkey fund, but no blob for id: {s}\n", .{hexid});
            fail(s,cfg);
        }
    } else |err| {
        if (err != error.FileNotFound) {
            if (cfg.verbose) warn("cannot open {s}/{s}/blob error: {}\n", .{ cfg.datadir, hexid, err });
            fail(s, cfg);
        }
        // ensure that the blob record directory also doesn't exist
        const tdir = try mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", hexid });
        defer allocator.free(tdir);
        if (utils.dir_exists(tdir)) {
            warn("user blob authkey not found, but dir exists: {s}\n", .{hexid});
            fail(s,cfg);
        }

        blob = try allocator.alloc(u8, 2);
        @memset(blob, 0);
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
        const bloblen = std.mem.readInt(u16, buf[32..34], std.builtin.Endian.big);
        // read blob
        const end = 34 + @as(u17,bloblen) + 64;
        const recvd = read_pkt(s, buf[34..end]) catch fail(s,cfg);
        if(recvd != end - 34) fail(s,cfg);
        const msg = buf[0 .. end];
        const tmp = verify_blob(msg, pk) catch fail(s, cfg);
        const new_blob = tmp[32 .. end - 64];
        if (!utils.dir_exists(cfg.datadir)) {
            posix.mkdir(cfg.datadir, 0o700) catch fail(s, cfg);
        }

        const tdir = try mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", hexid });
        defer allocator.free(tdir);

        if (!utils.dir_exists(tdir)) {
            posix.mkdir(tdir, 0o700) catch fail(s, cfg);
        }
        save_blob(cfg, hexid[0..], "pub", pk[0..]) catch fail(s, cfg);
        save_blob(cfg, hexid[0..], "blob", new_blob) catch fail(s, cfg);
    } else {
        // read pubkey
        var buf = [_]u8{0} ** (2 + 64 + 65536);
        // read blob size
        const x = try s.read(buf[0..2]);
        if (x != 2) fail(s, cfg);
        const bloblen = std.mem.readInt(u16, buf[0..2], std.builtin.Endian.big);
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
    } else |_| {
        fail(s, cfg);
    }

    var resp : []u8 = undefined;
    if (load_blob(s_allocator, cfg, req.id[0..], "key"[0..], 33)) |k| {
        resp = try allocator.alloc(u8, 65);

        resp[0]=k[0];
        if (-1 == oprf.oprf_Evaluate(k[1..33].ptr, &req.alpha, resp[1..33].ptr)) fail(s, cfg);

        s_allocator.free(k);

        sodium.randombytes_buf(resp[33..].ptr, 32); // nonce to sign
    } else |_| {
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
    if (s.read(sig[0..sig.len])) |siglen| {
        if (siglen != sig.len) fail(s, cfg);
    } else |e| {
        warn("error reading sig: {}\n", .{e});
        fail(s,cfg);
    }
    if(cfg.verbose) {
        warn("[auth] sig ",.{});
        utils.hexdump(sig[0..]);
    }
    if (0 != sodium.crypto_sign_verify_detached(&sig, resp[(resp.len - 32)..].ptr, 32, pk[0..].ptr)) {
        warn("bad sig\n", .{});
        if(cfg.verbose) warn("pk: ",.{});
        utils.hexdump(pk);
        fail(s, cfg);
    }

    _ = try s.write("\x00\x04auth");
    _ = try s.flush();
}

fn dkg(cfg: *const Config, s: anytype, msg0: []const u8, share: []u8) anyerror!void {
    var ltsigkey: []u8 = undefined;
    if (load_blob(s_allocator, cfg, ""[0..], cfg.ltsigkey, sodium.crypto_sign_SECRETKEYBYTES)) |b| {
        ltsigkey = b;
    } else |err| {
        if (err != error.FileNotFound) {
            if (cfg.verbose) warn("cannot open {s}/{s} error: {}\n", .{ cfg.datadir, cfg.ltsigkey, err });
            fail(s, cfg);
        }
        warn("no ltsigkey found at : {s}/{s}\n", .{cfg.datadir, cfg.ltsigkey});
        fail(s,cfg);
    }

    var peer = workaround.new_peerstate();
    defer workaround.del_peerstate(@ptrCast(&peer));

    const retsp = tp_dkg.tpdkg_start_peer(@ptrCast(peer), cfg.ts_epsilon, ltsigkey.ptr, @ptrCast(msg0.ptr));
    if(retsp!=0) {
        warn("failed to start tp-dkg peer (error code: {})\n", .{retsp});
        fail(s, cfg);
    }
    const n = @as(*tp_dkg.TP_DKG_PeerState, @ptrCast(peer)).n;
    const t = @as(*tp_dkg.TP_DKG_PeerState, @ptrCast(peer)).t;
    const peer_sig_pks: [][sodium.crypto_sign_PUBLICKEYBYTES]u8 = try allocator.alloc([sodium.crypto_sign_PUBLICKEYBYTES]u8, n);
    defer allocator.free(peer_sig_pks);
    const peer_noise_pks: [][sodium.crypto_scalarmult_BYTES]u8 = try allocator.alloc([sodium.crypto_scalarmult_BYTES]u8, n);
    defer allocator.free(peer_noise_pks);
    const noise_outs : []*tp_dkg.Noise_XK_session_t_s = try allocator.alloc(*tp_dkg.Noise_XK_session_t_s, n);
    defer allocator.free(noise_outs);
    const noise_ins : []*tp_dkg.Noise_XK_session_t_s = try allocator.alloc(*tp_dkg.Noise_XK_session_t_s, n);
    defer allocator.free(noise_ins);
    const ishares : [][toprf.TOPRF_Share_BYTES]u8 = try allocator.alloc([toprf.TOPRF_Share_BYTES]u8, n);
    defer allocator.free(ishares);
    const xshares : [][toprf.TOPRF_Share_BYTES]u8 = try allocator.alloc([toprf.TOPRF_Share_BYTES]u8, n);
    defer allocator.free(xshares);
    const commitments: [][sodium.crypto_core_ristretto255_BYTES]u8 = try allocator.alloc([sodium.crypto_core_ristretto255_BYTES]u8, n * t);
    defer allocator.free(commitments);
    const peer_complaints: []u16 = try allocator.alloc(u16, n * n);
    defer allocator.free(peer_complaints);
    const peer_my_complaints: []u8 = try allocator.alloc(u8, n);
    defer allocator.free(peer_my_complaints);
    const peer_last_ts: []u64 = try allocator.alloc(u64, n);
    defer allocator.free(peer_last_ts);

    tp_dkg.tpdkg_peer_set_bufs(@ptrCast(peer), @alignCast(@ptrCast(peer_sig_pks)), @alignCast(@ptrCast(peer_noise_pks)),
                               @alignCast(@ptrCast(noise_outs)), @alignCast(@ptrCast(noise_ins)),
                               @alignCast(@ptrCast(ishares)), @alignCast(@ptrCast(xshares)),
                               @alignCast(@ptrCast(commitments)),
                               @alignCast(@ptrCast(peer_complaints.ptr)), @alignCast(@ptrCast(peer_my_complaints.ptr)),
                               @ptrCast(peer_last_ts.ptr));

    while(tp_dkg.tpdkg_peer_not_done(@ptrCast(peer))!=0) {
        var msg : []u8 = try allocator.alloc(u8, tp_dkg.tpdkg_peer_input_size(@ptrCast(peer)));
        defer allocator.free(msg);
        if(msg.len > 0) {
            const msglen = try read_pkt(s, msg[0..msg.len]);
            if (msglen != msg.len) {
                fail(s, cfg);
            }
        }
        const cur_step = @as(*tp_dkg.TP_DKG_PeerState, @ptrCast(peer)).step;
        const resp_size = tp_dkg.tpdkg_peer_output_size(@ptrCast(peer));
        const resp : []u8 = try allocator.alloc(u8, resp_size);
        defer allocator.free(resp);
        const ret = tp_dkg.tpdkg_peer_next(@ptrCast(peer), msg.ptr, msg.len, resp.ptr, resp.len);
        if(0!=ret) {
            warn("TP DKG failed with {} in step {}.", .{ret, cur_step});
            tp_dkg.tpdkg_peer_free(@ptrCast(peer));
            fail(s, cfg);
        }
        if(resp.len>0) {
            const bw = write_pkt(s, resp) catch fail(s, cfg);
            if (bw != resp.len) fail(s, cfg);
            try s.flush();
        }
    }

    workaround.extract_share(@ptrCast(peer), share.ptr);
}

/// this op creates an oprf key, stores it with an associated pubkey
/// of the client, and updates a blob.
fn create(cfg: *const Config, s: anytype, req: *const Request) anyerror!void {
    const tdir = mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", req.id[0..]}) catch fail(s,cfg);
    defer allocator.free(tdir);
    if (utils.dir_exists(tdir)) fail(s,cfg);

    const key: []u8 = try s_allocator.alloc(u8, 33);
    defer s_allocator.free(key);
    key[0]=1;
    sodium.randombytes_buf(key[1..].ptr, key.len);

    var beta = [_]u8{0} ** 33;
    beta[0]=key[0];

    if (-1 == oprf.oprf_Evaluate(key[1..].ptr, &req.alpha, beta[1..].ptr)) fail(s, cfg);

    _ = try s.write(beta[0..]);
    try s.flush();

    var buf: [32 + RULE_SIZE + 64]u8 = undefined; // pubkey, rule, signature
    //# wait for auth signing pubkey and rules
    const msglen = try read_pkt(s, buf[0..buf.len]);
    if (msglen != buf.len) {
        fail(s, cfg);
    }

    const CreateResp = extern struct {
        pk: [32]u8 align(1), rule: [RULE_SIZE]u8 align(1), signature: [64]u8 align(1)
    };
    const resp: *CreateResp = @ptrCast(buf[0..]);

    const blob = verify_blob(buf[0..], resp.pk) catch fail(s, cfg);
    const rules = blob[32..];

    // 3rd phase
    // add user to host record
    update_blob(cfg, s) catch fail(s, cfg);

    if (!utils.dir_exists(cfg.datadir)) {
        posix.mkdir(cfg.datadir, 0o700) catch fail(s, cfg);
    }
    posix.mkdir(tdir, 0o700) catch fail(s, cfg);

    save_blob(cfg, req.id[0..], "pub", resp.pk[0..]) catch fail(s, cfg);
    save_blob(cfg, req.id[0..], "key", key) catch fail(s, cfg);
    save_blob(cfg, req.id[0..], "rules", rules) catch fail(s, cfg);

    _ = try s.write("ok");
    try s.flush();
}

fn create_dkg(cfg: *const Config, s: anytype, req: *const Request) anyerror!void {
    const tdir = mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", req.id[0..]}) catch fail(s,cfg);
    defer allocator.free(tdir);
    if (utils.dir_exists(tdir)) fail(s,cfg);

    var msg0 = mem.zeroes([tp_dkg.tpdkg_msg0_SIZE]u8);
    const msg0len = try s.read(msg0[0..]);
    if(msg0len != msg0.len) {
        fail(s, cfg);
    }

    const share = try s_allocator.alloc(u8, 33);
    defer s_allocator.free(share);
    try dkg(cfg, s, msg0[0..], share[0..]);
    if(DEBUG) {
        warn("[dkg] share ",.{});
        utils.hexdump(share[0..]);
    }

    var beta = [_]u8{0} ** 33;
    beta[0] = share[0];

    if (-1 == oprf.oprf_Evaluate(share[1..].ptr, &req.alpha, beta[1..].ptr)) fail(s, cfg);

    const betalen = try s.write(beta[0..]);
    try s.flush();
    if(betalen!=beta.len) fail(s,cfg);

    var buf: [32 + RULE_SIZE + 64]u8 = undefined; // pubkey, rule, signature
    //# wait for auth signing pubkey and rules
    const msglen = try read_pkt(s, buf[0..buf.len]);
    if (msglen != buf.len) {
        fail(s, cfg);
    }

    const CreateResp = extern struct {
        pk: [32]u8 align(1), rule: [RULE_SIZE]u8 align(1), signature: [64]u8 align(1)
    };
    const resp: *CreateResp = @ptrCast(buf[0..]);

    const blob = verify_blob(buf[0..], resp.pk) catch fail(s, cfg);
    const rules = blob[32..];

    // 3rd phase
    // add user to host record
    update_blob(cfg, s) catch fail(s, cfg);

    if (!utils.dir_exists(cfg.datadir)) {
        posix.mkdir(cfg.datadir, 0o700) catch fail(s, cfg);
    }
    posix.mkdir(tdir, 0o700) catch fail(s, cfg);

    save_blob(cfg, req.id[0..], "pub", resp.pk[0..]) catch fail(s, cfg);
    save_blob(cfg, req.id[0..], "key", share) catch fail(s, cfg);
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
    if (load_blob(s_allocator, cfg, req.id[0..], "key"[0..], 33)) |k| {
        key = k;
    } else |_| {
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
    } else |_| {
        bail = true;
    }

    //var beta: [32]u8 = undefined;
    var beta = [_]u8{0} ** 33;
    beta[0] = key[0];

    if (bail) fail(s, cfg);

    if (-1 == oprf.oprf_Evaluate(key[1..].ptr, &req.alpha, beta[1..].ptr)) fail(s, cfg);
    s_allocator.free(key); // sanitize

    var resp = try allocator.alloc(u8, beta.len + rules.len);
    defer allocator.free(resp);

    @memcpy(resp[0..beta.len], beta[0..]);
    @memcpy(resp[beta.len..], rules[0..]);

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

    var key = [_]u8{0} ** 33;
    if(0!=sodium.sodium_mlock(&key,key.len)) fail(s,cfg);
    sodium.randombytes_buf(key[1..].ptr, 32);
    key[0]=1;

    //var beta: [32]u8 = undefined;
    var beta = [_]u8{0} ** 33;
    beta[0]=key[0];

    if (-1 == oprf.oprf_Evaluate(key[1..].ptr, &alpha, &beta)) fail(s, cfg);

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

fn change_dkg(cfg: *const Config, s: anytype, req: *const Request) anyerror!void {
    auth(cfg, s, req) catch fail(s, cfg);

    var alpha: [32]u8 = undefined;
    // wait for alpha
    const msglen = try s.read(alpha[0..]);
    if (msglen != alpha.len) {
         fail(s, cfg);
    }

    var msg0 = mem.zeroes([tp_dkg.tpdkg_msg0_SIZE]u8);
    const msg0len = try s.read(msg0[0..]);
    if(msg0len != msg0.len) {
        fail(s, cfg);
    }

    const share = try s_allocator.alloc(u8, 33);
    defer s_allocator.free(share);
    try dkg(cfg, s, msg0[0..], share[0..]);

    var beta = [_]u8{0} ** 33;
    beta[0] = share[0];

    if (-1 == oprf.oprf_Evaluate(share[1..].ptr, &alpha, beta[1..].ptr)) fail(s, cfg);
    //var beta: [32]u8 = undefined;

    const betalen = try s.write(beta[0..]);
    try s.flush();
    if(betalen!=beta.len) fail(s,cfg);

    var signedpub: [32 + RULE_SIZE + 64]u8 = undefined; // pubkey, rules, sig
    const signedpublen = try s.read(signedpub[0..]);
    if(signedpublen != signedpub.len) fail(s,cfg);
    const pk = signedpub[0..32];
    _ = verify_blob(signedpub[0..], pk.*) catch fail(s, cfg);

    const rules = signedpub[32..32+RULE_SIZE];

    save_blob(cfg, req.id[0..], "new", share[0..]) catch fail(s, cfg);
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
    } else |_| {
        fail(s,cfg);
    }
    defer allocator.free(new_rules);
    var cur_rules: []u8 = undefined;
    if (load_blob(allocator, cfg, req.id[0..], "rules"[0..], RULE_SIZE)) |r| {
        cur_rules = r;
    } else |_| {
        fail(s,cfg);
    }
    defer allocator.free(cur_rules);

    // load the auth pub keys
    var new_pub: []u8 = undefined;
    const new_pubpath = try mem.concat(allocator, u8, &[_][]const u8{ "pub.", new[0..] });
    defer allocator.free(new_pubpath);
    if (load_blob(allocator, cfg, req.id[0..], new_pubpath, 32)) |r| {
        new_pub = r;
    } else |_| {
        fail(s,cfg);
    }
    defer allocator.free(new_pub);
    var cur_pub: []u8 = undefined;
    if (load_blob(allocator, cfg, req.id[0..], "pub"[0..], 32)) |r| {
        cur_pub = r;
    } else |_| {
        fail(s,cfg);
    }
    defer allocator.free(cur_pub);

    // and last the keys
    var new_key: []u8 = undefined;
    if (load_blob(s_allocator, cfg, req.id[0..], new[0..], 33)) |r| {
        new_key = r;
    } else |_| {
        fail(s,cfg);
    }
    var cur_key: []u8 = undefined;
    if (load_blob(s_allocator, cfg, req.id[0..], "key"[0..], 33)) |r| {
        cur_key = r;
    } else |_| {
        s_allocator.free(new_key);
        fail(s,cfg);
    }
    new_key[0]=cur_key[0];

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
    posix.unlink(nkpath) catch fail(s, cfg);
    allocator.free(nkpath);

    const nppath = try mem.concat(allocator, u8, &[_][]const u8{ path, "/", "pub.", new });
    posix.unlink(nppath) catch fail(s, cfg);
    allocator.free(nppath);

    const nrpath = try mem.concat(allocator, u8, &[_][]const u8{ path, "/", "rules.", new });
    posix.unlink(nrpath) catch fail(s, cfg);
    allocator.free(nrpath);

    // send ack
    _ = try s.write("ok");
    try s.flush();
}

/// this op returns a requested blob
fn read(cfg: *const Config, s: anytype, req: *const Request) anyerror!void {
    auth(cfg, s, req) catch fail(s, cfg);

    if (load_blob(allocator, cfg, req.id[0..], "blob", null)) |r| {
        _ = try s.write(r);
        allocator.free(r);
    } else |_| {
        _ = try s.write("");
    }
    try s.flush();
}
