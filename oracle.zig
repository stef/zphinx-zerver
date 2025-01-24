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
///    6    - the size of the rule itself
///   24    - the nonce for encryption
///   32/64 - the xor_mask for v1/v2 rules
///   16    - the auth tag
///------
/// + 78
const V1RULE_SIZE = 79;
const RULE_SIZE = V1RULE_SIZE + 32;

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
    /// decay ratelimit after rl_decay seconds
    rl_decay: i64,
    /// increase hardness after rl_threshold attempts if not decaying
    rl_threshold: u8,
    /// when checking freshness of puzzle solution, allow this extra
    /// gracetime in addition to the hardness max solution time
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
    Hardness{ .n = 65,  .k = 4, .timeout =  20    }, // 640KiB, ~0.04
    Hardness{ .n = 70,  .k = 4, .timeout =  40    }, // 1MiB, ~0.08
    Hardness{ .n = 75,  .k = 4, .timeout =  90    }, // 2MiB, ~0.2
    Hardness{ .n = 80,  .k = 4, .timeout =  160   }, // 5MiB, ~0.5
    Hardness{ .n = 85,  .k = 4, .timeout =  320   }, // 10MiB, ~0.9
    Hardness{ .n = 90,  .k = 4, .timeout =  800   }, // 20MiB, ~2.4
    Hardness{ .n = 95,  .k = 4, .timeout =  1600  }, // 40MiB, ~4.6
    Hardness{ .n = 100, .k = 4, .timeout =  3200  }, // 80MiB, ~7.8
    Hardness{ .n = 105, .k = 4, .timeout =  6400  }, // 160MiB, ~25
    Hardness{ .n = 110, .k = 4, .timeout =  12800 }, // 320MiB, ~57
    Hardness{ .n = 115, .k = 4, .timeout =  25600 }, // 640MiB, ~70
    Hardness{ .n = 120, .k = 4, .timeout =  51200 }, // 1GiB, ~109
};


/// the first byte of a request from a client marks the op
const ReqType = enum(u8) {
    CREATE = 0x00,              // 0000 0000
    READ = 0x33,                // 0011 0011
    UNDO = 0x55,                // 0101 0101
    GET = 0x66,                 // 0110 0110
    V1GET = 0x69,               // 0110 1001
    COMMIT = 0x99,              // 1001 1001
    CHANGE_DKG = 0xa0,
    CHANGE = 0xaa,              // 1010 1010
    CREATE_DKG = 0xf0,
    DELETE = 0xff,              // 1111 1111
    V1DELETE = 0xf9,            // 1111 1001
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
    warn("{} listening on {}\n", .{std.os.linux.getpid(), addr});

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
            log("new connection\n", .{}, "");
        } else |e| {
            if(e==error.WouldBlock) {
                while(true) {
                    const Status = if (builtin.link_libc) c_int else u32;
                    var status: Status = undefined;
                    const rc = posix.system.waitpid(-1, &status, posix.system.W.NOHANG);
                    if(rc>0) {
                        kids.remove(mem.asBytes(&rc));
                        log("removing kid {} from pool\n",.{rc}, "");
                    } else break;
                }
                continue;
            }
            unreachable;
        }

        while (kids.count() >= cfg.max_kids) {
            log("pool full, waiting for kid to die\n", .{}, "");
            const pid = posix.waitpid(-1, 0).pid;
            log("wait returned: {}\n", .{pid}, "");
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
                log("connection accepted\n", .{}, "");
                ratelimit(&cfg, &s) catch |err| {
                    if(err==error.WouldBlock or err==error.IO) {
                        log("timeout, abort.\n",.{}, "");
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
fn parse_req(s: anytype, msg: []u8) *Request {
    if(@as(ReqType, @enumFromInt(msg[0])) == ReqType.READ and msg.len == 33) {
        var req = allocator.create(Request) catch fail(s);
        req.op = ReqType.READ;
        req.has_alpha = false;
        _ = std.fmt.bufPrint(req.id[0..], "{x:0>64}", .{std.fmt.fmtSliceHexLower(msg[1..])}) catch fail(s);
        return req;
    }

    if (msg.len != 65) fail(s);

    const RawRequest = extern struct {
        op: ReqType align(1), id: [32]u8 align(1), alpha: [32]u8 align(1)
    };
    const rreq: *RawRequest = @ptrCast(msg[0..65]);

    var req = allocator.create(Request) catch fail(s);
    req.op = rreq.op;
    @memcpy(req.alpha[0..], rreq.alpha[0..]);
    _ = std.fmt.bufPrint(req.id[0..], "{x:0>64}", .{std.fmt.fmtSliceHexLower(rreq.id[0..])}) catch fail(s);
    return req;
}

fn log(comptime msg: []const u8, args: anytype, recid: []const u8) void {
    const pid = std.os.linux.getpid();
    warn("{} {} {s} ", .{pid, conn.address, recid});
    warn(msg, args);
}

fn ratelimit(cfg: *const Config, s: anytype) anyerror!void {
    log("ratelimit start\n", .{}, "");
    var op: [1]u8 = undefined;
    _ = s.read(op[0..]) catch |err| {
        if(err==ssl.BearError.UNSUPPORTED_VERSION) {
           log("unsupported TLS version. aborting.\n",.{}, "");
           try s.close();
           posix.exit(0);
        } else if(err==ssl.BearError.UNKNOWN_ERROR_582 or err==ssl.BearError.UNKNOWN_ERROR_552) {
           log("unknown TLS error: {}. aborting.\n",.{err}, "");
           try s.close();
           posix.exit(0);
        } else if(err==ssl.BearError.BAD_VERSION) {
           log("bad TLS version. aborting.\n",.{},"");
           try s.close();
           posix.exit(0);
        }
    };

    //log("ratelimit op {x}\n", .{op[0]}, "");

    switch (@as(ChallengeOp, @enumFromInt(op[0]))) {
        ChallengeOp.SPHINX_CREATE => {
            var req = [_]u8{0} ** 65;
            const reqlen = try s.read(req[1..]);
            if(reqlen+1 != req.len) {
                log("invalid create request. aborting.\n",.{}, "");
            }
            const request = parse_req(s, req[0..]);
            log("sphinx op create\n", .{}, &request.id);
            try handler(cfg, s, request);
        },
        ChallengeOp.SPHINX_DKG_CREATE => {
            var req = [_]u8{0} ** 65;
            const reqlen = try s.read(req[1..]);
            if(reqlen+1 != req.len) {
                log("invalid dkg create request. aborting.\n",.{}, "");
            }
            req[0] = op[0];
            const request = parse_req(s, req[0..]);
            log("sphinx op dkg create\n", .{}, &request.id);
            try handler(cfg, s, request);
        },
        ChallengeOp.CHALLENGE_CREATE => {
            //log("ratelimit op challenge\n", .{}, "");
            try create_challenge(cfg, s);
        },
        ChallengeOp.VERIFY => {
            //log("rl op solve\n", .{}, "");
            try verify_challenge(cfg, s);
        },
        _ => {
            log("invalid ratelimit op. aborting.\n",.{}, "");
        }
    }
    try s.close();
    posix.exit(0);
}

fn create_challenge(cfg: *const Config, s: anytype) anyerror!void {
    //log("create puzzle start\n", .{}, "");
    // read request
    var req = [_]u8{0} ** 65;
    var reqlen : usize = 0;
    _ = try s.read(req[0..1]);

    log("create_challenge for req op {x}.\n", .{req[0]}, "");

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
            log("\ncannot open {s}/key error: {}\n", .{ cfg.datadir, err }, "");
            fail(s);
        }
        key = try s_allocator.alloc(u8, 32);
        sodium.randombytes_buf(key.ptr, key.len);
        save_blob(cfg, "", "key", key) catch fail(s);
    }
    defer s_allocator.free(key);

    // assemble challenge
    var challenge : ChallengeRequest = undefined;
    const now = std.time.timestamp();
    challenge.ts = now;

    const request = parse_req(s, req[0..reqlen]);
    log("record id\n", .{}, request.id[0..]);
    // figure out n & k params and set them in challenge
    if (load_blob(s_allocator, cfg, request.id[0..], "difficulty"[0..], @sizeOf(RatelimitCTX))) |diff| {
        var ctx: *RatelimitCTX = @ptrCast(@alignCast(diff[0..]));
        var save: bool = false;
        //if (cfg.verbose) warn("rl ctx {}\n", .{ctx});
        if(ctx.level >= Difficulties.len) {
            // invalid rl context, punish hard
            log("invalid difficulty: {}\n", .{ ctx.level }, request.id[0..]);
            ctx.level = Difficulties.len - 1;
            ctx.count=0;
            save = true;
        } else if(now - cfg.rl_decay > ctx.ts and ctx.level>0) { // timestamp too long ago, let's decay
            const periods = @divTrunc((now - ctx.ts), cfg.rl_decay);
            if(ctx.level >= periods) {
                ctx.level = ctx.level - @as(u8, @intCast(periods));
            } else {
                ctx.level = 0;
            }
            ctx.count=0;
            save = true;
        }

        if(save) {
            ctx.ts = now;
            save_blob(cfg, request.id[0..], "difficulty"[0..], diff) catch fail(s);
        }

        log("rl difficulty: {}\n", .{ctx}, request.id[0..]);
        challenge.n=Difficulties[ctx.level].n;
        challenge.k=Difficulties[ctx.level].k;

        if(ctx.level > 0) {
           if(ctx.level < Difficulties.len / 2) {
               log("\x1b[38;5;196malert\x1b[38;5;253m: {} someones re-trying ({})\n", .{conn.address, ctx.level}, request.id[0..]);
           } else if((ctx.level > Difficulties.len / 2) and ctx.level < (Difficulties.len - 1)) {
               log("\x1b[38;5;196malert\x1b[38;5;253m: {} someones trying ({}) hard\n", .{conn.address, ctx.level}, request.id[0..]);
           } else {
               log("\x1b[38;5;196malert\x1b[38;5;253m: {} someones trying ({}/{}) really hard\n", .{conn.address, ctx.level, ctx.count}, request.id[0..]);
           }
        }

    } else |err| {
        if (err != error.FileNotFound) {
            log("cannot open {s}/{s}/difficulty error: {}\n", .{ cfg.datadir, request.id[0..], err }, request.id[0..]);
            fail(s);
        }
        challenge.n = Difficulties[0].n;
        challenge.k = Difficulties[0].k;
        var ctx = RatelimitCTX{
            .level = 0,
            .count = 0,
            .ts = now,
        };

        save_blob(cfg, request.id[0..], "difficulty"[0..], mem.asBytes(&ctx)[0..]) catch |err2| if (err2!=error.FileNotFound ) {
            log("cannot save {s}/{s}/difficulty error: {}\n", .{ cfg.datadir, request.id[0..], err }, request.id[0..]);
            fail(s);
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
    _ = s.write(mem.asBytes(&challenge)[0..]) catch fail(s);
}

fn verify_challenge(cfg: *const Config, s: anytype) anyerror!void {
    log("verify puzzle start\n", .{}, "");
    // first read challenge record
    var challenge : ChallengeRequest = undefined;
    const challenge_bytes = mem.asBytes(&challenge)[0..];
    const challenge_len = try s.read(challenge_bytes);
    if(challenge_len!=challenge_bytes.len) {
        log("challenge record to short {} != {}\n", .{challenge_len, challenge_bytes.len}, "");
        fail(s);
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
        log("cannot open {s}/key error: {}\n", .{ cfg.datadir, err }, "");
        fail(s);
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
        log("bad sig on challenge\n", .{}, "");
        fail(s);
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
        log("puzzle expired. reject\n",.{}, "");
        fail(s);
    }

    // valid challenge record, let's read the solution
    const solsize = equihash.solsize(challenge.n, challenge.k);
    var solution: []u8 = try allocator.alloc(u8, @as(usize, @intCast(solsize)));
    defer allocator.free(solution);
    const sollen = try s.read(solution[0..]);
    if(sollen!=solsize) {
        log("truncated solution\n",.{}, "");
        fail(s);
    }
    var seed: []u8 = try allocator.alloc(u8, challenge_len + reqlen);
    @memcpy(seed[0..challenge_len], challenge_bytes);
    @memcpy(seed[challenge_len..challenge_len+reqlen], req[0..reqlen]);
    if(0==equihash.verify(challenge.n, challenge.k, seed.ptr, seed.len, solution.ptr, solsize)) {
        log("bad challenge solution\n",.{}, "");
        fail(s);
    }

    // call handler with request
    const request = parse_req(s, req[0..reqlen]);

    if (load_blob(s_allocator, cfg, request.id[0..], "difficulty"[0..], @sizeOf(RatelimitCTX))) |diff| {
        var ctx: *RatelimitCTX = @ptrCast(@alignCast(diff[0..]));
        if(ctx.count >= cfg.rl_threshold and (ctx.level < Difficulties.len - 1)) {
            ctx.count=0;
            ctx.level+=1;
        } else {
            ctx.count+=1;
        }
        ctx.ts = now;
        save_blob(cfg, request.id[0..], "difficulty"[0..], diff) catch fail(s);
    } else |err| {
        log("cannot open {s}/{s}/difficulty, error: {}\n", .{ cfg.datadir, request.id[0..], err }, request.id[0..]);
        fail(s);
    }

    return handler(cfg, s, request);
}

/// dispatcher for incoming client requests
/// parses incoming request and calls appropriate op
fn handler(cfg: *const Config, s: anytype, req : *const Request) anyerror!void {
    log("sphinx op {}\n", .{req.op}, &req.id);
    switch (req.op) {
        ReqType.CREATE => {
            try create(cfg, s, req);
        },
        ReqType.CREATE_DKG => {
            try create_dkg(cfg, s, req);
        },
        ReqType.GET => {
            try get(cfg, s, req, false);
        },
        ReqType.V1GET => {
            try get(cfg, s, req, true);
        },
        ReqType.CHANGE => {
            try change(cfg, s, req);
        },
        ReqType.CHANGE_DKG => {
            try change_dkg(cfg, s, req);
        },
        ReqType.DELETE => {
            try delete(cfg, s, req, false);
        },
        ReqType.V1DELETE => {
            try delete(cfg, s, req, true);
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
fn fail(s: anytype) noreturn {
    @setCold(true);
    log("fail\n", .{}, "");
    if(DEBUG) {
        warn("frame addr stack trace ->\n", .{});
        std.debug.dumpCurrentStackTrace(@frameAddress());
        warn("return addr stack trace ->\n", .{});
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

fn ssl_file_missing(path: []const u8) noreturn {
    warn("The SSL key at {s} is not a readable file. Make sure this is a proper ssl key.\n", .{path});
    warn("Our GettingStarted document gives simple example of how to do so.\n", .{});
    warn("Check out https://sphinx.pm/server_install.html .\n", .{});
    warn("Aborting.\n", .{});
    posix.exit(1);
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

    var env = try std.process.getEnvMap(allocator);
    defer env.deinit();
    cfg.verbose = std.mem.eql(u8, env.get("ORACLE_VERBOSE") orelse "false","true");
    cfg.address = if(env.get("ORACLE_ADDRESS")) |v| try allocator.dupe(u8, v) else cfg.address;
    cfg.port = if(env.get("ORACLE_PORT")) |v| try std.fmt.parseInt(u16, v, 10) else cfg.port;
    cfg.timeout = if(env.get("ORACLE_TIMEOUT")) |v| try std.fmt.parseInt(u16, v, 10) else cfg.timeout;
    cfg.datadir = if(env.get("ORACLE_DATADIR")) |v| expandpath(v) else cfg.datadir;
    cfg.max_kids = if(env.get("ORACLE_MAX_KIDS")) |v| try std.fmt.parseInt(u16, v, 10) else cfg.max_kids;
    cfg.ssl_key = if(env.get("ORACLE_SSL_KEY")) |v| expandpath(v) else cfg.ssl_key;
    cfg.ssl_cert = if(env.get("ORACLE_SSL_CERT")) |v| expandpath(v) else cfg.ssl_cert;
    cfg.ltsigkey = if(env.get("ORACLE_LTSIGKEY")) |v| expandpath(v) else cfg.ltsigkey;
    cfg.ts_epsilon = if(env.get("ORACLE_TS_EPSILON")) |v| try std.fmt.parseInt(u64, v, 10) else cfg.ts_epsilon;
    cfg.rl_decay = if(env.get("ORACLE_RL_DECAY")) |v| try std.fmt.parseInt(i64, v, 10) else cfg.rl_decay;
    cfg.rl_threshold = if(env.get("ORACLE_RL_THRESHOLD")) |v| try std.fmt.parseInt(u8, v, 10) else cfg.rl_threshold;
    cfg.rl_gracetime = if(env.get("ORACLE_RL_GRACETIME")) |v| try std.fmt.parseInt(u16, v, 10) else cfg.rl_gracetime;

    if(cfg.rl_decay<1) {
        warn("rl_decay must be positive number, please check your config.\n",.{});
        return LoadCfgError.InvalidRLDecay;
    }

    std.fs.cwd().access(cfg.ltsigkey, .{}) catch {
        if(std.os.argv.len == 2 and std.mem.eql(u8,std.mem.span(std.os.argv[1]), "init")) {
            // create lt sig key pair
            const sk = try s_allocator.alloc(u8, sodium.crypto_sign_SECRETKEYBYTES);
            defer s_allocator.free(sk);
            const pk = try allocator.alloc(u8, sodium.crypto_sign_PUBLICKEYBYTES);
            defer allocator.free(pk);
            if(0!=sodium.crypto_sign_keypair(pk.ptr, sk.ptr)) {
                return SphinxError.Error;
            }

            if (posix.open(cfg.ltsigkey, .{.ACCMODE=.WRONLY, .CREAT = true }, 0o600)) |f| {
                defer posix.close(f);
                const w = try posix.write(f, sk);
                if (w != sk.len) return SphinxError.Error;
            } else |err| {
                warn("failed to save ltsigkey: {}\n", .{err});
                return SphinxError.Error;
            }

            const pubpath = try mem.concat(allocator, u8, &[_][]const u8{ cfg.ltsigkey, ".pub" });
            defer allocator.free(pubpath);
            if (posix.open(pubpath, .{.ACCMODE=.WRONLY, .CREAT = true }, 0o666)) |f| {
                defer posix.close(f);
                const w = try posix.write(f, pk);
                if (w != pk.len) return SphinxError.Error;
            } else |err| {
                warn("failed to save ltsigkey: {}\n", .{err});
                return SphinxError.Error;
            }
            warn("successfully created long-term signature key pair at:\n", .{});
            warn("{s}\n", .{cfg.ltsigkey});
            warn("and the public key - which you should make available to all clients -, is at:\n", .{});
            warn("{s}.pub\n", .{cfg.ltsigkey});

            const b64pk : []u8 = try allocator.alloc(u8, std.base64.standard.Encoder.calcSize(pk[0..].len));
            defer allocator.free(b64pk);
            _ = std.base64.standard.Encoder.encode(b64pk, pk);
            warn("The following is the base64 encoded public key that you can also share:\n{s}\n", .{b64pk});
        } else {
            warn("Long-term signing key at {s} is not readable.\n", .{cfg.ltsigkey});
            warn("You can generate one by running: {s} init\n", .{std.mem.span(std.os.argv[0])});
            posix.exit(1);
        }
    };

    std.fs.cwd().access(cfg.ssl_key, .{}) catch {
        ssl_file_missing(cfg.ssl_key);
    };
    std.fs.cwd().access(cfg.ssl_cert, .{}) catch {
        ssl_file_missing(cfg.ssl_cert);
    };

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
                log("{s} has not expected size of {}B instead has {}B\n", .{ path, size, fsize }, "");
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
        log("saveblob open({s}) failed {}\n", .{fpath, err}, "");
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
    if (idlen != signedid.len) fail(s);

    //if(cfg.verbose) warn("ub: {x:0>192}\n", .{signedid});

    const idvec: @Vector(32, u8) = signedid[0..32].*;
    if(@reduce(std.builtin.ReduceOp.Or, idvec) == 0) {
        log("skipping updating blob\n", .{}, "");
        return;
    }

    const hexid = try tohexid(signedid[0..32].*);
    defer allocator.free(hexid);

    log("updating blob\n", .{}, hexid);

    var blob: []u8 = undefined;
    var new = false;

    var pk: [32]u8 = undefined;
    if (load_blob(allocator, cfg, hexid[0..], "pub"[0..], 32)) |k| {
        pk = k[0..32].*;
        // verify sig on id
        _ = verify_blob(signedid[0..], pk) catch fail(s);

        if (load_blob(allocator, cfg, hexid[0..], "blob"[0..], null)) |b| {
            blob = b;
        } else |err| {
            if (err != error.FileNotFound) {
                log("cannot open {s}/{s}/blob error: {}\n", .{ cfg.datadir, hexid, err }, hexid);
                fail(s);
            }
            log("user blob authkey fund, but no blob for id: {s}\n", .{hexid}, hexid);
            fail(s);
        }
    } else |err| {
        if (err != error.FileNotFound) {
            log("cannot open {s}/{s}/blob error: {}\n", .{ cfg.datadir, hexid, err }, hexid);
            fail(s);
        }
        // ensure that the blob record directory also doesn't exist
        const tdir = try mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", hexid });
        defer allocator.free(tdir);
        if (utils.dir_exists(tdir)) {
            log("user blob authkey not found, but dir exists: {s}/{s}\n", .{cfg.datadir, hexid}, hexid);
            fail(s);
        }

        blob = try allocator.alloc(u8, 2);
        @memset(blob, 0);
        new = true;
        // fake pubkey
        //pk = try allocator.alloc(u8, 32);
        //sodium.randombytes_buf(pk[0..].ptr, pk.len);
    }

    const bw = write_pkt(s, blob) catch fail(s);
    allocator.free(blob);
    if (bw != blob.len) {
        log("truncated write of blob sent only {} out of {}\n", .{bw, blob.len}, hexid);
        fail(s);
    }
    try s.flush();

    if (new) {
        var buf = [_]u8{0} ** (2 + 32 + 64 + 65536);
        // read pubkey
        const pklen = try s.read(buf[0..32]);
        if (pklen != 32) {
            log("failed to read pubkey, short read, only {} bytes\n", .{pklen}, hexid);
            fail(s);
        }
        pk = buf[0..32].*;

        // read blob size
        const x = s.read(buf[32..34]) catch |err| {
            log("error reading blob size: {}", .{err}, hexid);
            fail(s);
        };
        if (x != 2) fail(s);
        const bloblen = std.mem.readInt(u16, buf[32..34], std.builtin.Endian.big);
        // read blob
        const end = 34 + @as(u17,bloblen) + 64;
        const recvd = read_pkt(s, buf[34..end]) catch |err| {
            log("error reading blob: {}", .{err}, hexid);
            fail(s);
        };
        if(recvd != end - 34) {
            log("received {} instead expected size of blob ({})\n", .{recvd, end - 34}, hexid);
            fail(s);
        }
        const msg = buf[0 .. end];
        const tmp = verify_blob(msg, pk) catch |err| {
            log("failed to verify blob: {}\n", .{err}, hexid);
            fail(s);
        };
        const new_blob = tmp[32 .. end - 64];
        if (!utils.dir_exists(cfg.datadir)) {
            posix.mkdir(cfg.datadir, 0o700) catch |err| {
                log("failed to create {s}, error: {}\n", .{cfg.datadir, err}, hexid);
                fail(s);
            };
        }

        const tdir = try mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", hexid });
        defer allocator.free(tdir);

        if (!utils.dir_exists(tdir)) {
            posix.mkdir(tdir, 0o700) catch |err| {
                log("failed to create {s}, error: {}\n", .{tdir, err}, hexid);
                fail(s);
            };
        }
        save_blob(cfg, hexid[0..], "pub", pk[0..]) catch |err| {
            log("failed to save pubkey: {}\n",.{err},hexid);
            fail(s);
        };
        save_blob(cfg, hexid[0..], "blob", new_blob) catch |err| {
            log("failed to save blob: {}\n",.{err},hexid);
            fail(s);
        };
    } else {
        // read pubkey
        var buf = [_]u8{0} ** (2 + 64 + 65536);
        // read blob size
        const x = s.read(buf[0..2]) catch |err| {
            log("error reading blob size: {}", .{err}, hexid);
            fail(s);
        };
        if (x != 2) fail(s);
        const bloblen = std.mem.readInt(u16, buf[0..2], std.builtin.Endian.big);
        const end = 2 + @as(u17,bloblen) + 64;
        // read blob
        const recvd = read_pkt(s, buf[2..end]) catch |err| {
            log("error reading blob: {}", .{err}, hexid);
            fail(s);
        };
        if(recvd != end - 2) {
            log("received {} instead expected size of blob ({})\n", .{recvd, end - 2}, hexid);
            fail(s);
        }
        const msg = buf[0 .. end];
        const tmp = verify_blob(msg, pk[0..32].*) catch |err| {
            log("failed to verify blob: {}\n", .{err}, hexid);
            fail(s);
        };
        const new_blob = tmp[0 .. end - 64];
        if(new_blob.len > 43) {
            save_blob(cfg, hexid[0..], "blob", new_blob) catch |err| {
                log("failed to save blob: {}\n",.{err},hexid);
                fail(s);
            };
        } else if(new_blob.len == 43) {
            const path = try mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", hexid[0..] });
            defer allocator.free(path);
            std.fs.cwd().deleteTree(path) catch |err| {
                log("failed to delete empty userblob record: {}\n",.{err},hexid);
                fail(s);
            };
        } else unreachable;
    }
}

/// auth is used in all (but create and get) operations it evaluates
/// the oprf, sends back beta and a nonce, which needs to be signed
/// correctly to authorize whatever operation follows. the pubkey for
/// the signature is stored in the directory indicated by the ID in
/// the initial request from the client.
fn auth(cfg: *const Config, s: anytype, req: *const Request, isv1: bool) anyerror!void {
    var pk: []u8 = undefined;
    if (load_blob(allocator, cfg, req.id[0..], "pub"[0..], 32)) |k| {
        pk = k;
    } else |err| {
        log("[auth] failed to load pubkey: {}\n",.{err},req.id[0..]);
        fail(s);
    }

    var resp : []u8 = undefined;
    if (load_blob(s_allocator, cfg, req.id[0..], "key"[0..], if(!isv1) 33 else 32)) |k| {
        resp = try allocator.alloc(u8, if(!isv1) 65 else 64);

        resp[0]=k[0];
        if(!isv1) {
            if (-1 == oprf.oprf_Evaluate(k[1..33].ptr, &req.alpha, resp[1..33].ptr)) {
                log("invalid alpha, it is not on the curve\n", .{}, req.id[0..]);
                fail(s);
            }
        } else {
            if (0 == sodium.crypto_core_ristretto255_is_valid_point(&req.alpha)) {
                s_allocator.free(k); // sanitize
                log("invalid alpha, it is not on the curve\n", .{}, req.id[0..]);
                fail(s);
            }
            if(0!=sodium.crypto_scalarmult_ristretto255(resp[0..32].ptr, k.ptr, &req.alpha)) {
                s_allocator.free(k); // sanitize
                log("failed to compute beta = alpha * k\n", .{}, req.id[0..]);
                fail(s);
            }
        }

        s_allocator.free(k);

        sodium.randombytes_buf(resp[(if(!isv1) 33 else 32)..].ptr, 32); // nonce to sign
    } else |_| {
        log("failed to load key, faking response\n", .{}, req.id[0..]);
        resp = try allocator.alloc(u8, 32);
        sodium.randombytes_buf(resp[0..].ptr, resp.len); // nonce to sign
    }
    defer allocator.free(resp);

    const rlen = s.write(resp[0..]) catch |err| {
        log("failed to write auth response: {}\n", .{err}, req.id[0..]);
        return err;
    };
    s.flush() catch |err| {
        log("failed to flush auth response: {}\n", .{err}, req.id[0..]);
        return err;
    };
    if (rlen != resp.len) {
        log("short write of auth response, only {} instead of {} written.\n", .{rlen, resp.len}, req.id[0..]);
        fail(s);
    }
    log("[auth] sent ",.{}, req.id[0..]);
    if(cfg.verbose) {
        utils.hexdump(resp[0..]);
    } else {
        warn("\n",.{});
    }
    var sig = [_]u8{0} ** 64;
    if (s.read(sig[0..sig.len])) |siglen| {
        if (siglen != sig.len) fail(s);
    } else |e| {
        log("error reading sig: {}\n", .{e}, req.id[0..]);
        fail(s);
    }
    if(cfg.verbose) {
        log("[auth] sig ",.{}, req.id[0..]);
        utils.hexdump(sig[0..]);
    }
    if (0 != sodium.crypto_sign_verify_detached(&sig, resp[(resp.len - 32)..].ptr, 32, pk[0..].ptr)) {
        log("bad sig\n", .{}, req.id[0..]);
        log("pk: ",.{}, req.id[0..]);
        utils.hexdump(pk);
        fail(s);
    }

    _ = s.write("\x00\x04auth") catch |err| {
        log("failed to write auth:ok message: {}\n", .{err}, req.id[0..]);
        return err;
    };
    _ = s.flush() catch |err| {
        log("failed to write auth:ok message: {}\n", .{err}, req.id[0..]);
        return err;
    };
}

fn dkg(cfg: *const Config, s: anytype, msg0: []const u8, share: []u8) anyerror!void {
    const ltsigkey: []u8 = try s_allocator.alloc(u8, sodium.crypto_sign_SECRETKEYBYTES);
    defer s_allocator.free(ltsigkey);

    if (posix.open(cfg.ltsigkey, .{.ACCMODE = .RDONLY }, 0)) |f| {
        defer posix.close(f);
        const rs = try posix.read(f, ltsigkey);
        if (rs != ltsigkey.len) {
            log("corrupted {s} size: {}\n", .{ cfg.ltsigkey, rs }, "");
            fail(s);
        }
    } else |err| {
        if (err != error.FileNotFound) {
            log("cannot open {s} error: {}\n", .{ cfg.ltsigkey, err }, "");
            fail(s);
        }
        log("no ltsigkey found at : {s}\n", .{cfg.ltsigkey}, "");
        fail(s);
    }


    var peer = workaround.new_peerstate();
    defer workaround.del_peerstate(@ptrCast(&peer));

    const retsp = tp_dkg.tpdkg_start_peer(@ptrCast(peer), cfg.ts_epsilon, ltsigkey.ptr, @ptrCast(msg0.ptr));
    if(retsp!=0) {
        log("failed to start tp-dkg peer (error code: {})\n", .{retsp}, "");
        fail(s);
    }
    const n = @as(*tp_dkg.TP_DKG_PeerState, @ptrCast(peer)).n;
    const t = @as(*tp_dkg.TP_DKG_PeerState, @ptrCast(peer)).t;
    log("starting dkg(n={}, t={})\n", .{n, t}, "");
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
        const cur_step = @as(*tp_dkg.TP_DKG_PeerState, @ptrCast(peer)).step;
        if(msg.len > 0) {
            const msglen = read_pkt(s, msg[0..msg.len]) catch |err| {
                log("failed to read step{} message from TP: {}\n", .{cur_step, err}, "");
                return err;
            };
            if (msglen != msg.len) {
                log("incorrect length of message step{} message from TP: expected: {}B, received {}B\n", .{cur_step, msg.len, msglen}, "");
                fail(s);
            }
        }
        const resp_size = tp_dkg.tpdkg_peer_output_size(@ptrCast(peer));
        const resp : []u8 = try allocator.alloc(u8, resp_size);
        defer allocator.free(resp);
        const ret = tp_dkg.tpdkg_peer_next(@ptrCast(peer), msg.ptr, msg.len, resp.ptr, resp.len);
        if(0!=ret) {
            log("TP DKG failed with {} in step {}.", .{ret, cur_step}, "");
            tp_dkg.tpdkg_peer_free(@ptrCast(peer));
            fail(s);
        }
        if(resp.len>0) {
            const bw = write_pkt(s, resp) catch |err| {
                log("failed to write response in step {} to TP: {}\n", .{cur_step, err}, "");
                fail(s);
            };
            if (bw != resp.len) {
                log("incorrect length of message step{} message to TP: expected: {}B, received {}B\n", .{cur_step, resp.len, bw}, "");
                fail(s);
            }
            try s.flush();
        }
    }

    workaround.extract_share(@ptrCast(peer), share.ptr);
    log("dkg success\n", .{}, "");
}

/// this op creates an oprf key, stores it with an associated pubkey
/// of the client, and updates a blob.
fn create(cfg: *const Config, s: anytype, req: *const Request) anyerror!void {
    const tdir = mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", req.id[0..]}) catch fail(s);
    defer allocator.free(tdir);
    if (utils.dir_exists(tdir)) {
        log("attempted to create a record, that already exists\n", .{}, req.id[0..]);
        fail(s);
    }

    const key: []u8 = try s_allocator.alloc(u8, 33);
    defer s_allocator.free(key);
    key[0]=1;
    sodium.randombytes_buf(key[1..].ptr, key.len);

    var beta = [_]u8{0} ** 33;
    beta[0]=key[0];

    if (-1 == oprf.oprf_Evaluate(key[1..].ptr, &req.alpha, beta[1..].ptr)) {
        log("failed to calculate beta = alpha * k\n", .{}, req.id[0..]);
        fail(s);
    }

    _ = s.write(beta[0..]) catch |err| {
        log("failed to send beta: {}\n", .{err}, req.id[0..]);
        return err;
    };
    s.flush() catch |err| {
        log("failed to flush beta: {}\n", .{err}, req.id[0..]);
        return err;
    };

    var buf: [32 + RULE_SIZE + 64]u8 = undefined; // pubkey, rule, signature
    //# wait for auth signing pubkey and rules
    const msglen = try read_pkt(s, buf[0..buf.len]);
    if (msglen != buf.len) {
        log("failed to receive record only {}B instead of the expected {}B\n", .{msglen, buf.len}, req.id[0..]);
        fail(s);
    }

    const CreateResp = extern struct {
        pk: [32]u8 align(1), rule: [RULE_SIZE]u8 align(1), signature: [64]u8 align(1)
    };
    const resp: *CreateResp = @ptrCast(buf[0..]);

    const blob = verify_blob(buf[0..], resp.pk) catch |err| {
        log("failed to verify blob: {}\n", .{err}, req.id[0..]);
        fail(s);
    };
    const rules = blob[32..];

    // 3rd phase
    // add user to host record
    update_blob(cfg, s) catch |err| {
        log("failed to add user to user list blob: {}\n", .{err}, req.id[0..]);
        fail(s);
    };

    if (!utils.dir_exists(cfg.datadir)) {
        posix.mkdir(cfg.datadir, 0o700) catch |err| {
            log("failed to create {s}, error: {}\n", .{cfg.datadir, err}, req.id[0..]);
            fail(s);
        };
    }
    posix.mkdir(tdir, 0o700) catch |err| {
        log("failed to create {s}, error: {}\n", .{tdir, err}, req.id[0..]);
        fail(s);
    };

    save_blob(cfg, req.id[0..], "pub", resp.pk[0..]) catch |err| {
            log("failed to save pubkey: {}\n",.{err},req.id[0..]);
            fail(s);
        };

    save_blob(cfg, req.id[0..], "key", key) catch |err| {
            log("failed to save key: {}\n",.{err},req.id[0..]);
            fail(s);
        };

    save_blob(cfg, req.id[0..], "rules", rules) catch |err| {
            log("failed to save rules: {}\n",.{err},req.id[0..]);
            fail(s);
        };

    _ = s.write("ok") catch |err| {
        log("failed to write confirmation of create: {}\n", .{err}, req.id[0..]);
        return err;
    };
    s.flush() catch |err| {
        log("failed to flush confirmation of create: {}\n", .{err}, req.id[0..]);
        return err;
    };
    log("create successful\n", .{}, req.id[0..]);
}

fn create_dkg(cfg: *const Config, s: anytype, req: *const Request) anyerror!void {
    const tdir = mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", req.id[0..]}) catch fail(s);
    defer allocator.free(tdir);
    if (utils.dir_exists(tdir)) {
        log("attempted to create a record, that already exists\n", .{}, req.id[0..]);
        fail(s);
    }
    log("running dkg for create op\n", .{}, req.id[0..]);

    var msg0 = mem.zeroes([tp_dkg.tpdkg_msg0_SIZE]u8);
    const msg0len = s.read(msg0[0..]) catch |err| {
        log("failed to read initial dkg message: {}\n", .{err}, req.id[0..]);
        return err;
    };
    if(msg0len != msg0.len) {
        log("dkg msg0 is only {} B instead of the expected {} B\n", .{msg0len, msg0.len}, req.id[0..]);
        fail(s);
    }

    const share = try s_allocator.alloc(u8, 33);
    defer s_allocator.free(share);
    dkg(cfg, s, msg0[0..], share[0..]) catch |err| {
        log("dkg failed: {}\n", .{err}, req.id[0..]);
        return err;
    };
    if(DEBUG) {
        log("[dkg] share ",.{}, req.id[0..]);
        utils.hexdump(share[0..]);
    }

    var beta = [_]u8{0} ** 33;
    beta[0] = share[0];

    if (-1 == oprf.oprf_Evaluate(share[1..].ptr, &req.alpha, beta[1..].ptr)) {
        log("failed to calculate beta = alpha * k\n", .{}, req.id[0..]);
        fail(s);
    }

    const betalen = s.write(beta[0..]) catch |err| {
        log("failed to send beta: {}\n", .{err}, req.id[0..]);
        return err;
    };
    s.flush() catch |err| {
        log("failed to flush beta: {}\n", .{err}, req.id[0..]);
        return err;
    };
    if(betalen!=beta.len) {
        log("only sent {} B of beta instead of the expected {} B\n", .{betalen, beta.len}, req.id[0..]);
        fail(s);
    }

    var buf: [32 + RULE_SIZE + 64]u8 = undefined; // pubkey, rule, signature
    //# wait for auth signing pubkey and rules
    const msglen = try read_pkt(s, buf[0..buf.len]);
    if (msglen != buf.len) {
        log("failed to receive record only {}B instead of the expected {}B\n", .{msglen, buf.len}, req.id[0..]);
        fail(s);
    }

    const CreateResp = extern struct {
        pk: [32]u8 align(1), rule: [RULE_SIZE]u8 align(1), signature: [64]u8 align(1)
    };
    const resp: *CreateResp = @ptrCast(buf[0..]);

    const blob = verify_blob(buf[0..], resp.pk) catch |err| {
        log("failed to verify blob: {}\n", .{err}, req.id[0..]);
        fail(s);
    };
    const rules = blob[32..];

    // 3rd phase
    // add user to host record
    update_blob(cfg, s) catch |err| {
        log("failed to add user to user list blob: {}\n", .{err}, req.id[0..]);
        fail(s);
    };

    if (!utils.dir_exists(cfg.datadir)) {
        posix.mkdir(cfg.datadir, 0o700) catch |err| {
            log("failed to create {s}, error: {}\n", .{cfg.datadir, err}, req.id[0..]);
            fail(s);
        };
    }
    posix.mkdir(tdir, 0o700) catch |err| {
        log("failed to create {s}, error: {}\n", .{tdir, err}, req.id[0..]);
        fail(s);
    };

    save_blob(cfg, req.id[0..], "pub", resp.pk[0..]) catch |err| {
        log("failed to save pubkey: {}\n",.{err},req.id[0..]);
        fail(s);
    };
    save_blob(cfg, req.id[0..], "key", share) catch |err| {
        log("failed to save share: {}\n",.{err},req.id[0..]);
        fail(s);
    };
    save_blob(cfg, req.id[0..], "rules", rules) catch |err| {
        log("failed to save rules: {}\n",.{err},req.id[0..]);
        fail(s);
    };

    _ = s.write("ok") catch |err| {
        log("failed to write confirmation of dkg create: {}\n", .{err}, req.id[0..]);
        return err;
    };
    s.flush() catch |err| {
        log("failed to flush confirmation of dkg create: {}\n", .{err}, req.id[0..]);
        return err;
    };
    log("dkg create successful\n", .{}, req.id[0..]);
}

/// this function evaluates the oprf and sends back beta
fn get(cfg: *const Config, s: anytype, req: *const Request, isv1: bool) anyerror!void {
    const ksize: u8 = if (! isv1) 33 else 32;

    var key: []u8 = undefined;
    //# 1st step OPRF with a new seed
    //# this might be if the user already has stored a blob for this id
    //# and now also wants a sphinx rwd
    if (load_blob(s_allocator, cfg, req.id[0..], "key"[0..], ksize)) |k| {
        key = k;
    } else |err| {
        log("couldn't load key: {}\n", .{err}, req.id[0..]);
        // todo?
        //key = try s_allocator.alloc(u8, 32);
        // todo should actually be always the same for repeated alphas
        // possibly use an hmac to calculate this. but that introduces a timing side chan....
        //sodium.randombytes_buf(&key, key.len);
        fail(s);
    }

    var rules: []u8 = undefined;
    if (load_blob(allocator, cfg, req.id[0..], "rules"[0..], null)) |r| {
        rules = r;
    } else |err| {
        log("couldn't load rules: {}\n", .{err}, req.id[0..]);
        fail(s);
    }

    var beta = try s_allocator.alloc(u8, ksize);
    defer s_allocator.free(beta);
    if(!isv1) beta[0] = key[0];

    if(!isv1) {
        if (-1 == oprf.oprf_Evaluate(key[1..].ptr, &req.alpha, beta[1..].ptr)) {
            log("failed to calculate beta = alpha * k\n", .{}, req.id[0..]);
            s_allocator.free(key); // sanitize
            fail(s);
        }
    } else {
        if (0 == sodium.crypto_core_ristretto255_is_valid_point(&req.alpha)) {
            log("invalid alpha, it is not on the curve\n", .{}, req.id[0..]);
            s_allocator.free(key); // sanitize
            fail(s);
        }
        if(0!=sodium.crypto_scalarmult_ristretto255(beta[0..].ptr, key.ptr, &req.alpha)) {
            log("failed to compute beta = alpha * k\n", .{}, req.id[0..]);
            s_allocator.free(key); // sanitize
            fail(s);
        }
    }
    s_allocator.free(key); // sanitize

    var resp = try allocator.alloc(u8, beta.len + rules.len);
    defer allocator.free(resp);

    @memcpy(resp[0..beta.len], beta[0..]);
    @memcpy(resp[beta.len..], rules[0..]);

    allocator.free(rules);

    _ = s.write(resp[0..]) catch |err| {
        log("failed to write response: {}\n", .{err}, req.id[0..]);
        return err;
    };
    s.flush() catch |err| {
        log("failed to flush response: {}\n", .{err}, req.id[0..]);
        return err;
    };
    log("get successful\n", .{}, req.id[0..]);
}

/// this op creates a new oprf key under the id, but stores it as "new", it must be "commited" to be set active
fn change(cfg: *const Config, s: anytype, req: *const Request) anyerror!void {
    auth(cfg, s, req, false) catch |err| {
        log("failed to auth for change op: {}\n", .{err}, req.id[0..]);
        fail(s);
    };

    var alpha: [32]u8 = undefined;
    // wait for alpha
    const msglen = s.read(alpha[0..]) catch |err| {
        log("failed to read alpha for change op: {}\n", .{err}, req.id[0..]);
        return err;
    };
    if (msglen != alpha.len) {
        log("read only {} B while receiving alpha, expected {} B\n", .{msglen, alpha.len}, req.id[0..]);
        fail(s);
    }

    var key = [_]u8{0} ** 33;
    if(0!=sodium.sodium_mlock(&key,key.len)) {
        log("failed to mlock key\n", .{}, req.id[0..]);
        fail(s);
    }
    sodium.randombytes_buf(key[1..].ptr, 32);
    key[0]=1;

    //var beta: [32]u8 = undefined;
    var beta = [_]u8{0} ** 33;
    beta[0]=key[0];

    if (-1 == oprf.oprf_Evaluate(key[1..].ptr, &alpha, beta[1..].ptr)) {
        log("invalid alpha, it is not on the curve\n", .{}, req.id[0..]);
        fail(s);
    }

    const betalen = s.write(beta[0..]) catch |err| {
        log("failed to send beta: {}\n", .{err}, req.id[0..]);
        return err;
    };
    s.flush() catch |err| {
        log("failed to flush beta: {}\n", .{err}, req.id[0..]);
        return err;
    };
    if(betalen!=beta.len) {
        log("only sent {} B of beta instead of the expected {} B\n", .{betalen, beta.len}, req.id[0..]);
        fail(s);
    }

    var signedpub: [32 + RULE_SIZE + 64]u8 = undefined; // pubkey, rules, sig
    const signedpublen = s.read(signedpub[0..]) catch |err| {
        log("failed to read signed pubkey: {}\n", .{err}, req.id[0..]);
        return err;
    };
    if(signedpublen != signedpub.len) {
        log("while receiving signed pubkey received only {} B, while expecting {} B\n", .{signedpublen, signedpub.len}, req.id[0..]);
        fail(s);
    }
    const pk = signedpub[0..32];
    _ = verify_blob(signedpub[0..], pk.*) catch |err| {
        log("failed to verify blob: {}\n", .{err}, req.id[0..]);
        fail(s);
    };

    const rules = signedpub[32..32+RULE_SIZE];

    save_blob(cfg, req.id[0..], "new", key[0..]) catch |err| {
        log("failed to save new key: {}\n",.{err},req.id[0..]);
        fail(s);
    };
    _ = sodium.sodium_munlock(&key,32);
    save_blob(cfg, req.id[0..], "rules.new", rules[0..]) catch |err| {
        log("failed to save rules.new: {}\n",.{err},req.id[0..]);
        fail(s);
    };
    save_blob(cfg, req.id[0..], "pub.new", pk[0..]) catch |err| {
        log("failed to save new pubkey: {}\n",.{err},req.id[0..]);
        fail(s);
    };

    _ = s.write("ok") catch |err| {
        log("failed to write confirmation of change: {}\n", .{err}, req.id[0..]);
        return err;
    };
    s.flush() catch |err| {
        log("failed to flush confirmation of change: {}\n", .{err}, req.id[0..]);
        return err;
    };
    log("change successful\n", .{}, req.id[0..]);
}

fn change_dkg(cfg: *const Config, s: anytype, req: *const Request) anyerror!void {
    auth(cfg, s, req, false) catch |err| {
        log("failed to auth for change op: {}\n", .{err}, req.id[0..]);
        fail(s);
    };
    log("running dkg for change op\n", .{}, req.id[0..]);

    var alpha: [32]u8 = undefined;
    // wait for alpha
    const msglen = s.read(alpha[0..]) catch |err| {
        log("failed to read alpha for change op: {}\n", .{err}, req.id[0..]);
        return err;
    };
    if (msglen != alpha.len) {
        log("read only {} B while receiving alpha, expected {} B\n", .{msglen, alpha.len}, req.id[0..]);
        fail(s);
    }

    var msg0 = mem.zeroes([tp_dkg.tpdkg_msg0_SIZE]u8);
    const msg0len = s.read(msg0[0..]) catch |err| {
        log("failed to read initial dkg message: {}\n", .{err}, req.id[0..]);
        return err;
    };
    if(msg0len != msg0.len) {
        log("dkg msg0 is only {} B instead of the expected {} B\n", .{msg0len, msg0.len}, req.id[0..]);
        fail(s);
    }

    const share = try s_allocator.alloc(u8, 33);
    defer s_allocator.free(share);
    dkg(cfg, s, msg0[0..], share[0..]) catch |err| {
        log("dkg failed: {}\n", .{err}, req.id[0..]);
        return err;
    };
    if(DEBUG) {
        log("[dkg] share ",.{}, req.id[0..]);
        utils.hexdump(share[0..]);
    }

    var beta = [_]u8{0} ** 33;
    beta[0] = share[0];

    if (-1 == oprf.oprf_Evaluate(share[1..].ptr, &alpha, beta[1..].ptr)) {
        log("failed to calculate beta = alpha * k\n", .{}, req.id[0..]);
        fail(s);
    }
    //var beta: [32]u8 = undefined;

    const betalen = s.write(beta[0..]) catch |err| {
        log("failed to send beta: {}\n", .{err}, req.id[0..]);
        return err;
    };
    s.flush() catch |err| {
        log("failed to flush beta: {}\n", .{err}, req.id[0..]);
        return err;
    };
    if(betalen!=beta.len) {
        log("only sent {} B of beta instead of the expected {} B\n", .{betalen, beta.len}, req.id[0..]);
        fail(s);
    }

    var signedpub: [32 + RULE_SIZE + 64]u8 = undefined; // pubkey, rules, sig
    const signedpublen = s.read(signedpub[0..]) catch |err| {
        log("failed to read signed pubkey: {}\n", .{err}, req.id[0..]);
        return err;
    };
    if(signedpublen != signedpub.len) {
        log("while receiving signed pubkey received only {} B, while expecting {} B\n", .{signedpublen, signedpub.len}, req.id[0..]);
        fail(s);
    }
    const pk = signedpub[0..32];
    _ = verify_blob(signedpub[0..], pk.*) catch |err| {
        log("failed to verify blob: {}\n", .{err}, req.id[0..]);
        fail(s);
    };

    const rules = signedpub[32..32+RULE_SIZE];

    save_blob(cfg, req.id[0..], "new", share[0..]) catch |err| {
        log("failed to save new share: {}\n",.{err},req.id[0..]);
        fail(s);
    };
    save_blob(cfg, req.id[0..], "rules.new", rules[0..]) catch |err| {
        log("failed to save rules.new: {}\n",.{err},req.id[0..]);
        fail(s);
    };
    save_blob(cfg, req.id[0..], "pub.new", pk[0..]) catch |err| {
        log("failed to save new pubkey: {}\n",.{err},req.id[0..]);
        fail(s);
    };

    _ = s.write("ok") catch |err| {
        log("failed to write confirmation of change: {}\n", .{err}, req.id[0..]);
        return err;
    };
    s.flush() catch |err| {
        log("failed to flush confirmation of change: {}\n", .{err}, req.id[0..]);
        return err;
    };
    log("threshold change successful\n", .{}, req.id[0..]);
}

/// this op deletes a complete id if it is authenticated, a host-username blob is also updated.
fn delete(cfg: *const Config, s: anytype, req: *const Request, isv1: bool) anyerror!void {
    const path = try mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", req.id[0..] });
    defer allocator.free(path);

    auth(cfg, s, req, isv1) catch |err| {
        log("failed to auth for delete op: {}\n", .{err}, req.id[0..]);
        fail(s);
    };

    if (!utils.dir_exists(path)) {
        log("record does not exist at {s}\n", .{path}, req.id[0..]);
        fail(s);
    }

    update_blob(cfg, s) catch |err| {
        log("failed to remove user from user list blob: {}\n", .{err}, req.id[0..]);
        fail(s);
    };

    std.fs.cwd().deleteTree(path) catch |err| {
        log("failed to delete record {s}: {}\n", .{path, err}, req.id[0..]);
        fail(s);
    };

    _ = s.write("ok") catch |err| {
        log("failed to write confirmation of change: {}\n", .{err}, req.id[0..]);
        return err;
    };
    s.flush() catch |err| {
        log("failed to flush confirmation of change: {}\n", .{err}, req.id[0..]);
        return err;
    };
    log("delete successful\n", .{}, req.id[0..]);
}

/// this generic function implements both commit and undo. essentially
/// it sets the one in "new" as the new key, and stores the old key
/// under "old"
fn commit_undo(cfg: *const Config, s: anytype, req: *const Request, new: *const [3:0]u8, old: *const [3:0]u8) anyerror!void {
    const path = try mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", req.id[0..] });
    defer allocator.free(path);

    if (!utils.dir_exists(path)) {
        log("path {s} doesn't exist\n", .{path}, req.id[0..]);
        fail(s);
    }

    auth(cfg, s, req, false) catch |err| {
        log("failed to auth for commit/undo op: {}\n", .{err}, req.id[0..]);
        fail(s);
    };

    // load all files to be shuffled around
    // start with the rules
    var new_rules: []u8 = undefined;
    const new_rulespath = try mem.concat(allocator, u8, &[_][]const u8{ "rules.", new[0..] });
    defer allocator.free(new_rulespath);
    if (load_blob(allocator, cfg, req.id[0..], new_rulespath, RULE_SIZE)) |r| {
        new_rules = r;
    } else |err| {
        log("cannot load {s}/{s}/{s}: {}\n", .{cfg.datadir, req.id[0..], new_rulespath, err}, req.id[0..]);
        fail(s);
    }
    defer allocator.free(new_rules);
    var cur_rules: []u8 = undefined;
    if (load_blob(allocator, cfg, req.id[0..], "rules"[0..], RULE_SIZE)) |r| {
        cur_rules = r;
    } else |err| {
        log("cannot load {s}/{s}/{s}: {}\n", .{cfg.datadir, req.id[0..], "rules", err}, req.id[0..]);
        fail(s);
    }
    defer allocator.free(cur_rules);

    // load the auth pub keys
    var new_pub: []u8 = undefined;
    const new_pubpath = try mem.concat(allocator, u8, &[_][]const u8{ "pub.", new[0..] });
    defer allocator.free(new_pubpath);
    if (load_blob(allocator, cfg, req.id[0..], new_pubpath, 32)) |r| {
        new_pub = r;
    } else |err| {
        log("cannot load {s}/{s}/{s}: {}\n", .{cfg.datadir, req.id[0..], new_pubpath[0..], err}, req.id[0..]);
        fail(s);
    }
    defer allocator.free(new_pub);
    var cur_pub: []u8 = undefined;
    if (load_blob(allocator, cfg, req.id[0..], "pub"[0..], 32)) |r| {
        cur_pub = r;
    } else |err| {
        log("cannot load {s}/{s}/pub: {}\n", .{cfg.datadir, req.id[0..], err}, req.id[0..]);
        fail(s);
    }
    defer allocator.free(cur_pub);

    // and last the keys
    var new_key: []u8 = undefined;
    if (load_blob(s_allocator, cfg, req.id[0..], new[0..], 33)) |r| {
        new_key = r;
    } else |err| {
        log("cannot load {s}/{s}/{s}: {}\n", .{cfg.datadir, req.id[0..], new[0..], err}, req.id[0..]);
        fail(s);
    }
    var cur_key: []u8 = undefined;
    if (load_blob(s_allocator, cfg, req.id[0..], "key"[0..], 33)) |r| {
        cur_key = r;
    } else |err| {
        log("cannot load {s}/{s}/key: {}\n", .{cfg.datadir, req.id[0..], err}, req.id[0..]);
        s_allocator.free(new_key);
        fail(s);
    }
    new_key[0]=cur_key[0];

    // we need to construct the filenames of the old rules/authpubkey
    const old_pubpath = try mem.concat(allocator, u8, &[_][]const u8{ "pub.", old[0..] });
    defer allocator.free(old_pubpath);
    const old_rulespath = try mem.concat(allocator, u8, &[_][]const u8{ "rules.", old[0..] });
    defer allocator.free(old_rulespath);

    // first save the keys
    save_blob(cfg, req.id[0..], old, cur_key) catch |err| {
        s_allocator.free(cur_key);
        s_allocator.free(new_key);
        log("cannot save to {s}/{s}/{s}: {}\n", .{cfg.datadir, req.id[0..], old, err}, req.id[0..]);
        fail(s);
    };
    s_allocator.free(cur_key);

    save_blob(cfg, req.id[0..], "key", new_key) catch |err| {
        log("cannot save to {s}/{s}/key: {}\n", .{cfg.datadir, req.id[0..], err}, req.id[0..]);
        s_allocator.free(new_key);
        fail(s);
    };
    s_allocator.free(new_key);

    // now save the rules and pubkeys
    save_blob(cfg, req.id[0..], old_rulespath, cur_rules) catch |err| {
        log("cannot save to {s}/{s}/{s}: {}\n", .{cfg.datadir, req.id[0..], old_rulespath, err}, req.id[0..]);
        fail(s);
    };
    save_blob(cfg, req.id[0..], old_pubpath, cur_pub) catch |err| {
        log("cannot save to {s}/{s}/{s}: {}\n", .{cfg.datadir, req.id[0..], old_pubpath, err}, req.id[0..]);
        fail(s);
    };

    save_blob(cfg, req.id[0..], "rules"[0..], new_rules) catch |err| {
        log("cannot save to {s}/{s}/rules: {}\n", .{cfg.datadir, req.id[0..], err}, req.id[0..]);
        fail(s);
    };
    save_blob(cfg, req.id[0..], "pub"[0..], new_pub) catch |err| {
        log("cannot save to {s}/{s}/pub: {}\n", .{cfg.datadir, req.id[0..], err}, req.id[0..]);
        fail(s);
    };

    // delete the previously "new" files
    const nkpath = try mem.concat(allocator, u8, &[_][]const u8{ path, "/", new });
    posix.unlink(nkpath) catch |err| {
        log("failed to delete {s}: {}\n", .{nkpath, err}, req.id[0..]);
        fail(s);
    };
    allocator.free(nkpath);

    const nppath = try mem.concat(allocator, u8, &[_][]const u8{ path, "/", "pub.", new });
    posix.unlink(nppath) catch |err| {
        log("failed to delete {s}: {}\n", .{nppath, err}, req.id[0..]);
        fail(s);
    };
    allocator.free(nppath);

    const nrpath = try mem.concat(allocator, u8, &[_][]const u8{ path, "/", "rules.", new });
    posix.unlink(nrpath) catch |err| {
        log("failed to delete {s}: {}\n", .{nrpath, err}, req.id[0..]);
        fail(s);
    };
    allocator.free(nrpath);

    // send ack
    _ = s.write("ok") catch |err| {
        log("failed to write confirmation of commit/undo: {}\n", .{err}, req.id[0..]);
        return err;
    };
    s.flush() catch |err| {
        log("failed to flush confirmation of commit/undo: {}\n", .{err}, req.id[0..]);
        return err;
    };
    log("commit/undo successful\n", .{}, req.id[0..]);
}

/// this op returns a requested blob
fn read(cfg: *const Config, s: anytype, req: *const Request) anyerror!void {
    auth(cfg, s, req, false) catch |err| {
        log("failed to auth for read op: {}\n", .{err}, req.id[0..]);
        fail(s);
    };

    if (load_blob(allocator, cfg, req.id[0..], "blob", null)) |r| {
        _ = s.write(r) catch |err| {
            log("failed to send blob: {}\n", .{err}, req.id[0..]);
            return err;
        };
        allocator.free(r);
    } else |err| {
        log("failed to load blob: {}\n", .{err}, req.id[0..]);
        _ = s.write("") catch |err2| {
            log("failed to write null blob: {}\n", .{err2}, req.id[0..]);
        };
    }
    s.flush() catch |err| {
        log("failed to flush blob: {}\n", .{err}, req.id[0..]);
        return err;
    };
}
