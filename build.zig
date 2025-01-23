const Builder = @import("std").Build;

pub fn build(b: *Builder) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const pie = b.option(bool, "pie", "Build a Position Independent Executable") orelse true;
    const relro = b.option(bool, "relro", "Force all relocations to be read-only after processing") orelse true;

    const exe = b.addExecutable(.{
        .name = "oracle",
        .root_source_file = .{
            .src_path = .{ .owner = b, .sub_path = "oracle.zig" },
        },
        .target = target,
        .optimize = optimize,
    });

    exe.pie = pie;
    exe.link_z_relro = relro;

    exe.addIncludePath(b.path("."));

    exe.linkSystemLibrary("sodium");
    exe.linkSystemLibrary("equihash");

    const bear = b.addStaticLibrary(.{ .name = "bear", .target = target, .optimize = optimize });
    linkBearSSL(".", bear, target, b);
    exe.addIncludePath(b.path("./BearSSL/inc"));
    exe.addIncludePath(b.path("./BearSSL/src"));
    exe.addIncludePath(b.path("./BearSSL/tools"));
    exe.linkLibrary(bear);

    linkliboprf(".", exe, b);

    const run_cmd = b.addRunArtifact(exe);

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    b.default_step.dependOn(&exe.step);
    b.installArtifact(exe);
}

const std = @import("std");

fn linkliboprf(comptime path_prefix: []const u8, module: *std.Build.Step.Compile, b: *Builder) void {
    module.addIncludePath(b.path(path_prefix ++ "/liboprf/src"));
    module.addIncludePath(b.path(path_prefix ++ "/liboprf/src/noise_xk/include"));
    module.addIncludePath(b.path(path_prefix ++ "/liboprf/src/noise_xk/include/karmel"));
    module.addIncludePath(b.path(path_prefix ++ "/liboprf/src/noise_xk/include/karmel/minimal"));

    module.addCSourceFile(.{ .file = b.path(path_prefix ++ "/workaround.c"), .flags = &[_][]const u8{"-Wall"} });

    module.addCSourceFile(.{ .file = b.path(path_prefix ++ "/liboprf/src/oprf.c"), .flags = &[_][]const u8{"-Wall"} });
    module.addCSourceFile(.{ .file = b.path(path_prefix ++ "/liboprf/src/toprf.c"), .flags = &[_][]const u8{"-Wall"} });
    module.addCSourceFile(.{ .file = b.path(path_prefix ++ "/liboprf/src/tp-dkg.c"), .flags = &[_][]const u8{"-Wall"} });
    module.addCSourceFile(.{ .file = b.path(path_prefix ++ "/liboprf/src/dkg.c"), .flags = &[_][]const u8{"-Wall"} });
    module.addCSourceFile(.{ .file = b.path(path_prefix ++ "/liboprf/src/utils.c"), .flags = &[_][]const u8{"-Wall"} });

    module.addCSourceFile(.{ .file = b.path(path_prefix ++ "/liboprf/src/noise_xk/src/Noise_XK.c"), .flags = &[_][]const u8{"-Wall"} });
    module.addCSourceFile(.{ .file = b.path(path_prefix ++ "/liboprf/src/noise_xk/src/XK.c"), .flags = &[_][]const u8{"-Wall"} });
}

/// Adds all BearSSL sources to the exeobj step
/// Allows simple linking from build scripts.
fn linkBearSSL(comptime path_prefix: []const u8, module: *std.Build.Step.Compile, target: std.Build.ResolvedTarget, b: *Builder) void {
    module.linkLibC();
    //module.setTarget(target);

    module.addIncludePath(b.path(path_prefix ++ "/BearSSL/inc"));
    module.addIncludePath(b.path(path_prefix ++ "/BearSSL/src"));
    module.addIncludePath(b.path(path_prefix ++ "/BearSSL/tools"));

    inline for (bearssl_sources) |srcfile| {
        module.addCSourceFile(.{
            .file = b.path(path_prefix ++ srcfile),
            .flags = &[_][]const u8{
                "-Wall",
                "-DBR_LE_UNALIGNED=0", // this prevent BearSSL from using undefined behaviour when doing potential unaligned access
            },
        });
    }

    if (target.result.os.tag == std.Target.Os.Tag.windows) {
        module.linkSystemLibrary("advapi32");
    }
}

const bearssl_sources = [_][]const u8{
    "/BearSSL/tools/keys.c",
    "/BearSSL/tools/files.c",
    "/BearSSL/tools/names.c",
    "/BearSSL/tools/xmem.c",
    "/BearSSL/tools/errors.c",
    "/BearSSL/tools/vector.c",
    "/BearSSL/src/settings.c",
    "/BearSSL/src/aead/ccm.c",
    "/BearSSL/src/aead/eax.c",
    "/BearSSL/src/aead/gcm.c",
    "/BearSSL/src/codec/ccopy.c",
    "/BearSSL/src/codec/dec16be.c",
    "/BearSSL/src/codec/dec16le.c",
    "/BearSSL/src/codec/dec32be.c",
    "/BearSSL/src/codec/dec32le.c",
    "/BearSSL/src/codec/dec64be.c",
    "/BearSSL/src/codec/dec64le.c",
    "/BearSSL/src/codec/enc16be.c",
    "/BearSSL/src/codec/enc16le.c",
    "/BearSSL/src/codec/enc32be.c",
    "/BearSSL/src/codec/enc32le.c",
    "/BearSSL/src/codec/enc64be.c",
    "/BearSSL/src/codec/enc64le.c",
    "/BearSSL/src/codec/pemdec.c",
    "/BearSSL/src/codec/pemenc.c",
    "/BearSSL/src/ec/ec_all_m15.c",
    "/BearSSL/src/ec/ec_all_m31.c",
    "/BearSSL/src/ec/ec_c25519_i15.c",
    "/BearSSL/src/ec/ec_c25519_i31.c",
    "/BearSSL/src/ec/ec_c25519_m15.c",
    "/BearSSL/src/ec/ec_c25519_m31.c",
    "/BearSSL/src/ec/ec_c25519_m62.c",
    "/BearSSL/src/ec/ec_c25519_m64.c",
    "/BearSSL/src/ec/ec_curve25519.c",
    "/BearSSL/src/ec/ec_default.c",
    "/BearSSL/src/ec/ec_keygen.c",
    "/BearSSL/src/ec/ec_p256_m15.c",
    "/BearSSL/src/ec/ec_p256_m31.c",
    "/BearSSL/src/ec/ec_p256_m62.c",
    "/BearSSL/src/ec/ec_p256_m64.c",
    "/BearSSL/src/ec/ec_prime_i15.c",
    "/BearSSL/src/ec/ec_prime_i31.c",
    "/BearSSL/src/ec/ec_pubkey.c",
    "/BearSSL/src/ec/ec_secp256r1.c",
    "/BearSSL/src/ec/ec_secp384r1.c",
    "/BearSSL/src/ec/ec_secp521r1.c",
    "/BearSSL/src/ec/ecdsa_atr.c",
    "/BearSSL/src/ec/ecdsa_default_sign_asn1.c",
    "/BearSSL/src/ec/ecdsa_default_sign_raw.c",
    "/BearSSL/src/ec/ecdsa_default_vrfy_asn1.c",
    "/BearSSL/src/ec/ecdsa_default_vrfy_raw.c",
    "/BearSSL/src/ec/ecdsa_i15_bits.c",
    "/BearSSL/src/ec/ecdsa_i15_sign_asn1.c",
    "/BearSSL/src/ec/ecdsa_i15_sign_raw.c",
    "/BearSSL/src/ec/ecdsa_i15_vrfy_asn1.c",
    "/BearSSL/src/ec/ecdsa_i15_vrfy_raw.c",
    "/BearSSL/src/ec/ecdsa_i31_bits.c",
    "/BearSSL/src/ec/ecdsa_i31_sign_asn1.c",
    "/BearSSL/src/ec/ecdsa_i31_sign_raw.c",
    "/BearSSL/src/ec/ecdsa_i31_vrfy_asn1.c",
    "/BearSSL/src/ec/ecdsa_i31_vrfy_raw.c",
    "/BearSSL/src/ec/ecdsa_rta.c",
    "/BearSSL/src/hash/dig_oid.c",
    "/BearSSL/src/hash/dig_size.c",
    "/BearSSL/src/hash/ghash_ctmul.c",
    "/BearSSL/src/hash/ghash_ctmul32.c",
    "/BearSSL/src/hash/ghash_ctmul64.c",
    "/BearSSL/src/hash/ghash_pclmul.c",
    "/BearSSL/src/hash/ghash_pwr8.c",
    "/BearSSL/src/hash/md5.c",
    "/BearSSL/src/hash/md5sha1.c",
    "/BearSSL/src/hash/mgf1.c",
    "/BearSSL/src/hash/multihash.c",
    "/BearSSL/src/hash/sha1.c",
    "/BearSSL/src/hash/sha2big.c",
    "/BearSSL/src/hash/sha2small.c",
    "/BearSSL/src/int/i15_add.c",
    "/BearSSL/src/int/i15_bitlen.c",
    "/BearSSL/src/int/i15_decmod.c",
    "/BearSSL/src/int/i15_decode.c",
    "/BearSSL/src/int/i15_decred.c",
    "/BearSSL/src/int/i15_encode.c",
    "/BearSSL/src/int/i15_fmont.c",
    "/BearSSL/src/int/i15_iszero.c",
    "/BearSSL/src/int/i15_moddiv.c",
    "/BearSSL/src/int/i15_modpow.c",
    "/BearSSL/src/int/i15_modpow2.c",
    "/BearSSL/src/int/i15_montmul.c",
    "/BearSSL/src/int/i15_mulacc.c",
    "/BearSSL/src/int/i15_muladd.c",
    "/BearSSL/src/int/i15_ninv15.c",
    "/BearSSL/src/int/i15_reduce.c",
    "/BearSSL/src/int/i15_rshift.c",
    "/BearSSL/src/int/i15_sub.c",
    "/BearSSL/src/int/i15_tmont.c",
    "/BearSSL/src/int/i31_add.c",
    "/BearSSL/src/int/i31_bitlen.c",
    "/BearSSL/src/int/i31_decmod.c",
    "/BearSSL/src/int/i31_decode.c",
    "/BearSSL/src/int/i31_decred.c",
    "/BearSSL/src/int/i31_encode.c",
    "/BearSSL/src/int/i31_fmont.c",
    "/BearSSL/src/int/i31_iszero.c",
    "/BearSSL/src/int/i31_moddiv.c",
    "/BearSSL/src/int/i31_modpow.c",
    "/BearSSL/src/int/i31_modpow2.c",
    "/BearSSL/src/int/i31_montmul.c",
    "/BearSSL/src/int/i31_mulacc.c",
    "/BearSSL/src/int/i31_muladd.c",
    "/BearSSL/src/int/i31_ninv31.c",
    "/BearSSL/src/int/i31_reduce.c",
    "/BearSSL/src/int/i31_rshift.c",
    "/BearSSL/src/int/i31_sub.c",
    "/BearSSL/src/int/i31_tmont.c",
    "/BearSSL/src/int/i32_add.c",
    "/BearSSL/src/int/i32_bitlen.c",
    "/BearSSL/src/int/i32_decmod.c",
    "/BearSSL/src/int/i32_decode.c",
    "/BearSSL/src/int/i32_decred.c",
    "/BearSSL/src/int/i32_div32.c",
    "/BearSSL/src/int/i32_encode.c",
    "/BearSSL/src/int/i32_fmont.c",
    "/BearSSL/src/int/i32_iszero.c",
    "/BearSSL/src/int/i32_modpow.c",
    "/BearSSL/src/int/i32_montmul.c",
    "/BearSSL/src/int/i32_mulacc.c",
    "/BearSSL/src/int/i32_muladd.c",
    "/BearSSL/src/int/i32_ninv32.c",
    "/BearSSL/src/int/i32_reduce.c",
    "/BearSSL/src/int/i32_sub.c",
    "/BearSSL/src/int/i32_tmont.c",
    "/BearSSL/src/int/i62_modpow2.c",
    "/BearSSL/src/kdf/hkdf.c",
    "/BearSSL/src/kdf/shake.c",
    "/BearSSL/src/mac/hmac.c",
    "/BearSSL/src/mac/hmac_ct.c",
    "/BearSSL/src/rand/aesctr_drbg.c",
    "/BearSSL/src/rand/hmac_drbg.c",
    "/BearSSL/src/rand/sysrng.c",
    "/BearSSL/src/rsa/rsa_default_keygen.c",
    "/BearSSL/src/rsa/rsa_default_modulus.c",
    "/BearSSL/src/rsa/rsa_default_oaep_decrypt.c",
    "/BearSSL/src/rsa/rsa_default_oaep_encrypt.c",
    "/BearSSL/src/rsa/rsa_default_pkcs1_sign.c",
    "/BearSSL/src/rsa/rsa_default_pkcs1_vrfy.c",
    "/BearSSL/src/rsa/rsa_default_priv.c",
    "/BearSSL/src/rsa/rsa_default_privexp.c",
    "/BearSSL/src/rsa/rsa_default_pss_sign.c",
    "/BearSSL/src/rsa/rsa_default_pss_vrfy.c",
    "/BearSSL/src/rsa/rsa_default_pub.c",
    "/BearSSL/src/rsa/rsa_default_pubexp.c",
    "/BearSSL/src/rsa/rsa_i15_keygen.c",
    "/BearSSL/src/rsa/rsa_i15_modulus.c",
    "/BearSSL/src/rsa/rsa_i15_oaep_decrypt.c",
    "/BearSSL/src/rsa/rsa_i15_oaep_encrypt.c",
    "/BearSSL/src/rsa/rsa_i15_pkcs1_sign.c",
    "/BearSSL/src/rsa/rsa_i15_pkcs1_vrfy.c",
    "/BearSSL/src/rsa/rsa_i15_priv.c",
    "/BearSSL/src/rsa/rsa_i15_privexp.c",
    "/BearSSL/src/rsa/rsa_i15_pss_sign.c",
    "/BearSSL/src/rsa/rsa_i15_pss_vrfy.c",
    "/BearSSL/src/rsa/rsa_i15_pub.c",
    "/BearSSL/src/rsa/rsa_i15_pubexp.c",
    "/BearSSL/src/rsa/rsa_i31_keygen.c",
    "/BearSSL/src/rsa/rsa_i31_keygen_inner.c",
    "/BearSSL/src/rsa/rsa_i31_modulus.c",
    "/BearSSL/src/rsa/rsa_i31_oaep_decrypt.c",
    "/BearSSL/src/rsa/rsa_i31_oaep_encrypt.c",
    "/BearSSL/src/rsa/rsa_i31_pkcs1_sign.c",
    "/BearSSL/src/rsa/rsa_i31_pkcs1_vrfy.c",
    "/BearSSL/src/rsa/rsa_i31_priv.c",
    "/BearSSL/src/rsa/rsa_i31_privexp.c",
    "/BearSSL/src/rsa/rsa_i31_pss_sign.c",
    "/BearSSL/src/rsa/rsa_i31_pss_vrfy.c",
    "/BearSSL/src/rsa/rsa_i31_pub.c",
    "/BearSSL/src/rsa/rsa_i31_pubexp.c",
    "/BearSSL/src/rsa/rsa_i32_oaep_decrypt.c",
    "/BearSSL/src/rsa/rsa_i32_oaep_encrypt.c",
    "/BearSSL/src/rsa/rsa_i32_pkcs1_sign.c",
    "/BearSSL/src/rsa/rsa_i32_pkcs1_vrfy.c",
    "/BearSSL/src/rsa/rsa_i32_priv.c",
    "/BearSSL/src/rsa/rsa_i32_pss_sign.c",
    "/BearSSL/src/rsa/rsa_i32_pss_vrfy.c",
    "/BearSSL/src/rsa/rsa_i32_pub.c",
    "/BearSSL/src/rsa/rsa_i62_keygen.c",
    "/BearSSL/src/rsa/rsa_i62_oaep_decrypt.c",
    "/BearSSL/src/rsa/rsa_i62_oaep_encrypt.c",
    "/BearSSL/src/rsa/rsa_i62_pkcs1_sign.c",
    "/BearSSL/src/rsa/rsa_i62_pkcs1_vrfy.c",
    "/BearSSL/src/rsa/rsa_i62_priv.c",
    "/BearSSL/src/rsa/rsa_i62_pss_sign.c",
    "/BearSSL/src/rsa/rsa_i62_pss_vrfy.c",
    "/BearSSL/src/rsa/rsa_i62_pub.c",
    "/BearSSL/src/rsa/rsa_oaep_pad.c",
    "/BearSSL/src/rsa/rsa_oaep_unpad.c",
    "/BearSSL/src/rsa/rsa_pkcs1_sig_pad.c",
    "/BearSSL/src/rsa/rsa_pkcs1_sig_unpad.c",
    "/BearSSL/src/rsa/rsa_pss_sig_pad.c",
    "/BearSSL/src/rsa/rsa_pss_sig_unpad.c",
    "/BearSSL/src/rsa/rsa_ssl_decrypt.c",
    "/BearSSL/src/ssl/prf.c",
    "/BearSSL/src/ssl/prf_md5sha1.c",
    "/BearSSL/src/ssl/prf_sha256.c",
    "/BearSSL/src/ssl/prf_sha384.c",
    "/BearSSL/src/ssl/ssl_ccert_single_ec.c",
    "/BearSSL/src/ssl/ssl_ccert_single_rsa.c",
    "/BearSSL/src/ssl/ssl_client.c",
    "/BearSSL/src/ssl/ssl_client_default_rsapub.c",
    "/BearSSL/src/ssl/ssl_client_full.c",
    "/BearSSL/src/ssl/ssl_engine.c",
    "/BearSSL/src/ssl/ssl_engine_default_aescbc.c",
    "/BearSSL/src/ssl/ssl_engine_default_aesccm.c",
    "/BearSSL/src/ssl/ssl_engine_default_aesgcm.c",
    "/BearSSL/src/ssl/ssl_engine_default_chapol.c",
    "/BearSSL/src/ssl/ssl_engine_default_descbc.c",
    "/BearSSL/src/ssl/ssl_engine_default_ec.c",
    "/BearSSL/src/ssl/ssl_engine_default_ecdsa.c",
    "/BearSSL/src/ssl/ssl_engine_default_rsavrfy.c",
    "/BearSSL/src/ssl/ssl_hashes.c",
    "/BearSSL/src/ssl/ssl_hs_client.c",
    "/BearSSL/src/ssl/ssl_hs_server.c",
    "/BearSSL/src/ssl/ssl_io.c",
    "/BearSSL/src/ssl/ssl_keyexport.c",
    "/BearSSL/src/ssl/ssl_lru.c",
    "/BearSSL/src/ssl/ssl_rec_cbc.c",
    "/BearSSL/src/ssl/ssl_rec_ccm.c",
    "/BearSSL/src/ssl/ssl_rec_chapol.c",
    "/BearSSL/src/ssl/ssl_rec_gcm.c",
    "/BearSSL/src/ssl/ssl_scert_single_ec.c",
    "/BearSSL/src/ssl/ssl_scert_single_rsa.c",
    "/BearSSL/src/ssl/ssl_server.c",
    "/BearSSL/src/ssl/ssl_server_full_ec.c",
    "/BearSSL/src/ssl/ssl_server_full_rsa.c",
    "/BearSSL/src/ssl/ssl_server_mine2c.c",
    "/BearSSL/src/ssl/ssl_server_mine2g.c",
    "/BearSSL/src/ssl/ssl_server_minf2c.c",
    "/BearSSL/src/ssl/ssl_server_minf2g.c",
    "/BearSSL/src/ssl/ssl_server_minr2g.c",
    "/BearSSL/src/ssl/ssl_server_minu2g.c",
    "/BearSSL/src/ssl/ssl_server_minv2g.c",
    "/BearSSL/src/symcipher/aes_big_cbcdec.c",
    "/BearSSL/src/symcipher/aes_big_cbcenc.c",
    "/BearSSL/src/symcipher/aes_big_ctr.c",
    "/BearSSL/src/symcipher/aes_big_ctrcbc.c",
    "/BearSSL/src/symcipher/aes_big_dec.c",
    "/BearSSL/src/symcipher/aes_big_enc.c",
    "/BearSSL/src/symcipher/aes_common.c",
    "/BearSSL/src/symcipher/aes_ct.c",
    "/BearSSL/src/symcipher/aes_ct64.c",
    "/BearSSL/src/symcipher/aes_ct64_cbcdec.c",
    "/BearSSL/src/symcipher/aes_ct64_cbcenc.c",
    "/BearSSL/src/symcipher/aes_ct64_ctr.c",
    "/BearSSL/src/symcipher/aes_ct64_ctrcbc.c",
    "/BearSSL/src/symcipher/aes_ct64_dec.c",
    "/BearSSL/src/symcipher/aes_ct64_enc.c",
    "/BearSSL/src/symcipher/aes_ct_cbcdec.c",
    "/BearSSL/src/symcipher/aes_ct_cbcenc.c",
    "/BearSSL/src/symcipher/aes_ct_ctr.c",
    "/BearSSL/src/symcipher/aes_ct_ctrcbc.c",
    "/BearSSL/src/symcipher/aes_ct_dec.c",
    "/BearSSL/src/symcipher/aes_ct_enc.c",
    "/BearSSL/src/symcipher/aes_pwr8.c",
    "/BearSSL/src/symcipher/aes_pwr8_cbcdec.c",
    "/BearSSL/src/symcipher/aes_pwr8_cbcenc.c",
    "/BearSSL/src/symcipher/aes_pwr8_ctr.c",
    "/BearSSL/src/symcipher/aes_pwr8_ctrcbc.c",
    "/BearSSL/src/symcipher/aes_small_cbcdec.c",
    "/BearSSL/src/symcipher/aes_small_cbcenc.c",
    "/BearSSL/src/symcipher/aes_small_ctr.c",
    "/BearSSL/src/symcipher/aes_small_ctrcbc.c",
    "/BearSSL/src/symcipher/aes_small_dec.c",
    "/BearSSL/src/symcipher/aes_small_enc.c",
    "/BearSSL/src/symcipher/aes_x86ni.c",
    "/BearSSL/src/symcipher/aes_x86ni_cbcdec.c",
    "/BearSSL/src/symcipher/aes_x86ni_cbcenc.c",
    "/BearSSL/src/symcipher/aes_x86ni_ctr.c",
    "/BearSSL/src/symcipher/aes_x86ni_ctrcbc.c",
    "/BearSSL/src/symcipher/chacha20_ct.c",
    "/BearSSL/src/symcipher/chacha20_sse2.c",
    "/BearSSL/src/symcipher/des_ct.c",
    "/BearSSL/src/symcipher/des_ct_cbcdec.c",
    "/BearSSL/src/symcipher/des_ct_cbcenc.c",
    "/BearSSL/src/symcipher/des_support.c",
    "/BearSSL/src/symcipher/des_tab.c",
    "/BearSSL/src/symcipher/des_tab_cbcdec.c",
    "/BearSSL/src/symcipher/des_tab_cbcenc.c",
    "/BearSSL/src/symcipher/poly1305_ctmul.c",
    "/BearSSL/src/symcipher/poly1305_ctmul32.c",
    "/BearSSL/src/symcipher/poly1305_ctmulq.c",
    "/BearSSL/src/symcipher/poly1305_i15.c",
    "/BearSSL/src/x509/asn1enc.c",
    "/BearSSL/src/x509/encode_ec_pk8der.c",
    "/BearSSL/src/x509/encode_ec_rawder.c",
    "/BearSSL/src/x509/encode_rsa_pk8der.c",
    "/BearSSL/src/x509/encode_rsa_rawder.c",
    "/BearSSL/src/x509/skey_decoder.c",
    "/BearSSL/src/x509/x509_decoder.c",
    "/BearSSL/src/x509/x509_knownkey.c",
    "/BearSSL/src/x509/x509_minimal.c",
    "/BearSSL/src/x509/x509_minimal_full.c",
};
