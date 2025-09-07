/**
 * javac Gost2File.java 
 * java Gost2File 
 *
 */

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.Arrays;

public class Gost2File {

    /* =========================
     *      GOST2-128 CORE
     * ========================= */

    // typedef uint64_t word64;
    // (In Java we use 'long' (signed 64-bit). We mask where needed.)
    private static final int n1 = 512; /* 4096-bit GOST2-128 key for 64 * 64-bit subkeys */

    private static int x1, x2, i_g;
    private static final byte[] h2 = new byte[n1];
    private static final byte[] h1 = new byte[n1 * 3];

    private static void init_gost_keyhash() {
        x1 = 0;
        x2 = 0;
        for (i_g = 0; i_g < n1; i_g++) h2[i_g] = 0;
        for (i_g = 0; i_g < n1; i_g++) h1[i_g] = 0;
    }

    private static void hashing(byte[] t1, int b6) {
        final byte[] s4 = new byte[]{
            13, (byte)199, 11, 67, (byte)237, (byte)193, (byte)164, 77, 115, (byte)184, (byte)141, (byte)222, 73, 38, (byte)147, 36, (byte)150, 87, 21, 104, 12, 61, (byte)156, 101, 111, (byte)145,
            119, 22, (byte)207, 35, (byte)198, 37, (byte)171, (byte)167, 80, 30, (byte)219, 28, (byte)213, 121, 86, 29, (byte)214, (byte)242, 6, 4, 89, (byte)162, 110, (byte)175, 19, (byte)157, 3, 88, (byte)234, 94, (byte)144, 118, (byte)159, (byte)239, 100, 17, (byte)182, (byte)173, (byte)238,
            68, 16, 79, (byte)132, 54, (byte)163, 52, 9, 58, 57, 55, (byte)229, (byte)192, (byte)170, (byte)226, 56, (byte)231, (byte)187, (byte)158, 70, (byte)224, (byte)233, (byte)245, 26, 47, 32, 44, (byte)247, 8, (byte)251, 20, (byte)197, (byte)185, 109, (byte)153, (byte)204, (byte)218, 93, (byte)178,
            (byte)212, (byte)137, 84, (byte)174, 24, 120, (byte)130, (byte)149, 72, (byte)180, (byte)181, (byte)208, (byte)255, (byte)189, (byte)152, 18, (byte)143, (byte)176, 60, (byte)249, 27, (byte)227, (byte)128, (byte)139, (byte)243, (byte)253, 59, 123, (byte)172, 108, (byte)211, 96, (byte)138, 10, (byte)215, 42, (byte)225, 40, 81,
            65, 90, 25, 98, (byte)126, (byte)154, 64, 124, 116, 122, 5, 1, (byte)168, 83, (byte)190, (byte)131, (byte)191, (byte)244, (byte)240, (byte)235, (byte)177, (byte)155, (byte)228, 125, 66, 43, (byte)201, (byte)248, (byte)220, (byte)129, (byte)188, (byte)230, 62, 75, 71, 78, 34, 31, (byte)216,
            (byte)254, (byte)136, 91, 114, 106, 46, (byte)217, (byte)196, 92, (byte)151, (byte)209, (byte)133, 51, (byte)236, 33, (byte)252, (byte)127, (byte)179, 69, 7, (byte)183, 105, (byte)146, 97, 39, 15, (byte)205, 112, (byte)200, (byte)166, (byte)223, 45, 48, (byte)246, (byte)186, 41, (byte)148, (byte)140, 107,
            76, 85, 95, (byte)194, (byte)142, 50, 49, (byte)134, 23, (byte)135, (byte)169, (byte)221, (byte)210, (byte)203, 63, (byte)165, 82, (byte)161, (byte)202, 53, 14, (byte)206, (byte)232, 103, 102, (byte)195, 117, (byte)250, 99, 0, 74, (byte)160, (byte)241, 2, 113
        };
        int b1, b2, b3, b4, b5;
        b4 = 0;
        while (b6 != 0) {
            for (; b6 != 0 && x2 < n1; b6--, x2++) {
                b5 = t1[b4++] & 0xFF;
                h1[x2 + n1] = (byte) b5;
                h1[x2 + (n1 * 2)] = (byte) (b5 ^ h1[x2]);
                x1 = (h2[x2] = (byte) (s4[(b5 ^ x1) & 0xFF] ^ h2[x2])) & 0xFF;
            }
            if (x2 == n1) {
                b2 = 0;
                x2 = 0;
                for (b3 = 0; b3 < (n1 + 2); b3++) {
                    for (b1 = 0; b1 < (n1 * 3); b1++)
                        b2 = (h1[b1] = (byte) (s4[b2 & 0xFF] ^ h1[b1])) & 0xFF;
                    b2 = (b2 + b3) % 256;
                }
            }
        }
    }

    private static void end_gost_keyhash(byte[] h4 /* length n1 */) {
        byte[] h3 = new byte[n1];
        int j, n4;
        n4 = n1 - x2;
        for (j = 0; j < n4; j++) h3[j] = (byte) n4;
        hashing(h3, n4);
        hashing(h2, h2.length);
        for (j = 0; j < n1; j++) h4[j] = h1[j];
    }

    /* create 64 * 64-bit subkeys from h4 hash */
    private static void create_keys(byte[] h4, long[] key /* length 64 */) {
        int k = 0;
        for (int i = 0; i < 64; i++) {
            long v = 0L;
            for (int z = 0; z < 8; z++) v = (v << 8) | ((long) h4[k++] & 0xFFL);
            key[i] = v;
        }
    }

    private static final byte[] k1 = {0x4, 0xA, 0x9, 0x2, 0xD, 0x8, 0x0, 0xE, 0x6, 0xB, 0x1, 0xC, 0x7, 0xF, 0x5, 0x3};
    private static final byte[] k2 = {0xE, 0xB, 0x4, 0xC, 0x6, 0xD, 0xF, 0xA, 0x2, 0x3, 0x8, 0x1, 0x0, 0x7, 0x5, 0x9};
    private static final byte[] k3 = {0x5, 0x8, 0x1, 0xD, 0xA, 0x3, 0x4, 0x2, 0xE, 0xF, 0xC, 0x7, 0x6, 0x0, 0x9, 0xB};
    private static final byte[] k4 = {0x7, 0xD, 0xA, 0x1, 0x0, 0x8, 0x9, 0xF, 0xE, 0x4, 0x6, 0xC, 0xB, 0x2, 0x5, 0x3};
    private static final byte[] k5 = {0x6, 0xC, 0x7, 0x1, 0x5, 0xF, 0xD, 0x8, 0x4, 0xA, 0x9, 0xE, 0x0, 0x3, 0xB, 0x2};
    private static final byte[] k6 = {0x4, 0xB, 0xA, 0x0, 0x7, 0x2, 0x1, 0xD, 0x3, 0x6, 0x8, 0x5, 0x9, 0xC, 0xF, 0xE};
    private static final byte[] k7 = {0xD, 0xB, 0x4, 0x1, 0x3, 0xF, 0x5, 0x9, 0x0, 0xA, 0xE, 0x7, 0x6, 0x8, 0x2, 0xC};
    private static final byte[] k8 = {0x1, 0xF, 0xD, 0x0, 0x5, 0x7, 0xA, 0x4, 0x9, 0x2, 0x3, 0xE, 0x6, 0xB, 0x8, 0xC};

    private static final byte[] k9 = {0xC, 0x4, 0x6, 0x2, 0xA, 0x5, 0xB, 0x9, 0xE, 0x8, 0xD, 0x7, 0x0, 0x3, 0xF, 0x1};
    private static final byte[] k10 = {0x6, 0x8, 0x2, 0x3, 0x9, 0xA, 0x5, 0xC, 0x1, 0xE, 0x4, 0x7, 0xB, 0xD, 0x0, 0xF};
    private static final byte[] k11 = {0xB, 0x3, 0x5, 0x8, 0x2, 0xF, 0xA, 0xD, 0xE, 0x1, 0x7, 0x4, 0xC, 0x9, 0x6, 0x0};
    private static final byte[] k12 = {0xC, 0x8, 0x2, 0x1, 0xD, 0x4, 0xF, 0x6, 0x7, 0x0, 0xA, 0x5, 0x3, 0xE, 0x9, 0xB};
    private static final byte[] k13 = {0x7, 0xF, 0x5, 0xA, 0x8, 0x1, 0x6, 0xD, 0x0, 0x9, 0x3, 0xE, 0xB, 0x4, 0x2, 0xC};
    private static final byte[] k14 = {0x5, 0xD, 0xF, 0x6, 0x9, 0x2, 0xC, 0xA, 0xB, 0x7, 0x8, 0x1, 0x4, 0x3, 0xE, 0x0};
    private static final byte[] k15 = {0x8, 0xE, 0x2, 0x5, 0x6, 0x9, 0x1, 0xC, 0xF, 0x4, 0xB, 0x0, 0xD, 0xA, 0x3, 0x7};
    private static final byte[] k16 = {0x1, 0x7, 0xE, 0xD, 0x0, 0x5, 0x8, 0x3, 0x4, 0xF, 0xA, 0x6, 0x9, 0xC, 0xB, 0x2};

    private static final byte[] k175 = new byte[256], k153 = new byte[256], k131 = new byte[256], k109 = new byte[256], k87 = new byte[256], k65 = new byte[256], k43 = new byte[256], k21 = new byte[256];

    private static void kboxinit() {
        for (int i = 0; i < 256; i++) {
            k175[i] = (byte) ((k16[(i >> 4) & 15] << 4) | (k15[i & 15] & 0xF));
            k153[i] = (byte) ((k14[(i >> 4) & 15] << 4) | (k13[i & 15] & 0xF));
            k131[i] = (byte) ((k12[(i >> 4) & 15] << 4) | (k11[i & 15] & 0xF));
            k109[i] = (byte) ((k10[(i >> 4) & 15] << 4) | (k9[i & 15] & 0xF));
            k87[i]  = (byte) ((k8[(i >> 4) & 15]  << 4) | (k7[i & 15] & 0xF));
            k65[i]  = (byte) ((k6[(i >> 4) & 15]  << 4) | (k5[i & 15] & 0xF));
            k43[i]  = (byte) ((k4[(i >> 4) & 15]  << 4) | (k3[i & 15] & 0xF));
            k21[i]  = (byte) ((k2[(i >> 4) & 15]  << 4) | (k1[i & 15] & 0xF));
        }
    }

    private static long f(long x) {
        long y = (x >>> 32) & 0xFFFFFFFFL;
        long z = (x) & 0xFFFFFFFFL;

        int y0 = (int) ((y >>> 24) & 0xFF);
        int y1 = (int) ((y >>> 16) & 0xFF);
        int y2 = (int) ((y >>> 8) & 0xFF);
        int y3 = (int) (y & 0xFF);

        int z0 = (int) ((z >>> 24) & 0xFF);
        int z1 = (int) ((z >>> 16) & 0xFF);
        int z2 = (int) ((z >>> 8) & 0xFF);
        int z3 = (int) (z & 0xFF);

        long ySub = (((long) k87[y0] & 0xFFL) << 24) | (((long) k65[y1] & 0xFFL) << 16) |
                    (((long) k43[y2] & 0xFFL) << 8)  | (((long) k21[y3] & 0xFFL));
        long zSub = (((long) k175[z0] & 0xFFL) << 24) | (((long) k153[z1] & 0xFFL) << 16) |
                    (((long) k131[z2] & 0xFFL) << 8)  | (((long) k109[z3] & 0xFFL));

        long nx = ((ySub & 0xFFFFFFFFL) << 32) | (zSub & 0xFFFFFFFFL);
        return ((nx << 11) | (nx >>> (64 - 11)));
    }

    private static void gostcrypt(long[] in /* len 2 */, long[] out /* len 2 */, long[] key /* len 64 */) {
        long a = in[0], b = in[1];
        int k = 0;
        for (int i = 0; i < 32; i++) {
            b ^= f(a + key[k++]);
            a ^= f(b + key[k++]);
        }
        out[0] = b; out[1] = a;
    }

    private static void gostdecrypt(long[] in, long[] out, long[] key) {
        long a = in[0], b = in[1];
        int k = 63;
        for (int i = 0; i < 32; i++) {
            b ^= f(a + key[k--]);
            a ^= f(b + key[k--]);
        }
        out[0] = b; out[1] = a;
    }

    /* =========================
     *          SHA-256
     * ========================= */

    private static class Sha256Ctx {
        int[] state = new int[8];
        long bitlen;
        byte[] data = new byte[64];
        int datalen;
    }

    private static int ROTRIGHT(int a, int b) { return (a >>> b) | (a << (32 - b)); }
    private static int CH(int x, int y, int z) { return (x & y) ^ (~x & z); }
    private static int MAJ(int x, int y, int z) { return (x & y) ^ (x & z) ^ (y & z); }
    private static int EP0(int x) { return ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22); }
    private static int EP1(int x) { return ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25); }
    private static int SIG0(int x){ return ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ (x >>> 3); }
    private static int SIG1(int x){ return ROTRIGHT(x,17)^ ROTRIGHT(x,19)^ (x >>> 10); }

    private static final int[] k256 = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };

    private static void sha256_transform(Sha256Ctx ctx, byte[] data) {
        int[] m = new int[64];
        for (int i = 0, j = 0; i < 16; i++, j += 4) {
            m[i] = ((data[j] & 0xFF) << 24) | ((data[j + 1] & 0xFF) << 16) | ((data[j + 2] & 0xFF) << 8) | (data[j + 3] & 0xFF);
        }
        for (int i = 16; i < 64; i++) {
            m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
        }

        int a = ctx.state[0], b = ctx.state[1], c = ctx.state[2], d = ctx.state[3];
        int e = ctx.state[4], f = ctx.state[5], g = ctx.state[6], h = ctx.state[7];

        for (int i = 0; i < 64; i++) {
            int t1 = h + EP1(e) + CH(e, f, g) + k256[i] + m[i];
            int t2 = EP0(a) + MAJ(a, b, c);
            h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }

        ctx.state[0] += a; ctx.state[1] += b; ctx.state[2] += c; ctx.state[3] += d;
        ctx.state[4] += e; ctx.state[5] += f; ctx.state[6] += g; ctx.state[7] += h;
    }

    private static void sha256_init(Sha256Ctx ctx) {
        ctx.datalen = 0; ctx.bitlen = 0L;
        ctx.state[0] = 0x6a09e667; ctx.state[1] = 0xbb67ae85; ctx.state[2] = 0x3c6ef372; ctx.state[3] = 0xa54ff53a;
        ctx.state[4] = 0x510e527f; ctx.state[5] = 0x9b05688c; ctx.state[6] = 0x1f83d9ab; ctx.state[7] = 0x5be0cd19;
    }

    private static void sha256_update(Sha256Ctx ctx, byte[] data, int len) {
        for (int i = 0; i < len; i++) {
            ctx.data[ctx.datalen++] = data[i];
            if (ctx.datalen == 64) {
                sha256_transform(ctx, ctx.data);
                ctx.bitlen += 512;
                ctx.datalen = 0;
            }
        }
    }

    private static void sha256_final(Sha256Ctx ctx, byte[] hash /* 32 */) {
        int i = ctx.datalen;
        ctx.bitlen += (long) ctx.datalen * 8;

        /* Pad */
        ctx.data[i++] = (byte) 0x80;
        if (i > 56) {
            while (i < 64) ctx.data[i++] = 0x00;
            sha256_transform(ctx, ctx.data);
            i = 0;
        }
        while (i < 56) ctx.data[i++] = 0x00;

        /* Append length (big-endian) */
        long bitlen = ctx.bitlen;
        for (int j = 7; j >= 0; j--) ctx.data[i++] = (byte) ((bitlen >>> (j * 8)) & 0xFF);

        sha256_transform(ctx, ctx.data);

        for (int k = 0; k < 8; k++) {
            int v = ctx.state[k];
            hash[k * 4 + 0] = (byte) ((v >>> 24) & 0xFF);
            hash[k * 4 + 1] = (byte) ((v >>> 16) & 0xFF);
            hash[k * 4 + 2] = (byte) ((v >>> 8) & 0xFF);
            hash[k * 4 + 3] = (byte) (v & 0xFF);
        }
    }

    /* =========================
     *       Utilities
     * ========================= */

    private static final int BLOCK_SIZE = 16;
    private static final int READ_CHUNK = 64 * 1024;

    private static void be_bytes_to_words(byte[] in, int offset, long[] out2 /* len 2 */) {
        long a = 0L, b = 0L;
        for (int i = 0; i < 8; i++) a = (a << 8) | ((long) in[offset + i] & 0xFFL);
        for (int i = 8; i < 16; i++) b = (b << 8) | ((long) in[offset + i] & 0xFFL);
        out2[0] = a;
        out2[1] = b;
    }

    private static void be_words_to_bytes(long[] in2, byte[] out, int offset) {
        long a = in2[0], b = in2[1];
        for (int i = 7; i >= 0; i--) out[offset + (7 - i)] = (byte) ((a >>> (i * 8)) & 0xFF);
        for (int i = 7; i >= 0; i--) out[offset + (15 - i)] = (byte) ((b >>> (i * 8)) & 0xFF);
    }

    /* Password prompt with no echo (cross-platform) */
    private static String prompt_password(String prompt) throws IOException {
        // Java's best portable option is System.console().readPassword().
        // If the console is not available (e.g., IDE), we fallback to standard input (echoed).
        Console cons = System.console();
        if (cons != null) {
            char[] pw = cons.readPassword("%s", prompt);
            return pw == null ? "" : new String(pw);
        } else {
            System.out.print(prompt);
            System.out.flush();
            BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
            String s = br.readLine();
            return s == null ? "" : s;
        }
    }

    /* IV generation with fallback chain */
    private static void generate_iv(byte[] iv) {
        // We use SecureRandom. Try strongest first; if not available, fallback to default; as LAST RESORT, use java.util.Random.
        try {
            SecureRandom sr;
            try {
                sr = SecureRandom.getInstanceStrong();
            } catch (Exception e) {
                sr = new SecureRandom();
            }
            sr.nextBytes(iv);
        } catch (Exception e) {
            java.util.Random r = new java.util.Random(System.currentTimeMillis());
            for (int i = 0; i < iv.length; i++) iv[i] = (byte) r.nextInt(256);
        }
    }

    /* Derive 4096-bit key material from password using MD2II-based hashing,
       then expand to 64 subkeys. Password is treated as bytes (no hex parsing here). */
    private static void derive_gost_subkeys_from_password(String password, long[] subkeys) {
        byte[] h4 = new byte[n1];
        init_gost_keyhash();
        byte[] pbytes = password.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        hashing(pbytes, pbytes.length);
        end_gost_keyhash(h4);
        create_keys(h4, subkeys);
        // zero sensitive
        Arrays.fill(h4, (byte) 0);
    }

    /* PKCS#7 padding */
    private static int pkcs7_pad(byte[] buf, int used) {
        int pad = BLOCK_SIZE - (used % BLOCK_SIZE);
        for (int i = 0; i < pad; i++) buf[used + i] = (byte) pad;
        return used + pad;
    }

    private static boolean pkcs7_unpad(byte[] buf, int[] lenRef) {
        int len = lenRef[0];
        if (len == 0 || (len % BLOCK_SIZE) != 0) return false;
        int pad = buf[len - 1] & 0xFF;
        if (pad == 0 || pad > BLOCK_SIZE) return false;
        for (int i = 0; i < pad; i++) {
            if ((buf[len - 1 - i] & 0xFF) != pad) return false;
        }
        lenRef[0] = len - pad;
        return true;
    }

    /* Output filename helpers */
    private static boolean has_suffix(String name, String suffix) {
        return name.endsWith(suffix);
    }

    private static String make_output_name_encrypt(String in) {
        return in + ".gost2";
    }

    private static String make_output_name_decrypt(String in) {
        if (has_suffix(in, ".gost2")) {
            return in.substring(0, in.length() - 6);
        } else {
            return in + ".dec";
        }
    }

    /* =========================
     *   CBC Encrypt / Decrypt
     * ========================= */

    private static void cbc_encrypt_stream(InputStream fin, OutputStream fout, long[] subkeys, byte[] iv, boolean[] errOut, byte[] out_hash) throws IOException {
        /* Write IV first (clear) */
        try {
            fout.write(iv);
        } catch (IOException e) {
            errOut[0] = true; return;
        }

        byte[] inbuf = new byte[READ_CHUNK + BLOCK_SIZE];
        byte[] outbuf = new byte[READ_CHUNK + BLOCK_SIZE];
        byte[] prev = Arrays.copyOf(iv, BLOCK_SIZE);

        Sha256Ctx hctx = new Sha256Ctx(); sha256_init(hctx);

        int r;
        int carry = 0; // bytes carried from previous read (remainder not multiple of 16)

        while ((r = fin.read(inbuf, carry, READ_CHUNK)) >= 0) {
            if (r == -1) r = 0;
            r += carry;
            int full = (r / BLOCK_SIZE) * BLOCK_SIZE;
            int rem = r - full;

            // process full blocks
            for (int off = 0; off < full; off += BLOCK_SIZE) {
                for (int i = 0; i < BLOCK_SIZE; i++) inbuf[off + i] ^= prev[i];
                long[] inw = new long[2], outw = new long[2];
                be_bytes_to_words(inbuf, off, inw);
                gostcrypt(inw, outw, subkeys);
                be_words_to_bytes(outw, outbuf, off);
                System.arraycopy(outbuf, off, prev, 0, BLOCK_SIZE);
            }
            if (full > 0) {
                try {
                    fout.write(outbuf, 0, full);
                } catch (IOException e) { errOut[0] = true; return; }
                sha256_update(hctx, outbuf, full);
            }

            if (rem == 0) {
                carry = 0;
            } else {
                System.arraycopy(inbuf, full, inbuf, 0, rem);
                carry = rem;
            }

            // If end of stream reached, break to padding
            if (r - carry < READ_CHUNK) {
                break;
            }
        }

        // Final padding
        int total = pkcs7_pad(inbuf, carry);

        for (int off = 0; off < total; off += BLOCK_SIZE) {
            for (int i = 0; i < BLOCK_SIZE; i++) inbuf[off + i] ^= prev[i];
            long[] inw = new long[2], outw = new long[2];
            be_bytes_to_words(inbuf, off, inw);
            gostcrypt(inw, outw, subkeys);
            be_words_to_bytes(outw, outbuf, off);
            System.arraycopy(outbuf, off, prev, 0, BLOCK_SIZE);
        }
        try {
            fout.write(outbuf, 0, total);
        } catch (IOException e) { errOut[0] = true; return; }
        sha256_update(hctx, outbuf, total);

        /* Write SHA-256 over ciphertext only (not including IV) */
        sha256_final(hctx, out_hash);
        try {
            fout.write(out_hash);
        } catch (IOException e) { errOut[0] = true; }
    }

    private static void cbc_decrypt_stream(RandomAccessFile fin, OutputStream fout, long[] subkeys, boolean[] errOut, boolean[] auth_ok) throws IOException {
        auth_ok[0] = false;

        /* Determine file size to separate trailing 32-byte hash */
        long fsz = fin.length();
        if (fsz < (long)(BLOCK_SIZE + 32)) {
            System.err.println("Error: input too small.");
            errOut[0] = true; return;
        }

        long payload = fsz - 32; /* up to before hash */

        /* Read IV */
        fin.seek(0);
        byte[] iv = new byte[BLOCK_SIZE];
        if (fin.read(iv) != BLOCK_SIZE) { errOut[0] = true; return; }

        /* Read stored hash (at end) */
        fin.seek(payload);
        byte[] stored_hash = new byte[32];
        if (fin.read(stored_hash) != 32) { errOut[0] = true; return; }

        /* Prepare to stream-decrypt ciphertext (between IV and payload end) */
        fin.seek(BLOCK_SIZE);
        long remaining = payload - BLOCK_SIZE;
        if (remaining <= 0 || (remaining % BLOCK_SIZE) != 0) {
            System.err.println("Error: invalid ciphertext size.");
            errOut[0] = true; return;
        }

        byte[] prev = Arrays.copyOf(iv, BLOCK_SIZE);
        byte[] inbuf = new byte[READ_CHUNK];
        byte[] outbuf = new byte[READ_CHUNK];
        Sha256Ctx hctx = new Sha256Ctx(); sha256_init(hctx);

        while (remaining > 0) {
            int toread = (int) Math.min(remaining, (long) READ_CHUNK);
            // align to block
            toread -= (toread % BLOCK_SIZE);
            int r = fin.read(inbuf, 0, toread);
            if (r != toread) { errOut[0] = true; return; }

            /* hash ciphertext */
            sha256_update(hctx, inbuf, r);

            /* decrypt blocks */
            for (int off = 0; off < r; off += BLOCK_SIZE) {
                byte[] cpy = new byte[BLOCK_SIZE];
                System.arraycopy(inbuf, off, cpy, 0, BLOCK_SIZE);
                long[] inw = new long[2], outw = new long[2];
                be_bytes_to_words(inbuf, off, inw);
                gostdecrypt(inw, outw, subkeys);
                be_words_to_bytes(outw, outbuf, off);
                for (int i = 0; i < BLOCK_SIZE; i++) outbuf[off + i] ^= prev[i];
                System.arraycopy(cpy, 0, prev, 0, BLOCK_SIZE);
            }

            remaining -= r;
            if (remaining > 0) {
                try {
                    fout.write(outbuf, 0, r);
                } catch (IOException e) { errOut[0] = true; return; }
            } else {
                if (r < BLOCK_SIZE) { errOut[0] = true; return; }
                int keep = r - BLOCK_SIZE;
                if (keep > 0) {
                    try {
                        fout.write(outbuf, 0, keep);
                    } catch (IOException e) { errOut[0] = true; return; }
                }
                byte[] lastblk = Arrays.copyOfRange(outbuf, keep, keep + BLOCK_SIZE);
                int[] lastlenRef = new int[]{BLOCK_SIZE};
                if (!pkcs7_unpad(lastblk, lastlenRef)) {
                    System.err.println("Error: invalid padding.");
                    errOut[0] = true; return;
                }
                if (lastlenRef[0] > 0) {
                    try {
                        fout.write(lastblk, 0, lastlenRef[0]);
                    } catch (IOException e) { errOut[0] = true; return; }
                }
            }
        }

        /* Verify hash */
        byte[] calc_hash = new byte[32];
        sha256_final(hctx, calc_hash);
        auth_ok[0] = MessageDigest.isEqual(calc_hash, stored_hash);
    }

    /* =========================
     *            MAIN
     * ========================= */

    private static void usage(String prog) {
        System.err.printf("Usage: %s c|d <input_file>%n", prog);
    }

    public static void main(String[] args) {
        if (args.length != 2) { usage("Gost2File"); System.exit(1); }
        boolean mode_encrypt = false, mode_decrypt = false;
        if ("c".equals(args[0])) mode_encrypt = true;
        else if ("d".equals(args[0])) mode_decrypt = true;
        else { usage("Gost2File"); System.exit(1); }

        String inpath = args[1];
        String outpath = mode_encrypt ? make_output_name_encrypt(inpath) : make_output_name_decrypt(inpath);

        /* Open files */
        try (InputStream fin = mode_encrypt ? new BufferedInputStream(Files.newInputStream(Paths.get(inpath)))
                                            : null;
             RandomAccessFile raf = mode_decrypt ? new RandomAccessFile(inpath, "r") : null;
             OutputStream fout = new BufferedOutputStream(Files.newOutputStream(Paths.get(outpath)))) {

            if (mode_encrypt && fin == null) {
                System.err.printf("Error: cannot open input '%s'%n", inpath);
                System.exit(1);
            }
            if (mode_decrypt && raf == null) {
                System.err.printf("Error: cannot open input '%s'%n", inpath);
                System.exit(1);
            }

            /* Read password (not from CLI) */
            String password = "";
            try {
                password = prompt_password("Enter password: ");
            } catch (IOException ioe) {
                System.err.println("Error reading password.");
                try { Files.deleteIfExists(Paths.get(outpath)); } catch (IOException ignored) {}
                System.exit(1);
            }

            /* Init cipher tables and derive subkeys */
            kboxinit();
            long[] subkeys = new long[64];
            derive_gost_subkeys_from_password(password, subkeys);
            // Zero password string
            // Strings are immutable; we cannot zero their internal char[] portably.
            // In practice, prefer char[] for sensitive data. Here we just drop the reference.
            password = null;

            boolean[] err = new boolean[]{false};
            if (mode_encrypt) {
                byte[] iv = new byte[BLOCK_SIZE];
                byte[] hash_out = new byte[32];
                generate_iv(iv);
                try {
                    cbc_encrypt_stream(fin, fout, subkeys, iv, err, hash_out);
                } catch (IOException e) {
                    err[0] = true;
                }
                if (!err[0]) {
                    System.out.printf("Encryption completed. Output: %s%n", outpath);
                }
            } else {
                boolean[] auth_ok = new boolean[]{false};
                try {
                    cbc_decrypt_stream(raf, fout, subkeys, err, auth_ok);
                } catch (IOException e) {
                    err[0] = true;
                }
                if (!err[0]) {
                    System.out.printf("Decryption completed. Output: %s%n", outpath);
                    System.out.printf("Authentication %s%n", auth_ok[0] ? "OK" : "FAILED");
                }
            }

            if (err[0]) {
                System.err.println("Operation failed due to an error.");
                try { fout.flush(); } catch (IOException ignored) {}
                try { Files.deleteIfExists(Paths.get(outpath)); } catch (IOException ignored) {}
                System.exit(2);
            }
        } catch (IOException e) {
            System.err.printf("Error: %s%n", e.getMessage());
            try { Files.deleteIfExists(Paths.get(outpath)); } catch (IOException ignored) {}
            System.exit(1);
        }
    }
}
