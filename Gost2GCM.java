/** File encryption with GOST2-128 in GCM mode.
 * javac Gost2GCM.java 
 * java Gost2GCM 
 *
 */

import java.io.*;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Arrays;

public class Gost2GCM {

    /* ---------------------- No-echo password input ---------------------- */
    // Java adaptation: use System.console(). If unavailable (IDE), fallback to buffered stdin.
    private static String getPassword() throws IOException {
        Console console = System.console();
        if (console != null) {
            char[] p = console.readPassword("Enter password: ");
            return new String(p);
        } else {
            System.out.print("Enter password: ");
            BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
            return br.readLine();
        }
    }

    /* ---------------------- Portable secure random ---------------------- */
    // Java adaptation: use standard SecureRandom (strong RNG).
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private static int secure_random_bytes(byte[] buf, int off, int len) {
        SECURE_RANDOM.nextBytes(buf); // fills entire array; we’ll respect off/len by copying
        if (off == 0 && len == buf.length) return 0;
        byte[] tmp = new byte[len];
        SECURE_RANDOM.nextBytes(tmp);
        System.arraycopy(tmp, 0, buf, off, len);
        return 0;
    }

    /* Last-resort weak RNG (only if all above fail) */
    // Java adaptation: not used since SecureRandom is always available; keep stub for parity.
    private static void fallback_weak_rng(byte[] buf) {
        SECURE_RANDOM.nextBytes(buf);
    }

    private static void get_iv_16(byte[] iv) {
        int rc = secure_random_bytes(iv, 0, 16);
        if (rc != 0) {
            System.err.println("WARNING: secure RNG unavailable; using weak fallback.");
            fallback_weak_rng(iv);
        }
    }

    /* ---------------------- GOST2-128 cipher (from provided code) ---------------------- */

    // typedef uint64_t word64;  -> Java long (signed 64, but arithmetic wraps like C unsigned).

    private static final int n1 = 512; /* 4096-bit GOST2-128 key for 64 * 64-bit subkeys */

    private static int x1, x2, i_;
    private static final byte[] h2 = new byte[n1];
    private static final byte[] h1 = new byte[n1 * 3];

    private static void init_hashing() {
        x1 = 0; x2 = 0;
        Arrays.fill(h2, (byte)0);
        Arrays.fill(h1, (byte)0);
    }

    private static final int[] s4 = new int[] {
        13,199,11,67,237,193,164,77,115,184,141,222,73,38,147,36,150,87,21,104,12,61,156,101,111,145,
        119,22,207,35,198,37,171,167,80,30,219,28,213,121,86,29,214,242,6,4,89,162,110,175,19,157,
        3,88,234,94,144,118,159,239,100,17,182,173,238,68,16,79,132,54,163,52,9,58,57,55,229,192,
        170,226,56,231,187,158,70,224,233,245,26,47,32,44,247,8,251,20,197,185,109,153,204,218,93,178,
        212,137,84,174,24,120,130,149,72,180,181,208,255,189,152,18,143,176,60,249,27,227,128,139,243,253,
        59,123,172,108,211,96,138,10,215,42,225,40,81,65,90,25,98,126,154,64,124,116,122,5,1,168,83,190,
        131,191,244,240,235,177,155,228,125,66,43,201,248,220,129,188,230,62,75,71,78,34,31,216,254,136,91,
        114,106,46,217,196,92,151,209,133,51,236,33,252,127,179,69,7,183,105,146,97,39,15,205,112,200,166,
        223,45,48,246,186,41,148,140,107,76,85,95,194,142,50,49,134,23,135,169,221,210,203,63,165,82,161,
        202,53,14,206,232,103,102,195,117,250,99,0,74,160,241,2,113
    };

    private static void hashing(byte[] t1, int b6) {
        int b1,b2,b3,b4,b5; b4=0; b2=0;
        while (b6 != 0) {
            for (; b6 != 0 && x2 < n1; b6--, x2++) {
                b5 = t1[b4++] & 0xFF;
                h1[x2 + n1] = (byte)b5;
                h1[x2 + (n1*2)] = (byte)((b5 ^ (h1[x2] & 0xFF)) & 0xFF);
                int v = ((h2[x2] & 0xFF) ^ s4[(b5 ^ x1) & 0xFF]) & 0xFF;
                h2[x2] = (byte)v;
                x1 = v;
            }
            if (x2 == n1) {
                b2 = 0; x2 = 0;
                for (b3 = 0; b3 < (n1+2); b3++) {
                    for (b1 = 0; b1 < (n1*3); b1++) {
                        int nv = ((h1[b1] & 0xFF) ^ s4[b2 & 0xFF]) & 0xFF;
                        h1[b1] = (byte)nv;
                        b2 = nv;
                    }
                    b2 = (b2 + b3) % 256;
                }
            }
        }
    }

    private static void end_hash(byte[] h4 /* n1 */) {
        byte[] h3 = new byte[n1];
        int n4 = n1 - x2;
        Arrays.fill(h3, 0, n4, (byte)n4);
        hashing(h3, n4);
        hashing(h2, h2.length);
        System.arraycopy(h1, 0, h4, 0, n1);
    }

    /* create 64 * 64-bit subkeys from h4 hash */
    private static void create_keys(byte[] h4, long[] key /* 64 */) {
        int k = 0;
        for (int i = 0; i < 64; i++) {
            long v = 0L;
            for (int z = 0; z < 8; z++) {
                v = (v << 8) | (long)(h4[k++] & 0xFFL);
            }
            key[i] = v;
        }
    }

    /* S-boxes / tables */
    private static final byte[] k1_  = { 0x4,0xA,0x9,0x2,0xD,0x8,0x0,0xE,0x6,0xB,0x1,0xC,0x7,0xF,0x5,0x3 };
    private static final byte[] k2_  = { 0xE,0xB,0x4,0xC,0x6,0xD,0xF,0xA,0x2,0x3,0x8,0x1,0x0,0x7,0x5,0x9 };
    private static final byte[] k3_  = { 0x5,0x8,0x1,0xD,0xA,0x3,0x4,0x2,0xE,0xF,0xC,0x7,0x6,0x0,0x9,0xB };
    private static final byte[] k4_  = { 0x7,0xD,0xA,0x1,0x0,0x8,0x9,0xF,0xE,0x4,0x6,0xC,0xB,0x2,0x5,0x3 };
    private static final byte[] k5_  = { 0x6,0xC,0x7,0x1,0x5,0xF,0xD,0x8,0x4,0xA,0x9,0xE,0x0,0x3,0xB,0x2 };
    private static final byte[] k6_  = { 0x4,0xB,0xA,0x0,0x7,0x2,0x1,0xD,0x3,0x6,0x8,0x5,0x9,0xC,0xF,0xE };
    private static final byte[] k7_  = { 0xD,0xB,0x4,0x1,0x3,0xF,0x5,0x9,0x0,0xA,0xE,0x7,0x6,0x8,0x2,0xC };
    private static final byte[] k8_  = { 0x1,0xF,0xD,0x0,0x5,0x7,0xA,0x4,0x9,0x2,0x3,0xE,0x6,0xB,0x8,0xC };
    private static final byte[] k9_  = { 0xC,0x4,0x6,0x2,0xA,0x5,0xB,0x9,0xE,0x8,0xD,0x7,0x0,0x3,0xF,0x1 };
    private static final byte[] k10_ = { 0x6,0x8,0x2,0x3,0x9,0xA,0x5,0xC,0x1,0xE,0x4,0x7,0xB,0xD,0x0,0xF };
    private static final byte[] k11_ = { 0xB,0x3,0x5,0x8,0x2,0xF,0xA,0xD,0xE,0x1,0x7,0x4,0xC,0x9,0x6,0x0 };
    private static final byte[] k12_ = { 0xC,0x8,0x2,0x1,0xD,0x4,0xF,0x6,0x7,0x0,0xA,0x5,0x3,0xE,0x9,0xB };
    private static final byte[] k13_ = { 0x7,0xF,0x5,0xA,0x8,0x1,0x6,0xD,0x0,0x9,0x3,0xE,0xB,0x4,0x2,0xC };
    private static final byte[] k14_ = { 0x5,0xD,0xF,0x6,0x9,0x2,0xC,0xA,0xB,0x7,0x8,0x1,0x4,0x3,0xE,0x0 };
    private static final byte[] k15_ = { 0x8,0xE,0x2,0x5,0x6,0x9,0x1,0xC,0xF,0x4,0xB,0x0,0xD,0xA,0x3,0x7 };
    private static final byte[] k16_ = { 0x1,0x7,0xE,0xD,0x0,0x5,0x8,0x3,0x4,0xF,0xA,0x6,0x9,0xC,0xB,0x2 };

    private static final byte[] k175 = new byte[256], k153 = new byte[256], k131 = new byte[256], k109 = new byte[256];
    private static final byte[] k87 = new byte[256], k65 = new byte[256], k43 = new byte[256], k21 = new byte[256];

    private static void kboxinit() {
        for (int i = 0; i < 256; i++) {
            k175[i] = (byte)(( (k16_[(i >> 4) & 15] & 0xF) << 4) | (k15_[i & 15] & 0xF));
            k153[i] = (byte)(( (k14_[(i >> 4) & 15] & 0xF) << 4) | (k13_[i & 15] & 0xF));
            k131[i] = (byte)(( (k12_[(i >> 4) & 15] & 0xF) << 4) | (k11_[i & 15] & 0xF));
            k109[i] = (byte)(( (k10_[(i >> 4) & 15] & 0xF) << 4) | (k9_[i & 15] & 0xF));
            k87[i]  = (byte)(( (k8_[(i >> 4) & 15]  & 0xF) << 4) | (k7_[i & 15] & 0xF));
            k65[i]  = (byte)(( (k6_[(i >> 4) & 15]  & 0xF) << 4) | (k5_[i & 15] & 0xF));
            k43[i]  = (byte)(( (k4_[(i >> 4) & 15]  & 0xF) << 4) | (k3_[i & 15] & 0xF));
            k21[i]  = (byte)(( (k2_[(i >> 4) & 15]  & 0xF) << 4) | (k1_[i & 15] & 0xF));
        }
    }

    private static long toUInt32(long x) { return x & 0xFFFFFFFFL; }

    private static long f_gost(long x) {
        long y = (x >>> 32) & 0xFFFFFFFFL;
        long z = x & 0xFFFFFFFFL;

        int y0 = (int)((y >>> 24) & 0xFF);
        int y1 = (int)((y >>> 16) & 0xFF);
        int y2 = (int)((y >>> 8)  & 0xFF);
        int y3 = (int)(y & 0xFF);

        int z0 = (int)((z >>> 24) & 0xFF);
        int z1 = (int)((z >>> 16) & 0xFF);
        int z2 = (int)((z >>> 8)  & 0xFF);
        int z3 = (int)(z & 0xFF);

        long yy = ((long)(k87[y0] & 0xFF) << 24)
                | ((long)(k65[y1] & 0xFF) << 16)
                | ((long)(k43[y2] & 0xFF) << 8)
                | ((long)(k21[y3] & 0xFF));
        long zz = ((long)(k175[z0] & 0xFF) << 24)
                | ((long)(k153[z1] & 0xFF) << 16)
                | ((long)(k131[z2] & 0xFF) << 8)
                | ((long)(k109[z3] & 0xFF));

        long out = ((yy & 0xFFFFFFFFL) << 32) | (zz & 0xFFFFFFFFL);
        // rotate left by 11 on 64-bit
        return (out << 11) | (out >>> (64 - 11));
    }

    private static void gostcrypt(long[] in /*2*/, long[] out /*2*/, long[] key /*64*/) {
        long a = in[0], b = in[1];
        int k = 0;
        for (int r = 0; r < 32; r++) {
            b ^= f_gost(a + key[k++]);
            a ^= f_gost(b + key[k++]);
        }
        out[0] = b; out[1] = a;
    }

    @SuppressWarnings("unused")
    private static void gostdecrypt(long[] in, long[] out, long[] key) {
        long a = in[0], b = in[1];
        int k = 63;
        for (int r=0; r<32; r++) {
            b ^= f_gost(a + key[k--]);
            a ^= f_gost(b + key[k--]);
        }
        out[0] = b; out[1] = a;
    }

    /* ---------------------- GCM helpers (128-bit ops) ---------------------- */

    // Java adaptation: represent be128 as pair of unsigned 64 stored in long.
    private static final class be128 {
        long hi, lo;
        be128(long hi, long lo) { this.hi = hi; this.lo = lo; }
    }

    /* big-endian logical 128-bit */
    private static be128 load_be128(byte[] b, int off) {
        long hi = 0L, lo = 0L;
        for (int i = 0; i < 8; i++) hi = (hi << 8) | (b[off + i] & 0xFFL);
        for (int i = 8; i < 16; i++) lo = (lo << 8) | (b[off + i] & 0xFFL);
        return new be128(hi, lo);
    }

    private static void store_be128(be128 x, byte[] b, int off) {
        for (int i = 7; i >= 0; i--) { b[off + i] = (byte)(x.hi & 0xFF); x.hi >>>= 8; }
        for (int i = 15; i >= 8; i--) { b[off + i] = (byte)(x.lo & 0xFF); x.lo >>>= 8; }
    }

    private static be128 be128_xor(be128 a, be128 b) {
        return new be128(a.hi ^ b.hi, a.lo ^ b.lo);
    }

    /* right shift by 1 bit (big-endian logical value) */
    private static be128 be128_shr1(be128 v) {
        long lo = (v.lo >>> 1) | ((v.hi & 1L) << 63);
        long hi = (v.hi >>> 1);
        return new be128(hi, lo);
    }

    /* left shift by 1 bit */
    private static be128 be128_shl1(be128 v) {
        long hi = (v.hi << 1) | ((v.lo >>> 63) & 1L);
        long lo = (v.lo << 1);
        return new be128(hi, lo);
    }

    /* GF(2^128) multiplication per SP 800-38D, right-shift method */
    private static be128 gf_mult(be128 X, be128 Y) {
        be128 Z = new be128(0,0);
        be128 V = new be128(Y.hi, Y.lo);
        /* R = 0xE1000000000000000000000000000000 (big-endian) */
        final be128 R = new be128(0xE100000000000000L, 0x0000000000000000L);

        for (int i=0;i<128;i++) {
            long msb = (X.hi & 0x8000000000000000L);
            if (msb != 0) Z = be128_xor(Z, V);
            long lsb = (V.lo & 1L);
            V = be128_shr1(V);
            if (lsb != 0) V = be128_xor(V, R);
            X = be128_shl1(X);
        }
        return Z;
    }

    /* GHASH update: Y <- (Y ^ X) * H */
    private static void ghash_update(be128[] Yref, be128 H, byte[] block, int off) {
        be128 X = load_be128(block, off);
        Yref[0] = gf_mult(be128_xor(Yref[0], X), H);
    }

    /* Encrypt a single 16-byte block with GOST2-128 */
    private static void gost_encrypt_block(byte[] in, int inOff, byte[] out, int outOff, long[] key) {
        long inw0 = 0L, inw1 = 0L;
        for (int i = 0; i < 8; i++) inw0 = (inw0 << 8) | (in[inOff + i] & 0xFFL);
        for (int i = 0; i < 8; i++) inw1 = (inw1 << 8) | (in[inOff + 8 + i] & 0xFFL);
        long[] inw = new long[]{inw0, inw1};
        long[] outw = new long[2];
        gostcrypt(inw, outw, key);
        for (int i = 7; i >= 0; i--) { out[outOff + i] = (byte)(outw[0] & 0xFF); outw[0] >>>= 8; }
        for (int i = 15; i >= 8; i--) { out[outOff + i] = (byte)(outw[1] & 0xFF); outw[1] >>>= 8; }
    }

    /* Compute H = E_K(0^128) */
    private static void compute_H(byte[] H, long[] key) {
        byte[] zero = new byte[16];
        gost_encrypt_block(zero, 0, H, 0, key);
    }

    /* inc32 on the last 32 bits of a 128-bit counter (big-endian) */
    private static void inc32(byte[] ctr) {
        int c = ((ctr[12] & 0xFF) << 24) | ((ctr[13] & 0xFF) << 16) |
                ((ctr[14] & 0xFF) << 8) | (ctr[15] & 0xFF);
        c = (c + 1);
        ctr[12] = (byte)((c >>> 24) & 0xFF);
        ctr[13] = (byte)((c >>> 16) & 0xFF);
        ctr[14] = (byte)((c >>> 8) & 0xFF);
        ctr[15] = (byte)(c & 0xFF);
    }

    /* Derive J0 from IV (generic case when IV != 12 bytes) */
    private static void derive_J0(byte[] J0, byte[] iv, int ivlen, be128 Hbe) {
        /* Y = 0 */
        be128[] Y = new be128[]{ new be128(0,0) };
        byte[] block = new byte[16];

        /* Process full 16-byte blocks of IV */
        int off = 0;
        while (ivlen - off >= 16) {
            ghash_update(Y, Hbe, iv, off);
            off += 16;
        }
        /* Last partial block (pad with zeros) */
        if (ivlen - off > 0) {
            Arrays.fill(block, (byte)0);
            System.arraycopy(iv, off, block, 0, ivlen - off);
            ghash_update(Y, Hbe, block, 0);
        }
        /* Append 128-bit length block: 64-bit zeros || [len(IV) in bits]_64 */
        Arrays.fill(block, (byte)0);
        long ivbits = ((long)ivlen) * 8L;
        block[8]  = (byte)((ivbits >>> 56) & 0xFF);
        block[9]  = (byte)((ivbits >>> 48) & 0xFF);
        block[10] = (byte)((ivbits >>> 40) & 0xFF);
        block[11] = (byte)((ivbits >>> 32) & 0xFF);
        block[12] = (byte)((ivbits >>> 24) & 0xFF);
        block[13] = (byte)((ivbits >>> 16) & 0xFF);
        block[14] = (byte)((ivbits >>> 8) & 0xFF);
        block[15] = (byte)(ivbits & 0xFF);
        ghash_update(Y, Hbe, block, 0);

        store_be128(Y[0], J0, 0);
    }

    /* Prepares GHASH lengths block for AAD(empty) and C(lenC) */
    private static void ghash_lengths_update(be128[] Y, be128 Hbe, long aad_bits, long c_bits) {
        byte[] lenblk = new byte[16];
        // [len(AAD)]_64 || [len(C)]_64
        // first 8 bytes zero (aad_bits=0), next 8 are c_bits
        lenblk[8]  = (byte)((c_bits >>> 56) & 0xFF);
        lenblk[9]  = (byte)((c_bits >>> 48) & 0xFF);
        lenblk[10] = (byte)((c_bits >>> 40) & 0xFF);
        lenblk[11] = (byte)((c_bits >>> 32) & 0xFF);
        lenblk[12] = (byte)((c_bits >>> 24) & 0xFF);
        lenblk[13] = (byte)((c_bits >>> 16) & 0xFF);
        lenblk[14] = (byte)((c_bits >>> 8) & 0xFF);
        lenblk[15] = (byte)(c_bits & 0xFF);
        ghash_update(Y, Hbe, lenblk, 0);
    }

    /* Constant-time tag comparison */
    private static int ct_memcmp(byte[] a, byte[] b, int n) {
        int r = 0;
        for (int i = 0; i < n; i++) r |= (a[i] ^ b[i]);
        return r; /* 0 if equal */
    }

    /* ---------------------- File name helpers ---------------------- */
    private static String add_suffix_gost2(String in) {
        return in + ".gost2";
    }

    private static String strip_suffix_gost2(String in) {
        String suf = ".gost2";
        if (in.endsWith(suf)) return in.substring(0, in.length() - suf.length());
        return in + ".dec";
    }

    /* ---------------------- High-level encrypt/decrypt ---------------------- */

    private static final int BUF_CHUNK = 4096;

    private static int encrypt_file(String infile, String outfile, long[] key) {
        try (InputStream fi = new BufferedInputStream(new FileInputStream(infile));
             OutputStream fo = new BufferedOutputStream(new FileOutputStream(outfile))) {

            /* Compute H and J0 */
            byte[] H = new byte[16]; compute_H(H, key);
            be128 Hbe = load_be128(H, 0);

            byte[] iv = new byte[16];
            get_iv_16(iv);

            /* Write IV (16 bytes) */
            fo.write(iv);

            byte[] J0 = new byte[16];
            derive_J0(J0, iv, 16, Hbe);

            /* S = GHASH over ciphertext (starts at 0) */
            be128[] S = new be128[]{ new be128(0,0) };

            /* Counter starts from inc32(J0) */
            byte[] ctr = Arrays.copyOf(J0, 16);
            inc32(ctr);

            /* Streaming encrypt */
            byte[] inbuf = new byte[BUF_CHUNK];
            int r;
            long total_c_bytes = 0;

            while ((r = fi.read(inbuf)) > 0) {
                int off = 0;
                while (off < r) {
                    byte[] ks = new byte[16];
                    byte[] cblk = new byte[16];
                    byte[] pblk = new byte[16];
                    int n = Math.min(16, r - off);

                    /* keystream = E_K(ctr) */
                    gost_encrypt_block(ctr, 0, ks, 0, key);
                    inc32(ctr);

                    /* P block (pad with zeros for XOR; we only write n bytes) */
                    Arrays.fill(pblk, (byte)0);
                    System.arraycopy(inbuf, off, pblk, 0, n);

                    for (int i = 0; i < n; i++) cblk[i] = (byte)( (pblk[i] ^ ks[i]) & 0xFF );
                    if (n < 16) Arrays.fill(cblk, n, 16, (byte)0); /* pad for GHASH */

                    /* Update GHASH with ciphertext block (padded for partial) */
                    ghash_update(S, Hbe, cblk, 0);

                    /* Write ciphertext bytes (only n bytes) */
                    fo.write(cblk, 0, n);

                    total_c_bytes += n;
                    off += n;
                }
            }

            /* S <- S ⊗ H with lengths block (AAD=0, C=total_c_bytes) */
            ghash_lengths_update(S, Hbe, 0, total_c_bytes * 8L);

            /* Tag T = E_K(J0) XOR S */
            byte[] EJ0 = new byte[16], Tag = new byte[16];
            gost_encrypt_block(J0, 0, EJ0, 0, key);
            byte[] Sbytes = new byte[16]; store_be128(new be128(S[0].hi, S[0].lo), Sbytes, 0);
            for (int i=0;i<16;i++) Tag[i] = (byte)((EJ0[i] ^ Sbytes[i]) & 0xFF);

            /* Write TAG */
            fo.write(Tag);

            System.out.println("Encryption completed. Wrote IV + ciphertext + tag.");
            return 0;
        } catch (IOException e) {
            e.printStackTrace();
            return -1;
        }
    }

    private static int decrypt_file(String infile, String outfile, long[] key) {
        RandomAccessFile fi = null;
        OutputStream fo = null;
        try {
            fi = new RandomAccessFile(infile, "r");
            long fsz = fi.length();
            if (fsz < 32) { System.err.println("File too small (needs at least IV+TAG)."); return -1; }

            /* Read IV */
            fi.seek(0);
            byte[] iv = new byte[16];
            fi.readFully(iv);

            long remaining = fsz - 16;
            if (remaining < 16) { System.err.println("Missing tag."); return -1; }
            long ciph_len = remaining - 16;

            fo = new BufferedOutputStream(new FileOutputStream(outfile));

            /* Compute H and J0 as in encryption */
            byte[] H = new byte[16]; compute_H(H, key);
            be128 Hbe = load_be128(H, 0);
            byte[] J0 = new byte[16];
            derive_J0(J0, iv, 16, Hbe);

            /* GHASH S over ciphertext */
            be128[] S = new be128[]{ new be128(0,0) };

            /* CTR starts at inc32(J0) */
            byte[] ctr = Arrays.copyOf(J0, 16); inc32(ctr);

            /* Stream: read ciphertext (excluding last 16B tag), update GHASH, decrypt and write P immediately */
            byte[] buf = new byte[BUF_CHUNK];
            long left = ciph_len;
            long pos = 16;

            while (left > 0) {
                int toRead = (int)Math.min(BUF_CHUNK, left);
                fi.seek(pos);
                fi.readFully(buf, 0, toRead);

                int off = 0;
                while (off < toRead) {
                    byte[] ks = new byte[16];
                    byte[] cblk = new byte[16];
                    byte[] pblk = new byte[16];
                    int n = Math.min(16, toRead - off);

                    Arrays.fill(cblk, (byte)0);
                    System.arraycopy(buf, off, cblk, 0, n);

                    /* GHASH over ciphertext block */
                    ghash_update(S, Hbe, cblk, 0);

                    /* keystream */
                    gost_encrypt_block(ctr, 0, ks, 0, key);
                    inc32(ctr);

                    /* P = C XOR KS (only n bytes) */
                    for (int i=0;i<n;i++) pblk[i] = (byte)((cblk[i] ^ ks[i]) & 0xFF);

                    fo.write(pblk, 0, n);

                    off += n;
                }

                pos += toRead;
                left -= toRead;
            }

            /* Read the trailing TAG */
            byte[] Tag = new byte[16];
            fi.seek(16 + ciph_len);
            fi.readFully(Tag);

            /* Finalize GHASH with lengths */
            long c_bits = ciph_len * 8L;
            ghash_lengths_update(S, Hbe, 0, c_bits);

            /* Compute expected tag: E_K(J0) XOR S */
            byte[] EJ0 = new byte[16], Stmp = new byte[16], Tcalc = new byte[16];
            gost_encrypt_block(J0, 0, EJ0, 0, key);
            store_be128(new be128(S[0].hi, S[0].lo), Stmp, 0);
            for (int i=0;i<16;i++) Tcalc[i] = (byte)((EJ0[i] ^ Stmp[i]) & 0xFF);

            /* Constant-time compare */
            int diff = ct_memcmp(Tag, Tcalc, 16);
            if (diff == 0) {
                System.out.println("Authentication: OK");
                return 0;
            } else {
                System.out.println("Authentication: FAILED");
                return 1; /* non-zero to indicate failure */
            }
        } catch (IOException e) {
            e.printStackTrace();
            return -1;
        } finally {
            try { if (fi != null) fi.close(); } catch (IOException ignored) {}
            try { if (fo != null) fo.close(); } catch (IOException ignored) {}
        }
    }

    /* ---------------------- Derive GOST2-128 subkeys from password ---------------------- */
    private static void derive_key_from_password(String pwd, long[] key) {
        /* Follow the original code's hashing pipeline to build h4 then subkeys */
        byte[] h4 = new byte[n1];
        init_hashing();
        byte[] pbytes = pwd.getBytes(); // platform default is fine; original C used raw bytes from char*
        hashing(pbytes, pbytes.length);
        end_hash(h4);
        create_keys(h4, key);
    }

    /* ---------------------- Main ---------------------- */
    private static void usage(String prog) {
        System.err.printf("Usage: %s c|d <input_file>\n", prog);
    }

    public static void main(String[] args) {
        try {
            if (args.length != 2) { usage("java Gost2GCM"); System.exit(2); }

            String mode = args[0];
            String infile = args[1];

            String pwd = getPassword();
            if (pwd == null) { System.err.println("Failed to read password."); System.exit(2); }

            /* Init GOST2 tables and derive subkeys from password */
            kboxinit();
            long[] key = new long[64];
            derive_key_from_password(pwd, key);
            // Zero password buffer after use (best effort)
            // Java adaptation: Strings are immutable; overwrite reference and suggest GC.
            pwd = "\0";

            /* Build output file name */
            if (mode.equalsIgnoreCase("c")) {
                String outfile = add_suffix_gost2(infile);
                int rc = encrypt_file(infile, outfile, key);
                System.exit(rc == 0 ? 0 : 1);
            } else if (mode.equalsIgnoreCase("d")) {
                String outfile = strip_suffix_gost2(infile);
                int rc = decrypt_file(infile, outfile, key);
                System.exit(rc == 0 ? 0 : 1);
            } else {
                usage("java Gost2GCM");
                System.exit(2);
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(2);
        }
    }
}
