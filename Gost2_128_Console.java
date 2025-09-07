import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * GOST2-128 Cipher - Java console version
 * This program demonstrates encryption and decryption with 3 example test vectors.
 * 
 * javac Gost2_128_Console.java 
 * java Gost2_128_Console
 *
 */
public class Gost2_128_Console {

    // Size constants
    static final int KEY_MATERIAL_SIZE = 512; // 4096-bit (512-byte) expanded key material

    // Internal state for the hashing-based key expansion
    static int hashStateX;
    static int hashStateY;
    static byte[] expandedKeyMaterial = new byte[KEY_MATERIAL_SIZE];
    static byte[] hashBuffer = new byte[KEY_MATERIAL_SIZE * 3];

    // Substitution box constants
    static final byte[] SBOX_K1  = { 0x4,0xA,0x9,0x2,0xD,0x8,0x0,0xE,0x6,0xB,0x1,0xC,0x7,0xF,0x5,0x3 };
    static final byte[] SBOX_K2  = { 0xE,0xB,0x4,0xC,0x6,0xD,0xF,0xA,0x2,0x3,0x8,0x1,0x0,0x7,0x5,0x9 };
    static final byte[] SBOX_K3  = { 0x5,0x8,0x1,0xD,0xA,0x3,0x4,0x2,0xE,0xF,0xC,0x7,0x6,0x0,0x9,0xB };
    static final byte[] SBOX_K4  = { 0x7,0xD,0xA,0x1,0x0,0x8,0x9,0xF,0xE,0x4,0x6,0xC,0xB,0x2,0x5,0x3 };
    static final byte[] SBOX_K5  = { 0x6,0xC,0x7,0x1,0x5,0xF,0xD,0x8,0x4,0xA,0x9,0xE,0x0,0x3,0xB,0x2 };
    static final byte[] SBOX_K6  = { 0x4,0xB,0xA,0x0,0x7,0x2,0x1,0xD,0x3,0x6,0x8,0x5,0x9,0xC,0xF,0xE };
    static final byte[] SBOX_K7  = { 0xD,0xB,0x4,0x1,0x3,0xF,0x5,0x9,0x0,0xA,0xE,0x7,0x6,0x8,0x2,0xC };
    static final byte[] SBOX_K8  = { 0x1,0xF,0xD,0x0,0x5,0x7,0xA,0x4,0x9,0x2,0x3,0xE,0x6,0xB,0x8,0xC };
    static final byte[] SBOX_K9  = { 0xC,0x4,0x6,0x2,0xA,0x5,0xB,0x9,0xE,0x8,0xD,0x7,0x0,0x3,0xF,0x1 };
    static final byte[] SBOX_K10 = { 0x6,0x8,0x2,0x3,0x9,0xA,0x5,0xC,0x1,0xE,0x4,0x7,0xB,0xD,0x0,0xF };
    static final byte[] SBOX_K11 = { 0xB,0x3,0x5,0x8,0x2,0xF,0xA,0xD,0xE,0x1,0x7,0x4,0xC,0x9,0x6,0x0 };
    static final byte[] SBOX_K12 = { 0xC,0x8,0x2,0x1,0xD,0x4,0xF,0x6,0x7,0x0,0xA,0x5,0x3,0xE,0x9,0xB };
    static final byte[] SBOX_K13 = { 0x7,0xF,0x5,0xA,0x8,0x1,0x6,0xD,0x0,0x9,0x3,0xE,0xB,0x4,0x2,0xC };
    static final byte[] SBOX_K14 = { 0x5,0xD,0xF,0x6,0x9,0x2,0xC,0xA,0xB,0x7,0x8,0x1,0x4,0x3,0xE,0x0 };
    static final byte[] SBOX_K15 = { 0x8,0xE,0x2,0x5,0x6,0x9,0x1,0xC,0xF,0x4,0xB,0x0,0xD,0xA,0x3,0x7 };
    static final byte[] SBOX_K16 = { 0x1,0x7,0xE,0xD,0x0,0x5,0x8,0x3,0x4,0xF,0xA,0x6,0x9,0xC,0xB,0x2 };

    // Byte-at-a-time substitution tables
    static final byte[] LUT_K175 = new byte[256];
    static final byte[] LUT_K153 = new byte[256];
    static final byte[] LUT_K131 = new byte[256];
    static final byte[] LUT_K109 = new byte[256];
    static final byte[] LUT_K87  = new byte[256];
    static final byte[] LUT_K65  = new byte[256];
    static final byte[] LUT_K43  = new byte[256];
    static final byte[] LUT_K21  = new byte[256];

    /** Initialize hashing state */
    static void initHashState() {
        hashStateX = 0;
        hashStateY = 0;
        Arrays.fill(expandedKeyMaterial, (byte)0);
        Arrays.fill(hashBuffer, (byte)0);
    }

    /** MD2II hashing to expand password into key material */
    static void hashing(byte[] input, int length) {
        final byte[] SBOX_S4 = {
            13, -57, 11, 67, -19, -63, -92, 77, 115, -72, -115, -34, 73,
            38, -109, 36, -106, 87, 21, 104, 12, 61, -100, 101, 111, -111,
            119, 22, -49, 35, -58, 37, -85, -89, 80, 30, -37, 28, -43,
            121, 86, 29, -42, -14, 6, 4, 89, -94, 110, -81, 19, -99,
            3, 88, -22, 94, -112, 118, -97, -17, 100, 17, -74, -83, -18,
            68, 16, 79, -124, 54, -93, 52, 9, 58, 57, 55, -27, -64,
            -86, -30, 56, -25, -69, -98, 70, -32, -23, -11, 26, 47, 32,
            44, -9, 8, -5, 20, -59, -71, 109, -103, -52, -38, 93, -78,
            -44, -119, 84, -82, 24, 120, -126, -107, 72, -76, -75, -48, -1,
            -67, -104, 18, -113, -80, 60, -7, 27, -29, -128, -117, -13, -3,
            59, 123, -84, 108, -45, 96, -118, 10, -41, 42, -31, 40, 81,
            65, 90, 25, 98, 126, -102, 64, 124, 116, 122, 5, 1, -88,
            83, -66, -125, -65, -12, -16, -21, -79, -101, -28, 125, 66, 43,
            -55, -8, -36, -127, -68, -26, 62, 75, 71, 78, 34, 31, -40,
            -2, -120, 91, 114, 106, 46, -39, -60, 92, -105, -47, -123, 51,
            -20, 33, -4, 127, -77, 69, 7, -73, 105, -110, 97, 39, 15,
            -51, 112, -56, -90, -33, 45, 48, -10, -70, 41, -108, -116, 107,
            76, 85, 95, -62, -114, 50, 49, -122, 23, -121, -87, -35, -46,
            -53, 63, -91, 82, -95, -54, 53, 14, -50, -24, 103, 102, -61,
            117, -6, 99, 0, 74, -96, -15, 2, 113
        };
        int tmpVal, idx = 0;
        while (length > 0) {
            for (; length > 0 && hashStateY < KEY_MATERIAL_SIZE; length--, hashStateY++) {
                int b = input[idx++] & 0xFF;
                hashBuffer[hashStateY + KEY_MATERIAL_SIZE] = (byte)b;
                hashBuffer[hashStateY + (KEY_MATERIAL_SIZE * 2)] = (byte)(b ^ hashBuffer[hashStateY]);
                hashStateX = (expandedKeyMaterial[hashStateY] = (byte)(expandedKeyMaterial[hashStateY] ^ SBOX_S4[(b ^ hashStateX) & 0xFF])) & 0xFF;
            }
            if (hashStateY == KEY_MATERIAL_SIZE) {
                tmpVal = 0;
                hashStateY = 0;
                for (int r = 0; r < (KEY_MATERIAL_SIZE + 2); r++) {
                    for (int i = 0; i < (KEY_MATERIAL_SIZE * 3); i++)
                        tmpVal = (hashBuffer[i] = (byte)(hashBuffer[i] ^ SBOX_S4[tmpVal & 0xFF])) & 0xFF;
                    tmpVal = (tmpVal + r) % 256;
                }
            }
        }
    }

    /** Finalize hash to produce expanded key material */
    static void finalizeHash(byte[] output) {
        byte[] pad = new byte[KEY_MATERIAL_SIZE];
        int padLen = KEY_MATERIAL_SIZE - hashStateY;
        Arrays.fill(pad, 0, padLen, (byte)padLen);
        hashing(pad, padLen);
        hashing(expandedKeyMaterial, expandedKeyMaterial.length);
        System.arraycopy(hashBuffer, 0, output, 0, KEY_MATERIAL_SIZE);
    }

    /** Generate 64 round keys from expanded key */
    static void generateRoundKeys(byte[] expanded, long[] roundKeys) {
        int idx = 0;
        for (int i = 0; i < 64; i++) {
            roundKeys[i] = 0;
            for (int j = 0; j < 8; j++) {
                roundKeys[i] = (roundKeys[i] << 8) + (expanded[idx++] & 0xFFL);
            }
        }
    }

    /** Build lookup tables */
    static void buildLUTs() {
        for (int i = 0; i < 256; i++) {
            LUT_K175[i] = (byte)((SBOX_K16[i >> 4] << 4) | SBOX_K15[i & 15]);
            LUT_K153[i] = (byte)((SBOX_K14[i >> 4] << 4) | SBOX_K13[i & 15]);
            LUT_K131[i] = (byte)((SBOX_K12[i >> 4] << 4) | SBOX_K11[i & 15]);
            LUT_K109[i] = (byte)((SBOX_K10[i >> 4] << 4) | SBOX_K9[i & 15]);
            LUT_K87[i]  = (byte)((SBOX_K8[i >> 4] << 4) | SBOX_K7[i & 15]);
            LUT_K65[i]  = (byte)((SBOX_K6[i >> 4] << 4) | SBOX_K5[i & 15]);
            LUT_K43[i]  = (byte)((SBOX_K4[i >> 4] << 4) | SBOX_K3[i & 15]);
            LUT_K21[i]  = (byte)((SBOX_K2[i >> 4] << 4) | SBOX_K1[i & 15]);
        }
    }

    /** Round function */
    static long roundFunc(long x) {
        long upper = (x >>> 32) & 0xFFFFFFFFL;
        long lower = x & 0xFFFFFFFFL;
        upper = ((LUT_K87[(int)((upper >>> 24) & 0xFF)] & 0xFFL) << 24)
              | ((LUT_K65[(int)((upper >>> 16) & 0xFF)] & 0xFFL) << 16)
              | ((LUT_K43[(int)((upper >>> 8) & 0xFF)] & 0xFFL) << 8)
              |  (LUT_K21[(int)(upper & 0xFF)] & 0xFFL);
        lower = ((LUT_K175[(int)((lower >>> 24) & 0xFF)] & 0xFFL) << 24)
              | ((LUT_K153[(int)((lower >>> 16) & 0xFF)] & 0xFFL) << 16)
              | ((LUT_K131[(int)((lower >>> 8) & 0xFF)] & 0xFFL) << 8)
              |  (LUT_K109[(int)(lower & 0xFF)] & 0xFFL);
        x = (upper << 32) | (lower & 0xFFFFFFFFL);
        return ((x << 11) | (x >>> (64 - 11))) & 0xFFFFFFFFFFFFFFFFL;
    }

    /** Encrypt one 128-bit block */
    static void encrypt(long[] in, long[] out, long[] roundKeys) {
        long left = in[0], right = in[1];
        int k = 0;
        for (int i = 0; i < 32; i++) {
            right ^= roundFunc(left + roundKeys[k++]);
            left ^= roundFunc(right + roundKeys[k++]);
        }
        out[0] = right;
        out[1] = left;
    }

    /** Decrypt one 128-bit block */
    static void decrypt(long[] in, long[] out, long[] roundKeys) {
        long left = in[0], right = in[1];
        int k = 63;
        for (int i = 0; i < 32; i++) {
            right ^= roundFunc(left + roundKeys[k--]);
            left ^= roundFunc(right + roundKeys[k--]);
        }
        out[0] = right;
        out[1] = left;
    }

    public static void main(String[] args) {
        buildLUTs();
        byte[] expanded = new byte[KEY_MATERIAL_SIZE];
        long[] roundKeys = new long[64];
        long[] plain = new long[2], cipher = new long[2], decrypted = new long[2];

        System.out.println("GOST2-128 Java Version");
        System.out.println("128-bit block, 4096-bit subkeys, 64 rounds\n");

        // EXAMPLE 1
        initHashState();
        byte[] keyText1 = "My secret password!0123456789abc".getBytes(StandardCharsets.US_ASCII);
        hashing(keyText1, 32);
        finalizeHash(expanded);
        generateRoundKeys(expanded, roundKeys);
        plain[0] = 0xFEFEFEFEFEFEFEFEL;
        plain[1] = 0xFEFEFEFEFEFEFEFEL;
        encrypt(plain, cipher, roundKeys);
        decrypt(cipher, decrypted, roundKeys);
        System.out.printf("Example 1:\nKey: %s\nPlain: %016X%016X\nCipher: %016X%016X\nDecrypted: %016X%016X\n\n",
                new String(keyText1), plain[0], plain[1], cipher[0], cipher[1], decrypted[0], decrypted[1]);

        // EXAMPLE 2
        initHashState();
        byte[] keyText2 = "My secret password!0123456789ABC".getBytes(StandardCharsets.US_ASCII);
        hashing(keyText2, keyText2.length);
        finalizeHash(expanded);
        generateRoundKeys(expanded, roundKeys);
        plain[0] = 0x0000000000000000L;
        plain[1] = 0x0000000000000000L;
        encrypt(plain, cipher, roundKeys);
        decrypt(cipher, decrypted, roundKeys);
        System.out.printf("Example 2:\nKey: %s\nPlain: %016X%016X\nCipher: %016X%016X\nDecrypted: %016X%016X\n\n",
                new String(keyText2), plain[0], plain[1], cipher[0], cipher[1], decrypted[0], decrypted[1]);

        // EXAMPLE 3
        initHashState();
        byte[] keyText3 = "My secret password!0123456789abZ".getBytes(StandardCharsets.US_ASCII);
        hashing(keyText3, keyText3.length);
        finalizeHash(expanded);
        generateRoundKeys(expanded, roundKeys);
        plain[0] = 0x0000000000000000L;
        plain[1] = 0x0000000000000001L;
        encrypt(plain, cipher, roundKeys);
        decrypt(cipher, decrypted, roundKeys);
        System.out.printf("Example 3:\nKey: %s\nPlain: %016X%016X\nCipher: %016X%016X\nDecrypted: %016X%016X\n",
                new String(keyText3), plain[0], plain[1], cipher[0], cipher[1], decrypted[0], decrypted[1]);
    }
}

/**
GOST2-128 Java Version
128-bit block, 4096-bit subkeys, 64 rounds

Example 1:
Key: My secret password!0123456789abc
Plain: FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE
Cipher: 8CA4C196B773D9C9A00AD3931F9B2B09
Decrypted: FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE

Example 2:
Key: My secret password!0123456789ABC
Plain: 00000000000000000000000000000000
Cipher: 96AB544910861D5B22B04FC984D80098
Decrypted: 00000000000000000000000000000000

Example 3:
Key: My secret password!0123456789abZ
Plain: 00000000000000000000000000000001
Cipher: ACF914AC22AE2079390BC240ED51916F
Decrypted: 00000000000000000000000000000001

*/
