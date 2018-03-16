/**
 * EdDSA-Java by str4d
 *
 * To the extent possible under law, the person who associated CC0 with
 * EdDSA-Java has waived all copyright and related or neighboring rights
 * to EdDSA-Java.
 *
 * You should have received a copy of the CC0 legalcode along with this
 * work. If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
 *
 */
package net.i2p.crypto.eddsa;

/**
 * Basic utilities for EdDSA.
 * Not for external use, not maintained as a public API.
 *
 * @author str4d
 *
 */
public interface Utils {
    /**
     * Constant-time byte comparison.
     * @param b a byte
     * @param c a byte
     * @return 1 if b and c are equal, 0 otherwise.
     */
    static int equal(int b, int c) {
        int result = 0;
        int xor = b ^ c;
        result = result | xor >> 0;
        result = result | xor >> 1;
        result = result | xor >> 2;
        result = result | xor >> 3;
        result = result | xor >> 4;
        result = result | xor >> 5;
        result = result | xor >> 6;
        result = result | xor >> 7;
        return (result ^ 0x01) & 0x01;
    }

    /**
     * Constant-time byte[] comparison.
     * @param b a byte[]
     * @param c a byte[]
     * @return 1 if b and c are equal, 0 otherwise.
     */
    static int equal(byte[] b, byte[] c) {
        int result = 0;
        result = result | b[0] ^ c[0];
        result = result | b[1] ^ c[1];
        result = result | b[2] ^ c[2];
        result = result | b[3] ^ c[3];
        result = result | b[4] ^ c[4];
        result = result | b[5] ^ c[5];
        result = result | b[6] ^ c[6];
        result = result | b[7] ^ c[7];
        result = result | b[8] ^ c[8];
        result = result | b[9] ^ c[9];
        result = result | b[10] ^ c[10];
        result = result | b[11] ^ c[11];
        result = result | b[12] ^ c[12];
        result = result | b[13] ^ c[13];
        result = result | b[14] ^ c[14];
        result = result | b[15] ^ c[15];
        result = result | b[16] ^ c[16];
        result = result | b[17] ^ c[17];
        result = result | b[18] ^ c[18];
        result = result | b[19] ^ c[19];
        result = result | b[20] ^ c[20];
        result = result | b[21] ^ c[21];
        result = result | b[22] ^ c[22];
        result = result | b[23] ^ c[23];
        result = result | b[24] ^ c[24];
        result = result | b[25] ^ c[25];
        result = result | b[26] ^ c[26];
        result = result | b[27] ^ c[27];
        result = result | b[28] ^ c[28];
        result = result | b[29] ^ c[29];
        result = result | b[30] ^ c[30];
        result = result | b[31] ^ c[31];

        return equal(result, 0);
    }

    /**
     * Constant-time determine if byte is negative.
     * @param b the byte to check.
     * @return 1 if the byte is negative, 0 otherwise.
     */
    static int negative(int b) {
        return (b >> 8) & 1;
    }

    /**
     * Get the i'th bit of a byte array.
     * @param h the byte array.
     * @param i the bit index.
     * @return 0 or 1, the value of the i'th bit in h
     */
    static int bit(byte[] h, int i) {
        return (h[i >> 3] >> (i & 7)) & 1;
    }

    /**
     * Converts a hex string to bytes.
     * @param s the hex string to be converted.
     * @return the byte[]
     */
    static byte[] hexToBytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    /**
     * Converts bytes to a hex string.
     * @param raw the byte[] to be converted.
     * @return the hex representation as a string.
     */
    static String bytesToHex(byte[] raw) {
        if ( raw == null ) {
            return null;
        }
        final StringBuilder hex = new StringBuilder(2 * raw.length);
        for (final byte b : raw) {
            hex.append(Character.forDigit(((int) b & 0xF0) >> 4, 16))
            .append(Character.forDigit(((int) b & 0x0F), 16));
        }
        return hex.toString();
    }

}
