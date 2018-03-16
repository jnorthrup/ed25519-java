/**
 * EdDSA-Java by str4d
 *
 * To the extent possible under law, the person who associated CC0 with
 * EdDSA-Java has waived all copyright and related or neighboring rights
 * to EdDSA-Java.
 *
 * You should have received a copy of the CC0 legalcode along with this
 * work. If not, see <https:></https:>//creativecommons.org/publicdomain/zero/1.0/>.
 *
 */
package net.i2p.crypto.eddsa

/**
 * Basic utilities for EdDSA.
 * Not for external use, not maintained as a public API.
 *
 * @author str4d
 */
interface Utils {
    companion object {
        /**
         * Constant-time byte comparison.
         * @param b a byte
         * @param c a byte
         * @return 1 if b and c are equal, 0 otherwise.
         */
        fun equal(b: Int, c: Int): Int {
            var result = 0
            val xor = b xor c
            result = result or (xor shr 0)
            result = result or (xor shr 1)
            result = result or (xor shr 2)
            result = result or (xor shr 3)
            result = result or (xor shr 4)
            result = result or (xor shr 5)
            result = result or (xor shr 6)
            result = result or (xor shr 7)
            return result xor 0x01 and 0x01
        }

        /**
         * Constant-time byte[] comparison.
         * @param b a byte[]
         * @param c a byte[]
         * @return 1 if b and c are equal, 0 otherwise.
         */
        fun equal(b: ByteArray, c: ByteArray): Int {
            var result = 0
            result = result or (b[0] xor c[0])
            result = result or (b[1] xor c[1])
            result = result or (b[2] xor c[2])
            result = result or (b[3] xor c[3])
            result = result or (b[4] xor c[4])
            result = result or (b[5] xor c[5])
            result = result or (b[6] xor c[6])
            result = result or (b[7] xor c[7])
            result = result or (b[8] xor c[8])
            result = result or (b[9] xor c[9])
            result = result or (b[10] xor c[10])
            result = result or (b[11] xor c[11])
            result = result or (b[12] xor c[12])
            result = result or (b[13] xor c[13])
            result = result or (b[14] xor c[14])
            result = result or (b[15] xor c[15])
            result = result or (b[16] xor c[16])
            result = result or (b[17] xor c[17])
            result = result or (b[18] xor c[18])
            result = result or (b[19] xor c[19])
            result = result or (b[20] xor c[20])
            result = result or (b[21] xor c[21])
            result = result or (b[22] xor c[22])
            result = result or (b[23] xor c[23])
            result = result or (b[24] xor c[24])
            result = result or (b[25] xor c[25])
            result = result or (b[26] xor c[26])
            result = result or (b[27] xor c[27])
            result = result or (b[28] xor c[28])
            result = result or (b[29] xor c[29])
            result = result or (b[30] xor c[30])
            result = result or (b[31] xor c[31])

            return equal(result, 0)
        }

        /**
         * Constant-time determine if byte is negative.
         * @param b the byte to check.
         * @return 1 if the byte is negative, 0 otherwise.
         */
        fun negative(b: Int): Int {
            return b shr 8 and 1
        }

        /**
         * Get the i'th bit of a byte array.
         * @param h the byte array.
         * @param i the bit index.
         * @return 0 or 1, the value of the i'th bit in h
         */
        fun bit(h: ByteArray, i: Int): Int {
            return h[i shr 3] shr (i and 7) and 1
        }

        /**
         * Converts a hex string to bytes.
         * @param s the hex string to be converted.
         * @return the byte[]
         */
        fun hexToBytes(s: String): ByteArray {
            val len = s.length
            val data = ByteArray(len / 2)
            var i = 0
            while (i < len) {
                data[i / 2] = ((Character.digit(s[i], 16) shl 4) + Character.digit(s[i + 1], 16)).toByte()
                i += 2
            }
            return data
        }

        /**
         * Converts bytes to a hex string.
         * @param raw the byte[] to be converted.
         * @return the hex representation as a string.
         */
        fun bytesToHex(raw: ByteArray?): String? {
            if (null == raw) {
                return null
            }
            val hex = StringBuilder(2 * raw.size)
            for (b in raw) {
                hex.append(Character.forDigit(b.toInt() and 0xF0 shr 4, 16))
                        .append(Character.forDigit(b.toInt() and 0x0F, 16))
            }
            return hex.toString()
        }
    }

}
