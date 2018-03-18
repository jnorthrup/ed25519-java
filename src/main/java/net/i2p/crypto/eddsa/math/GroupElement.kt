package net.i2p.crypto.eddsa.math

import kotlin.experimental.and

interface GroupElement {

    val repr: Representation

    val x: FieldElement

    val y: FieldElement

    val z: FieldElement

    val t: FieldElement

    val precmp: Array<Array<GroupElement>>?

    val dblPrecmp: Array<GroupElement>?

    val curve: Curve

    val representation: Representation

    val isOnCurve: Boolean

    fun toByteArray(): ByteArray

    fun precomputeSingle(): Array<Array<GroupElement>>

    fun precomputeDouble(): Array<GroupElement>

    fun dbl(): GroupElement

    fun madd(q: GroupElement): GroupElement

    fun msub(q: GroupElement): GroupElement

    fun add(q: GroupElement): GroupElement

    fun sub(q: GroupElement): GroupElement

    fun negate(): GroupElement

    override fun hashCode(): Int

    override fun equals(obj: Any?): Boolean

    fun cmov(u: GroupElement, b: Int): PrecompGroupElement

    fun select(pos: Int, b: Int): PrecompGroupElement

    fun scalarMultiply(a: ByteArray): GroupElement

    fun doubleScalarMultiplyVariableTime(A: GroupElement, a: ByteArray, b: ByteArray): GroupElement

    fun isOnCurve(curve: Curve): Boolean

    override fun toString(): String

    companion object {
        /**
         * Calculates a sliding-windows base 2 representation for a given value $a$.
         * To learn more about it see [6] page 8.
         *
         *
         * Output: $r$ which satisfies
         * $a = r0 * 2^0 + r1 * 2^1 + \dots + r255 * 2^{255}$ with $ri$ in $\{-15, -13, -11, -9, -7, -5, -3, -1, 0, 1, 3, 5, 7, 9, 11, 13, 15\}$
         *
         *
         * Method is package public only so that tests run.
         *
         * @param a $= a[0]+256*a[1]+\dots+256^{31} a[31]$.
         * @return The byte array $r$ in the above described form.
         */
        fun slide(a: ByteArray): ByteArray {
            val r = ByteArray(256)

            // Put each bit of 'a' into a separate byte, 0 or 1
            run {
                var i = 0
                while (256 > i) {
                    r[i] = (1 and (a[i shr 3] as Int shr (i and 7))).toByte()
                    ++i
                }
            }

            // Note: r[i] will always be odd.
            var i = 0
            while (256 > i) {
                if (0 != r[i].toInt()) {
                    var b = 1
                    while (6 >= b && 256 > i + b) {
                        // Accumulate bits if possible
                        if (0 != r[i + b].toInt()) {
                            if (15 >= r[i] + (r[i + b]as Int  shl b)) {
                                r[i] = (r[i] + (r[i + b] as Int shl b)).toByte()
                                r[i + b] = 0.toByte()
                            } else if (-15 <= r[i] - (r[i + b]as Int  shl b)) {
                                r[i] = (r[i] - (r[i + b]as Int  shl b)).toByte()
                                var k = i + b
                                while (256 > k) {
                                    if (0 == r[k].toInt()) {
                                        r[k] = 1.toByte()
                                        break
                                    }
                                    r[k] = 0.toByte()
                                    ++k
                                }
                            } else
                                break
                        }
                        ++b
                    }
                }
                ++i
            }

            return r
        }

        /**
         * Convert a to radix 16.
         *
         * Method is package public only so that tests run.
         *
         * @param a $= a[0]+256*a[1]+...+256^{31} a[31]$
         * @return 64 bytes, each between -8 and 7
         */
        fun toRadix16(a: ByteArray): ByteArray {
            val e = ByteArray(64)

            // Radix 16 notation
            e[2 * 0] = (a[0] and 15).toByte()
            e[2 * 0 + 1] = (a[0]  as Int shr 4 and 15).toByte()
            e[2 * 1] = (a[1] and 15).toByte()
            e[2 * 1 + 1] = (a[1] as Int  shr 4 and 15).toByte()
            e[2 * 2] = (a[2] and 15).toByte()
            e[2 * 2 + 1] = (a[2] as Int  shr 4 and 15).toByte()
            e[2 * 3] = (a[3] and 15).toByte()
            e[2 * 3 + 1] = (a[3] as Int  shr 4 and 15).toByte()
            e[2 * 4] = (a[4] and 15).toByte()
            e[2 * 4 + 1] = (a[4]  as Int shr 4 and 15).toByte()
            e[2 * 5] = (a[5] and 15).toByte()
            e[2 * 5 + 1] = (a[5]  as Int shr 4 and 15).toByte()
            e[2 * 6] = (a[6] and 15).toByte()
            e[2 * 6 + 1] = (a[6] as Int  shr 4 and 15).toByte()
            e[2 * 7] = (a[7] and 15).toByte()
            e[2 * 7 + 1] = (a[7] as Int  shr 4 and 15).toByte()
            e[2 * 8] = (a[8] and 15).toByte()
            e[2 * 8 + 1] = (a[8] as Int  shr 4 and 15).toByte()
            e[2 * 9] = (a[9] and 15).toByte()
            e[2 * 9 + 1] = (a[9]  as Int shr 4 and 15).toByte()
            e[2 * 10] = (a[10] and 15).toByte()
            e[2 * 10 + 1] = (a[10] as Int shr 4 and 15).toByte()
            e[2 * 11] = (a[11] and 15).toByte()
            e[2 * 11 + 1] = (a[11]  as Int shr 4 and 15).toByte()
            e[2 * 12] = (a[12] and 15).toByte()
            e[2 * 12 + 1] = (a[12] as Int  shr 4 and 15).toByte()
            e[2 * 13] = (a[13] and 15).toByte()
            e[2 * 13 + 1] = (a[13] as Int  shr 4 and 15).toByte()
            e[2 * 14] = (a[14] and 15).toByte()
            e[2 * 14 + 1] = (a[14] as Int  shr 4 and 15).toByte()
            e[2 * 15] = (a[15] and 15).toByte()
            e[2 * 15 + 1] = (a[15]  as Int shr 4 and 15).toByte()
            e[2 * 16] = (a[16] and 15).toByte()
            e[2 * 16 + 1] = (a[16] as Int  shr 4 and 15).toByte()
            e[2 * 17] = (a[17] and 15).toByte()
            e[2 * 17 + 1] = (a[17]  as Int shr 4 and 15).toByte()
            e[2 * 18] = (a[18] and 15).toByte()
            e[2 * 18 + 1] = (a[18] as Int  shr 4 and 15).toByte()
            e[2 * 19] = (a[19] and 15).toByte()
            e[2 * 19 + 1] = (a[19] as Int  shr 4 and 15).toByte()
            e[2 * 20] = (a[20] and 15).toByte()
            e[2 * 20 + 1] = (a[20] as Int  shr 4 and 15).toByte()
            e[2 * 21] = (a[21] and 15).toByte()
            e[2 * 21 + 1] = (a[21]  as Int shr 4 and 15).toByte()
            e[2 * 22] = (a[22] and 15).toByte()
            e[2 * 22 + 1] = (a[22] as Int  shr 4 and 15).toByte()
            e[2 * 23] = (a[23] and 15).toByte()
            e[2 * 23 + 1] = (a[23] as Int  shr 4 and 15).toByte()
            e[2 * 24] = (a[24] and 15).toByte()
            e[2 * 24 + 1] = (a[24]  as Int shr 4 and 15).toByte()
            e[2 * 25] = (a[25] and 15).toByte()
            e[2 * 25 + 1] = (a[25] as Int  shr 4 and 15).toByte()
            e[2 * 26] = (a[26] and 15).toByte()
            e[2 * 26 + 1] = (a[26]  as Int shr 4 and 15).toByte()
            e[2 * 27] = (a[27] and 15).toByte()
            e[2 * 27 + 1] = (a[27]  as Int shr 4 and 15).toByte()
            e[2 * 28] = (a[28] and 15).toByte()
            e[2 * 28 + 1] = (a[28] as Int  shr 4 and 15).toByte()
            e[2 * 29] = (a[29] and 15).toByte()
            e[2 * 29 + 1] = (a[29]  as Int shr 4 and 15).toByte()
            e[2 * 30] = (a[30] and 15).toByte()
            e[2 * 30 + 1] = (a[30] as Int  shr 4 and 15).toByte()
            e[2 * 31] = (a[31] and 15).toByte()
            e[2 * 31 + 1] = (a[31]  as Int shr 4 and 15).toByte()
            /* each e[i] is between 0 and 15 */
            /* e[63] is between 0 and 7 */
            var carry = 0
            e[0] = (e[0] + carry).toByte()
            carry = e[0] + 8
            carry = carry shr 4
            e[0] = (e[0] - (carry shl 4)).toByte()
            e[1] = (e[1] + carry).toByte()
            carry = e[1] + 8
            carry = carry shr 4
            e[1] = (e[1] - (carry shl 4)).toByte()
            e[2] = (e[2] + carry).toByte()
            carry = e[2] + 8
            carry = carry shr 4
            e[2] = (e[2] - (carry shl 4)).toByte()
            e[3] = (e[3] + carry).toByte()
            carry = e[3] + 8
            carry = carry shr 4
            e[3] = (e[3] - (carry shl 4)).toByte()
            e[4] = (e[4] + carry).toByte()
            carry = e[4] + 8
            carry = carry shr 4
            e[4] = (e[4] - (carry shl 4)).toByte()
            e[5] = (e[5] + carry).toByte()
            carry = e[5] + 8
            carry = carry shr 4
            e[5] = (e[5] - (carry shl 4)).toByte()
            e[6] = (e[6] + carry).toByte()
            carry = e[6] + 8
            carry = carry shr 4
            e[6] = (e[6] - (carry shl 4)).toByte()
            e[7] = (e[7] + carry).toByte()
            carry = e[7] + 8
            carry = carry shr 4
            e[7] = (e[7] - (carry shl 4)).toByte()
            e[8] = (e[8] + carry).toByte()
            carry = e[8] + 8
            carry = carry shr 4
            e[8] = (e[8] - (carry shl 4)).toByte()
            e[9] = (e[9] + carry).toByte()
            carry = e[9] + 8
            carry = carry shr 4
            e[9] = (e[9] - (carry shl 4)).toByte()
            e[10] = (e[10] + carry).toByte()
            carry = e[10] + 8
            carry = carry shr 4
            e[10] = (e[10] - (carry shl 4)).toByte()
            e[11] = (e[11] + carry).toByte()
            carry = e[11] + 8
            carry = carry shr 4
            e[11] = (e[11] - (carry shl 4)).toByte()
            e[12] = (e[12] + carry).toByte()
            carry = e[12] + 8
            carry = carry shr 4
            e[12] = (e[12] - (carry shl 4)).toByte()
            e[13] = (e[13] + carry).toByte()
            carry = e[13] + 8
            carry = carry shr 4
            e[13] = (e[13] - (carry shl 4)).toByte()
            e[14] = (e[14] + carry).toByte()
            carry = e[14] + 8
            carry = carry shr 4
            e[14] = (e[14] - (carry shl 4)).toByte()
            e[15] = (e[15] + carry).toByte()
            carry = e[15] + 8
            carry = carry shr 4
            e[15] = (e[15] - (carry shl 4)).toByte()
            e[16] = (e[16] + carry).toByte()
            carry = e[16] + 8
            carry = carry shr 4
            e[16] = (e[16] - (carry shl 4)).toByte()
            e[17] = (e[17] + carry).toByte()
            carry = e[17] + 8
            carry = carry shr 4
            e[17] = (e[17] - (carry shl 4)).toByte()
            e[18] = (e[18] + carry).toByte()
            carry = e[18] + 8
            carry = carry shr 4
            e[18] = (e[18] - (carry shl 4)).toByte()
            e[19] = (e[19] + carry).toByte()
            carry = e[19] + 8
            carry = carry shr 4
            e[19] = (e[19] - (carry shl 4)).toByte()
            e[20] = (e[20] + carry).toByte()
            carry = e[20] + 8
            carry = carry shr 4
            e[20] = (e[20] - (carry shl 4)).toByte()
            e[21] = (e[21] + carry).toByte()
            carry = e[21] + 8
            carry = carry shr 4
            e[21] = (e[21] - (carry shl 4)).toByte()
            e[22] = (e[22] + carry).toByte()
            carry = e[22] + 8
            carry = carry shr 4
            e[22] = (e[22] - (carry shl 4)).toByte()
            e[23] = (e[23] + carry).toByte()
            carry = e[23] + 8
            carry = carry shr 4
            e[23] = (e[23] - (carry shl 4)).toByte()
            e[24] = (e[24] + carry).toByte()
            carry = e[24] + 8
            carry = carry shr 4
            e[24] = (e[24] - (carry shl 4)).toByte()
            e[25] = (e[25] + carry).toByte()
            carry = e[25] + 8
            carry = carry shr 4
            e[25] = (e[25] - (carry shl 4)).toByte()
            e[26] = (e[26] + carry).toByte()
            carry = e[26] + 8
            carry = carry shr 4
            e[26] = (e[26] - (carry shl 4)).toByte()
            e[27] = (e[27] + carry).toByte()
            carry = e[27] + 8
            carry = carry shr 4
            e[27] = (e[27] - (carry shl 4)).toByte()
            e[28] = (e[28] + carry).toByte()
            carry = e[28] + 8
            carry = carry shr 4
            e[28] = (e[28] - (carry shl 4)).toByte()
            e[29] = (e[29] + carry).toByte()
            carry = e[29] + 8
            carry = carry shr 4
            e[29] = (e[29] - (carry shl 4)).toByte()
            e[30] = (e[30] + carry).toByte()
            carry = e[30] + 8
            carry = carry shr 4
            e[30] = (e[30] - (carry shl 4)).toByte()
            e[31] = (e[31] + carry).toByte()
            carry = e[31] + 8
            carry = carry shr 4
            e[31] = (e[31] - (carry shl 4)).toByte()
            e[32] = (e[32] + carry).toByte()
            carry = e[32] + 8
            carry = carry shr 4
            e[32] = (e[32] - (carry shl 4)).toByte()
            e[33] = (e[33] + carry).toByte()
            carry = e[33] + 8
            carry = carry shr 4
            e[33] = (e[33] - (carry shl 4)).toByte()
            e[34] = (e[34] + carry).toByte()
            carry = e[34] + 8
            carry = carry shr 4
            e[34] = (e[34] - (carry shl 4)).toByte()
            e[35] = (e[35] + carry).toByte()
            carry = e[35] + 8
            carry = carry shr 4
            e[35] = (e[35] - (carry shl 4)).toByte()
            e[36] = (e[36] + carry).toByte()
            carry = e[36] + 8
            carry = carry shr 4
            e[36] = (e[36] - (carry shl 4)).toByte()
            e[37] = (e[37] + carry).toByte()
            carry = e[37] + 8
            carry = carry shr 4
            e[37] = (e[37] - (carry shl 4)).toByte()
            e[38] = (e[38] + carry).toByte()
            carry = e[38] + 8
            carry = carry shr 4
            e[38] = (e[38] - (carry shl 4)).toByte()
            e[39] = (e[39] + carry).toByte()
            carry = e[39] + 8
            carry = carry shr 4
            e[39] = (e[39] - (carry shl 4)).toByte()
            e[40] = (e[40] + carry).toByte()
            carry = e[40] + 8
            carry = carry shr 4
            e[40] = (e[40] - (carry shl 4)).toByte()
            e[41] = (e[41] + carry).toByte()
            carry = e[41] + 8
            carry = carry shr 4
            e[41] = (e[41] - (carry shl 4)).toByte()
            e[42] = (e[42] + carry).toByte()
            carry = e[42] + 8
            carry = carry shr 4
            e[42] = (e[42] - (carry shl 4)).toByte()
            e[43] = (e[43] + carry).toByte()
            carry = e[43] + 8
            carry = carry shr 4
            e[43] = (e[43] - (carry shl 4)).toByte()
            e[44] = (e[44] + carry).toByte()
            carry = e[44] + 8
            carry = carry shr 4
            e[44] = (e[44] - (carry shl 4)).toByte()
            e[45] = (e[45] + carry).toByte()
            carry = e[45] + 8
            carry = carry shr 4
            e[45] = (e[45] - (carry shl 4)).toByte()
            e[46] = (e[46] + carry).toByte()
            carry = e[46] + 8
            carry = carry shr 4
            e[46] = (e[46] - (carry shl 4)).toByte()
            e[47] = (e[47] + carry).toByte()
            carry = e[47] + 8
            carry = carry shr 4
            e[47] = (e[47] - (carry shl 4)).toByte()
            e[48] = (e[48] + carry).toByte()
            carry = e[48] + 8
            carry = carry shr 4
            e[48] = (e[48] - (carry shl 4)).toByte()
            e[49] = (e[49] + carry).toByte()
            carry = e[49] + 8
            carry = carry shr 4
            e[49] = (e[49] - (carry shl 4)).toByte()
            e[50] = (e[50] + carry).toByte()
            carry = e[50] + 8
            carry = carry shr 4
            e[50] = (e[50] - (carry shl 4)).toByte()
            e[51] = (e[51] + carry).toByte()
            carry = e[51] + 8
            carry = carry shr 4
            e[51] = (e[51] - (carry shl 4)).toByte()
            e[52] = (e[52] + carry).toByte()
            carry = e[52] + 8
            carry = carry shr 4
            e[52] = (e[52] - (carry shl 4)).toByte()
            e[53] = (e[53] + carry).toByte()
            carry = e[53] + 8
            carry = carry shr 4
            e[53] = (e[53] - (carry shl 4)).toByte()
            e[54] = (e[54] + carry).toByte()
            carry = e[54] + 8
            carry = carry shr 4
            e[54] = (e[54] - (carry shl 4)).toByte()
            e[55] = (e[55] + carry).toByte()
            carry = e[55] + 8
            carry = carry shr 4
            e[55] = (e[55] - (carry shl 4)).toByte()
            e[56] = (e[56] + carry).toByte()
            carry = e[56] + 8
            carry = carry shr 4
            e[56] = (e[56] - (carry shl 4)).toByte()
            e[57] = (e[57] + carry).toByte()
            carry = e[57] + 8
            carry = carry shr 4
            e[57] = (e[57] - (carry shl 4)).toByte()
            e[58] = (e[58] + carry).toByte()
            carry = e[58] + 8
            carry = carry shr 4
            e[58] = (e[58] - (carry shl 4)).toByte()
            e[59] = (e[59] + carry).toByte()
            carry = e[59] + 8
            carry = carry shr 4
            e[59] = (e[59] - (carry shl 4)).toByte()
            e[60] = (e[60] + carry).toByte()
            carry = e[60] + 8
            carry = carry shr 4
            e[60] = (e[60] - (carry shl 4)).toByte()
            e[61] = (e[61] + carry).toByte()
            carry = e[61] + 8
            carry = carry shr 4
            e[61] = (e[61] - (carry shl 4)).toByte()
            e[62] = (e[62] + carry).toByte()
            carry = e[62] + 8
            carry = carry shr 4
            e[62] = (e[62] - (carry shl 4)).toByte()
            e[63] = (e[63] + carry).toByte()
            /* each e[i] is between -8 and 7 */
            return e
        }
    }
}
