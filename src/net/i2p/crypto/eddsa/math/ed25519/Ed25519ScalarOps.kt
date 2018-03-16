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
package net.i2p.crypto.eddsa.math.ed25519

import net.i2p.crypto.eddsa.math.ScalarOps
import net.i2p.crypto.eddsa.math.ed25519.Ed25519LittleEndianEncoding.load_3
import net.i2p.crypto.eddsa.math.ed25519.Ed25519LittleEndianEncoding.load_4

/**
 * Class for reducing a huge integer modulo the group order q and
 * doing a combined multiply plus add plus reduce operation.
 *
 *
 * $q = 2^{252} + 27742317777372353535851937790883648493$.
 *
 *
 * Reviewed/commented by Bloody Rookie (nemproject@gmx.de)
 */
class Ed25519ScalarOps : ScalarOps {

    /**
     * Reduction modulo the group order $q$.
     *
     *
     * Input:
     * $s[0]+256*s[1]+\dots+256^{63}*s[63] = s$
     *
     *
     * Output:
     * $s[0]+256*s[1]+\dots+256^{31}*s[31] = s \bmod q$
     * where $q = 2^{252} + 27742317777372353535851937790883648493$.
     */
    override fun reduce(s: ByteArray): ByteArray {
        // s0,..., s22 have 21 bits, s23 has 29 bits
        var s0 = (0x1FFFFF and load_3(s, 0)).toLong()
        var s1 = 0x1FFFFFL and (load_4(s, 2) shr 5)
        var s2 = (0x1FFFFF and (load_3(s, 5) shr 2)).toLong()
        var s3 = 0x1FFFFFL and (load_4(s, 7) shr 7)
        var s4 = 0x1FFFFFL and (load_4(s, 10) shr 4)
        var s5 = (0x1FFFFF and (load_3(s, 13) shr 1)).toLong()
        var s6 = 0x1FFFFFL and (load_4(s, 15) shr 6)
        var s7 = (0x1FFFFF and (load_3(s, 18) shr 3)).toLong()
        var s8 = (0x1FFFFF and load_3(s, 21)).toLong()
        var s9 = 0x1FFFFFL and (load_4(s, 23) shr 5)
        var s10 = (0x1FFFFF and (load_3(s, 26) shr 2)).toLong()
        var s11 = 0x1FFFFFL and (load_4(s, 28) shr 7)
        var s12 = 0x1FFFFFL and (load_4(s, 31) shr 4)
        var s13 = (0x1FFFFF and (load_3(s, 34) shr 1)).toLong()
        var s14 = 0x1FFFFFL and (load_4(s, 36) shr 6)
        var s15 = (0x1FFFFF and (load_3(s, 39) shr 3)).toLong()
        var s16 = (0x1FFFFF and load_3(s, 42)).toLong()
        var s17 = 0x1FFFFFL and (load_4(s, 44) shr 5)
        val s18 = (0x1FFFFF and (load_3(s, 47) shr 2)).toLong()
        val s19 = 0x1FFFFFL and (load_4(s, 49) shr 7)
        val s20 = 0x1FFFFFL and (load_4(s, 52) shr 4)
        val s21 = (0x1FFFFF and (load_3(s, 55) shr 1)).toLong()
        val s22 = 0x1FFFFFL and (load_4(s, 57) shr 6)
        val s23 = load_4(s, 60) shr 3
        var carry0: Long
        var carry1: Long
        var carry2: Long
        var carry3: Long
        var carry4: Long
        var carry5: Long
        var carry6: Long
        var carry7: Long
        var carry8: Long
        var carry9: Long
        var carry10: Long
        var carry11: Long
        val carry12: Long
        val carry13: Long
        val carry14: Long
        val carry15: Long
        val carry16: Long

        /**
         * Lots of magic numbers :)
         * To understand what's going on below, note that
         *
         * (1) q = 2^252 + q0 where q0 = 27742317777372353535851937790883648493.
         * (2) s11 is the coefficient of 2^(11*21), s23 is the coefficient of 2^(^23*21) and 2^252 = 2^((23-11) * 21)).
         * (3) 2^252 congruent -q0 modulo q.
         * (4) -q0 = 666643 * 2^0 + 470296 * 2^21 + 654183 * 2^(2*21) - 997805 * 2^(3*21) + 136657 * 2^(4*21) - 683901 * 2^(5*21)
         *
         * Thus
         * s23 * 2^(23*11) = s23 * 2^(12*21) * 2^(11*21) = s3 * 2^252 * 2^(11*21) congruent
         * s23 * (666643 * 2^0 + 470296 * 2^21 + 654183 * 2^(2*21) - 997805 * 2^(3*21) + 136657 * 2^(4*21) - 683901 * 2^(5*21)) * 2^(11*21) modulo q =
         * s23 * (666643 * 2^(11*21) + 470296 * 2^(12*21) + 654183 * 2^(13*21) - 997805 * 2^(14*21) + 136657 * 2^(15*21) - 683901 * 2^(16*21)).
         *
         * The same procedure is then applied for s22,...,s18.
         */
        s11 += s23 * 666643L
        s12 += s23 * 470296L
        s13 += s23 * 654183L
        s14 -= s23 * 997805L
        s15 += s23 * 136657L
        s16 -= s23 * 683901L
        // not used again
        //s23 = 0;

        s10 += s22 * 666643L
        s11 += s22 * 470296L
        s12 += s22 * 654183L
        s13 -= s22 * 997805L
        s14 += s22 * 136657L
        s15 -= s22 * 683901L
        // not used again
        //s22 = 0;

        s9 += s21 * 666643L
        s10 += s21 * 470296L
        s11 += s21 * 654183L
        s12 -= s21 * 997805L
        s13 += s21 * 136657L
        s14 -= s21 * 683901L
        // not used again
        //s21 = 0;

        s8 += s20 * 666643L
        s9 += s20 * 470296L
        s10 += s20 * 654183L
        s11 -= s20 * 997805L
        s12 += s20 * 136657L
        s13 -= s20 * 683901L
        // not used again
        //s20 = 0;

        s7 += s19 * 666643L
        s8 += s19 * 470296L
        s9 += s19 * 654183L
        s10 -= s19 * 997805L
        s11 += s19 * 136657L
        s12 -= s19 * 683901L
        // not used again
        //s19 = 0;

        s6 += s18 * 666643L
        s7 += s18 * 470296L
        s8 += s18 * 654183L
        s9 -= s18 * 997805L
        s10 += s18 * 136657L
        s11 -= s18 * 683901L
        // not used again
        //s18 = 0;

        /**
         * Time to reduce the coefficient in order not to get an overflow.
         */
        carry6 = s6 + (1 shl 20).toLong() shr 21
        s7 += carry6
        s6 -= carry6 shl 21
        carry8 = s8 + (1 shl 20).toLong() shr 21
        s9 += carry8
        s8 -= carry8 shl 21
        carry10 = s10 + (1 shl 20).toLong() shr 21
        s11 += carry10
        s10 -= carry10 shl 21
        carry12 = s12 + (1 shl 20).toLong() shr 21
        s13 += carry12
        s12 -= carry12 shl 21
        carry14 = s14 + (1 shl 20).toLong() shr 21
        s15 += carry14
        s14 -= carry14 shl 21
        carry16 = s16 + (1 shl 20).toLong() shr 21
        s17 += carry16
        s16 -= carry16 shl 21

        carry7 = s7 + (1 shl 20).toLong() shr 21
        s8 += carry7
        s7 -= carry7 shl 21
        carry9 = s9 + (1 shl 20).toLong() shr 21
        s10 += carry9
        s9 -= carry9 shl 21
        carry11 = s11 + (1 shl 20).toLong() shr 21
        s12 += carry11
        s11 -= carry11 shl 21
        carry13 = s13 + (1 shl 20).toLong() shr 21
        s14 += carry13
        s13 -= carry13 shl 21
        carry15 = s15 + (1 shl 20).toLong() shr 21
        s16 += carry15
        s15 -= carry15 shl 21

        /**
         * Continue with above procedure.
         */
        s5 += s17 * 666643L
        s6 += s17 * 470296L
        s7 += s17 * 654183L
        s8 -= s17 * 997805L
        s9 += s17 * 136657L
        s10 -= s17 * 683901L
        // not used again
        //s17 = 0;

        s4 += s16 * 666643L
        s5 += s16 * 470296L
        s6 += s16 * 654183L
        s7 -= s16 * 997805L
        s8 += s16 * 136657L
        s9 -= s16 * 683901L
        // not used again
        //s16 = 0;

        s3 += s15 * 666643L
        s4 += s15 * 470296L
        s5 += s15 * 654183L
        s6 -= s15 * 997805L
        s7 += s15 * 136657L
        s8 -= s15 * 683901L
        // not used again
        //s15 = 0;

        s2 += s14 * 666643L
        s3 += s14 * 470296L
        s4 += s14 * 654183L
        s5 -= s14 * 997805L
        s6 += s14 * 136657L
        s7 -= s14 * 683901L
        // not used again
        //s14 = 0;

        s1 += s13 * 666643L
        s2 += s13 * 470296L
        s3 += s13 * 654183L
        s4 -= s13 * 997805L
        s5 += s13 * 136657L
        s6 -= s13 * 683901L
        // not used again
        //s13 = 0;

        s0 += s12 * 666643L
        s1 += s12 * 470296L
        s2 += s12 * 654183L
        s3 -= s12 * 997805L
        s4 += s12 * 136657L
        s5 -= s12 * 683901L
        // set below
        //s12 = 0;

        /**
         * Reduce coefficients again.
         */
        carry0 = s0 + (1 shl 20).toLong() shr 21
        s1 += carry0
        s0 -= carry0 shl 21
        carry2 = s2 + (1 shl 20).toLong() shr 21
        s3 += carry2
        s2 -= carry2 shl 21
        carry4 = s4 + (1 shl 20).toLong() shr 21
        s5 += carry4
        s4 -= carry4 shl 21
        carry6 = s6 + (1 shl 20).toLong() shr 21
        s7 += carry6
        s6 -= carry6 shl 21
        carry8 = s8 + (1 shl 20).toLong() shr 21
        s9 += carry8
        s8 -= carry8 shl 21
        carry10 = s10 + (1 shl 20).toLong() shr 21
        s11 += carry10
        s10 -= carry10 shl 21

        carry1 = s1 + (1 shl 20).toLong() shr 21
        s2 += carry1
        s1 -= carry1 shl 21
        carry3 = s3 + (1 shl 20).toLong() shr 21
        s4 += carry3
        s3 -= carry3 shl 21
        carry5 = s5 + (1 shl 20).toLong() shr 21
        s6 += carry5
        s5 -= carry5 shl 21
        carry7 = s7 + (1 shl 20).toLong() shr 21
        s8 += carry7
        s7 -= carry7 shl 21
        carry9 = s9 + (1 shl 20).toLong() shr 21
        s10 += carry9
        s9 -= carry9 shl 21
        //carry11 = (s11 + (1<<20)) >> 21; s12 += carry11; s11 -= carry11 << 21;
        carry11 = s11 + (1 shl 20).toLong() shr 21
        s11 -= carry11 shl 21

        s0 += carry11 * 666643L
        s1 += carry11 * 470296L
        s2 += carry11 * 654183L
        s3 -= carry11 * 997805L
        s4 += carry11 * 136657L
        s5 -= carry11 * 683901L
        // set below
        //s12 = 0;

        carry0 = s0 shr 21
        s1 += carry0
        s0 -= carry0 shl 21
        carry1 = s1 shr 21
        s2 += carry1
        s1 -= carry1 shl 21
        carry2 = s2 shr 21
        s3 += carry2
        s2 -= carry2 shl 21
        carry3 = s3 shr 21
        s4 += carry3
        s3 -= carry3 shl 21
        carry4 = s4 shr 21
        s5 += carry4
        s4 -= carry4 shl 21
        carry5 = s5 shr 21
        s6 += carry5
        s5 -= carry5 shl 21
        carry6 = s6 shr 21
        s7 += carry6
        s6 -= carry6 shl 21
        carry7 = s7 shr 21
        s8 += carry7
        s7 -= carry7 shl 21
        carry8 = s8 shr 21
        s9 += carry8
        s8 -= carry8 shl 21
        carry9 = s9 shr 21
        s10 += carry9
        s9 -= carry9 shl 21
        carry10 = s10 shr 21
        s11 += carry10
        s10 -= carry10 shl 21
        //carry11 = s11 >> 21; s12 += carry11; s11 -= carry11 << 21;
        carry11 = s11 shr 21
        s11 -= carry11 shl 21

        // TODO-CR BR: Is it really needed to do it TWO times? (it doesn't hurt, just a question).
        s0 += carry11 * 666643L
        s1 += carry11 * 470296L
        s2 += carry11 * 654183L
        s3 -= carry11 * 997805L
        s4 += carry11 * 136657L
        s5 -= carry11 * 683901L
        // not used again
        //s12 = 0;

        carry0 = s0 shr 21
        s1 += carry0
        s0 -= carry0 shl 21
        carry1 = s1 shr 21
        s2 += carry1
        s1 -= carry1 shl 21
        carry2 = s2 shr 21
        s3 += carry2
        s2 -= carry2 shl 21
        carry3 = s3 shr 21
        s4 += carry3
        s3 -= carry3 shl 21
        carry4 = s4 shr 21
        s5 += carry4
        s4 -= carry4 shl 21
        carry5 = s5 shr 21
        s6 += carry5
        s5 -= carry5 shl 21
        carry6 = s6 shr 21
        s7 += carry6
        s6 -= carry6 shl 21
        carry7 = s7 shr 21
        s8 += carry7
        s7 -= carry7 shl 21
        carry8 = s8 shr 21
        s9 += carry8
        s8 -= carry8 shl 21
        carry9 = s9 shr 21
        s10 += carry9
        s9 -= carry9 shl 21
        carry10 = s10 shr 21
        s11 += carry10
        s10 -= carry10 shl 21

        // s0, ..., s11 got 21 bits each.
        val result = ByteArray(32)
        result[0] = s0.toByte()
        result[1] = (s0 shr 8).toByte()
        result[2] = (s0 shr 16 or (s1 shl 5)).toByte()
        result[3] = (s1 shr 3).toByte()
        result[4] = (s1 shr 11).toByte()
        result[5] = (s1 shr 19 or (s2 shl 2)).toByte()
        result[6] = (s2 shr 6).toByte()
        result[7] = (s2 shr 14 or (s3 shl 7)).toByte()
        result[8] = (s3 shr 1).toByte()
        result[9] = (s3 shr 9).toByte()
        result[10] = (s3 shr 17 or (s4 shl 4)).toByte()
        result[11] = (s4 shr 4).toByte()
        result[12] = (s4 shr 12).toByte()
        result[13] = (s4 shr 20 or (s5 shl 1)).toByte()
        result[14] = (s5 shr 7).toByte()
        result[15] = (s5 shr 15 or (s6 shl 6)).toByte()
        result[16] = (s6 shr 2).toByte()
        result[17] = (s6 shr 10).toByte()
        result[18] = (s6 shr 18 or (s7 shl 3)).toByte()
        result[19] = (s7 shr 5).toByte()
        result[20] = (s7 shr 13).toByte()
        result[21] = s8.toByte()
        result[22] = (s8 shr 8).toByte()
        result[23] = (s8 shr 16 or (s9 shl 5)).toByte()
        result[24] = (s9 shr 3).toByte()
        result[25] = (s9 shr 11).toByte()
        result[26] = (s9 shr 19 or (s10 shl 2)).toByte()
        result[27] = (s10 shr 6).toByte()
        result[28] = (s10 shr 14 or (s11 shl 7)).toByte()
        result[29] = (s11 shr 1).toByte()
        result[30] = (s11 shr 9).toByte()
        result[31] = (s11 shr 17).toByte()
        return result
    }


    /**
     * $(ab+c) \bmod q$
     *
     *
     * Input:
     *
     *  * $a[0]+256*a[1]+\dots+256^{31}*a[31] = a$
     *  * $b[0]+256*b[1]+\dots+256^{31}*b[31] = b$
     *  * $c[0]+256*c[1]+\dots+256^{31}*c[31] = c$
     *
     *
     * Output:
     * $result[0]+256*result[1]+\dots+256^{31}*result[31] = (ab+c) \bmod q$
     * where $q = 2^{252} + 27742317777372353535851937790883648493$.
     *
     *
     * See the comments in [.reduce] for an explanation of the algorithm.
     */
    override fun multiplyAndAdd(a: ByteArray, b: ByteArray, c: ByteArray): ByteArray {
        val a0 = (0x1FFFFF and load_3(a, 0)).toLong()
        val a1 = 0x1FFFFFL and (load_4(a, 2) shr 5)
        val a2 = (0x1FFFFF and (load_3(a, 5) shr 2)).toLong()
        val a3 = 0x1FFFFFL and (load_4(a, 7) shr 7)
        val a4 = 0x1FFFFFL and (load_4(a, 10) shr 4)
        val a5 = (0x1FFFFF and (load_3(a, 13) shr 1)).toLong()
        val a6 = 0x1FFFFFL and (load_4(a, 15) shr 6)
        val a7 = (0x1FFFFF and (load_3(a, 18) shr 3)).toLong()
        val a8 = (0x1FFFFF and load_3(a, 21)).toLong()
        val a9 = 0x1FFFFFL and (load_4(a, 23) shr 5)
        val a10 = (0x1FFFFF and (load_3(a, 26) shr 2)).toLong()
        val a11 = load_4(a, 28) shr 7
        val b0 = (0x1FFFFF and load_3(b, 0)).toLong()
        val b1 = 0x1FFFFFL and (load_4(b, 2) shr 5)
        val b2 = (0x1FFFFF and (load_3(b, 5) shr 2)).toLong()
        val b3 = 0x1FFFFFL and (load_4(b, 7) shr 7)
        val b4 = 0x1FFFFFL and (load_4(b, 10) shr 4)
        val b5 = (0x1FFFFF and (load_3(b, 13) shr 1)).toLong()
        val b6 = 0x1FFFFFL and (load_4(b, 15) shr 6)
        val b7 = (0x1FFFFF and (load_3(b, 18) shr 3)).toLong()
        val b8 = (0x1FFFFF and load_3(b, 21)).toLong()
        val b9 = 0x1FFFFFL and (load_4(b, 23) shr 5)
        val b10 = (0x1FFFFF and (load_3(b, 26) shr 2)).toLong()
        val b11 = load_4(b, 28) shr 7
        val c0 = (0x1FFFFF and load_3(c, 0)).toLong()
        val c1 = 0x1FFFFFL and (load_4(c, 2) shr 5)
        val c2 = (0x1FFFFF and (load_3(c, 5) shr 2)).toLong()
        val c3 = 0x1FFFFFL and (load_4(c, 7) shr 7)
        val c4 = 0x1FFFFFL and (load_4(c, 10) shr 4)
        val c5 = (0x1FFFFF and (load_3(c, 13) shr 1)).toLong()
        val c6 = 0x1FFFFFL and (load_4(c, 15) shr 6)
        val c7 = (0x1FFFFF and (load_3(c, 18) shr 3)).toLong()
        val c8 = (0x1FFFFF and load_3(c, 21)).toLong()
        val c9 = 0x1FFFFFL and (load_4(c, 23) shr 5)
        val c10 = (0x1FFFFF and (load_3(c, 26) shr 2)).toLong()
        val c11 = load_4(c, 28) shr 7
        var s0: Long
        var s1: Long
        var s2: Long
        var s3: Long
        var s4: Long
        var s5: Long
        var s6: Long
        var s7: Long
        var s8: Long
        var s9: Long
        var s10: Long
        var s11: Long
        var s12: Long
        var s13: Long
        var s14: Long
        var s15: Long
        var s16: Long
        var s17: Long
        var s18: Long
        var s19: Long
        var s20: Long
        var s21: Long
        var s22: Long
        val s23: Long
        var carry0: Long
        var carry1: Long
        var carry2: Long
        var carry3: Long
        var carry4: Long
        var carry5: Long
        var carry6: Long
        var carry7: Long
        var carry8: Long
        var carry9: Long
        var carry10: Long
        var carry11: Long
        var carry12: Long
        var carry13: Long
        var carry14: Long
        var carry15: Long
        var carry16: Long
        val carry17: Long
        val carry18: Long
        val carry19: Long
        val carry20: Long
        val carry21: Long
        val carry22: Long

        s0 = c0 + a0 * b0
        s1 = c1 + a0 * b1 + a1 * b0
        s2 = c2 + a0 * b2 + a1 * b1 + a2 * b0
        s3 = c3 + a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0
        s4 = c4 + a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0
        s5 = c5 + a0 * b5 + a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1 + a5 * b0
        s6 = c6 + a0 * b6 + a1 * b5 + a2 * b4 + a3 * b3 + a4 * b2 + a5 * b1 + a6 * b0
        s7 = c7 + a0 * b7 + a1 * b6 + a2 * b5 + a3 * b4 + a4 * b3 + a5 * b2 + a6 * b1 + a7 * b0
        s8 = c8 + a0 * b8 + a1 * b7 + a2 * b6 + a3 * b5 + a4 * b4 + a5 * b3 + a6 * b2 + a7 * b1 + a8 * b0
        s9 = c9 + a0 * b9 + a1 * b8 + a2 * b7 + a3 * b6 + a4 * b5 + a5 * b4 + a6 * b3 + a7 * b2 + a8 * b1 + a9 * b0
        s10 = c10 + a0 * b10 + a1 * b9 + a2 * b8 + a3 * b7 + a4 * b6 + a5 * b5 + a6 * b4 + a7 * b3 + a8 * b2 + a9 * b1 + a10 * b0
        s11 = c11 + a0 * b11 + a1 * b10 + a2 * b9 + a3 * b8 + a4 * b7 + a5 * b6 + a6 * b5 + a7 * b4 + a8 * b3 + a9 * b2 + a10 * b1 + a11 * b0
        s12 = a1 * b11 + a2 * b10 + a3 * b9 + a4 * b8 + a5 * b7 + a6 * b6 + a7 * b5 + a8 * b4 + a9 * b3 + a10 * b2 + a11 * b1
        s13 = a2 * b11 + a3 * b10 + a4 * b9 + a5 * b8 + a6 * b7 + a7 * b6 + a8 * b5 + a9 * b4 + a10 * b3 + a11 * b2
        s14 = a3 * b11 + a4 * b10 + a5 * b9 + a6 * b8 + a7 * b7 + a8 * b6 + a9 * b5 + a10 * b4 + a11 * b3
        s15 = a4 * b11 + a5 * b10 + a6 * b9 + a7 * b8 + a8 * b7 + a9 * b6 + a10 * b5 + a11 * b4
        s16 = a5 * b11 + a6 * b10 + a7 * b9 + a8 * b8 + a9 * b7 + a10 * b6 + a11 * b5
        s17 = a6 * b11 + a7 * b10 + a8 * b9 + a9 * b8 + a10 * b7 + a11 * b6
        s18 = a7 * b11 + a8 * b10 + a9 * b9 + a10 * b8 + a11 * b7
        s19 = a8 * b11 + a9 * b10 + a10 * b9 + a11 * b8
        s20 = a9 * b11 + a10 * b10 + a11 * b9
        s21 = a10 * b11 + a11 * b10
        s22 = a11 * b11
        // set below
        //s23 = 0;

        carry0 = s0 + (1 shl 20).toLong() shr 21
        s1 += carry0
        s0 -= carry0 shl 21
        carry2 = s2 + (1 shl 20).toLong() shr 21
        s3 += carry2
        s2 -= carry2 shl 21
        carry4 = s4 + (1 shl 20).toLong() shr 21
        s5 += carry4
        s4 -= carry4 shl 21
        carry6 = s6 + (1 shl 20).toLong() shr 21
        s7 += carry6
        s6 -= carry6 shl 21
        carry8 = s8 + (1 shl 20).toLong() shr 21
        s9 += carry8
        s8 -= carry8 shl 21
        carry10 = s10 + (1 shl 20).toLong() shr 21
        s11 += carry10
        s10 -= carry10 shl 21
        carry12 = s12 + (1 shl 20).toLong() shr 21
        s13 += carry12
        s12 -= carry12 shl 21
        carry14 = s14 + (1 shl 20).toLong() shr 21
        s15 += carry14
        s14 -= carry14 shl 21
        carry16 = s16 + (1 shl 20).toLong() shr 21
        s17 += carry16
        s16 -= carry16 shl 21
        carry18 = s18 + (1 shl 20).toLong() shr 21
        s19 += carry18
        s18 -= carry18 shl 21
        carry20 = s20 + (1 shl 20).toLong() shr 21
        s21 += carry20
        s20 -= carry20 shl 21
        //carry22 = (s22 + (1<<20)) >> 21; s23 += carry22; s22 -= carry22 << 21;
        carry22 = s22 + (1 shl 20).toLong() shr 21
        s23 = carry22
        s22 -= carry22 shl 21

        carry1 = s1 + (1 shl 20).toLong() shr 21
        s2 += carry1
        s1 -= carry1 shl 21
        carry3 = s3 + (1 shl 20).toLong() shr 21
        s4 += carry3
        s3 -= carry3 shl 21
        carry5 = s5 + (1 shl 20).toLong() shr 21
        s6 += carry5
        s5 -= carry5 shl 21
        carry7 = s7 + (1 shl 20).toLong() shr 21
        s8 += carry7
        s7 -= carry7 shl 21
        carry9 = s9 + (1 shl 20).toLong() shr 21
        s10 += carry9
        s9 -= carry9 shl 21
        carry11 = s11 + (1 shl 20).toLong() shr 21
        s12 += carry11
        s11 -= carry11 shl 21
        carry13 = s13 + (1 shl 20).toLong() shr 21
        s14 += carry13
        s13 -= carry13 shl 21
        carry15 = s15 + (1 shl 20).toLong() shr 21
        s16 += carry15
        s15 -= carry15 shl 21
        carry17 = s17 + (1 shl 20).toLong() shr 21
        s18 += carry17
        s17 -= carry17 shl 21
        carry19 = s19 + (1 shl 20).toLong() shr 21
        s20 += carry19
        s19 -= carry19 shl 21
        carry21 = s21 + (1 shl 20).toLong() shr 21
        s22 += carry21
        s21 -= carry21 shl 21

        s11 += s23 * 666643L
        s12 += s23 * 470296L
        s13 += s23 * 654183L
        s14 -= s23 * 997805L
        s15 += s23 * 136657L
        s16 -= s23 * 683901L
        // not used again
        //s23 = 0;

        s10 += s22 * 666643L
        s11 += s22 * 470296L
        s12 += s22 * 654183L
        s13 -= s22 * 997805L
        s14 += s22 * 136657L
        s15 -= s22 * 683901L
        // not used again
        //s22 = 0;

        s9 += s21 * 666643L
        s10 += s21 * 470296L
        s11 += s21 * 654183L
        s12 -= s21 * 997805L
        s13 += s21 * 136657L
        s14 -= s21 * 683901L
        // not used again
        //s21 = 0;

        s8 += s20 * 666643L
        s9 += s20 * 470296L
        s10 += s20 * 654183L
        s11 -= s20 * 997805L
        s12 += s20 * 136657L
        s13 -= s20 * 683901L
        // not used again
        //s20 = 0;

        s7 += s19 * 666643L
        s8 += s19 * 470296L
        s9 += s19 * 654183L
        s10 -= s19 * 997805L
        s11 += s19 * 136657L
        s12 -= s19 * 683901L
        // not used again
        //s19 = 0;

        s6 += s18 * 666643L
        s7 += s18 * 470296L
        s8 += s18 * 654183L
        s9 -= s18 * 997805L
        s10 += s18 * 136657L
        s11 -= s18 * 683901L
        // not used again
        //s18 = 0;

        carry6 = s6 + (1 shl 20).toLong() shr 21
        s7 += carry6
        s6 -= carry6 shl 21
        carry8 = s8 + (1 shl 20).toLong() shr 21
        s9 += carry8
        s8 -= carry8 shl 21
        carry10 = s10 + (1 shl 20).toLong() shr 21
        s11 += carry10
        s10 -= carry10 shl 21
        carry12 = s12 + (1 shl 20).toLong() shr 21
        s13 += carry12
        s12 -= carry12 shl 21
        carry14 = s14 + (1 shl 20).toLong() shr 21
        s15 += carry14
        s14 -= carry14 shl 21
        carry16 = s16 + (1 shl 20).toLong() shr 21
        s17 += carry16
        s16 -= carry16 shl 21

        carry7 = s7 + (1 shl 20).toLong() shr 21
        s8 += carry7
        s7 -= carry7 shl 21
        carry9 = s9 + (1 shl 20).toLong() shr 21
        s10 += carry9
        s9 -= carry9 shl 21
        carry11 = s11 + (1 shl 20).toLong() shr 21
        s12 += carry11
        s11 -= carry11 shl 21
        carry13 = s13 + (1 shl 20).toLong() shr 21
        s14 += carry13
        s13 -= carry13 shl 21
        carry15 = s15 + (1 shl 20).toLong() shr 21
        s16 += carry15
        s15 -= carry15 shl 21

        s5 += s17 * 666643L
        s6 += s17 * 470296L
        s7 += s17 * 654183L
        s8 -= s17 * 997805L
        s9 += s17 * 136657L
        s10 -= s17 * 683901L
        // not used again
        //s17 = 0;

        s4 += s16 * 666643L
        s5 += s16 * 470296L
        s6 += s16 * 654183L
        s7 -= s16 * 997805L
        s8 += s16 * 136657L
        s9 -= s16 * 683901L
        // not used again
        //s16 = 0;

        s3 += s15 * 666643L
        s4 += s15 * 470296L
        s5 += s15 * 654183L
        s6 -= s15 * 997805L
        s7 += s15 * 136657L
        s8 -= s15 * 683901L
        // not used again
        //s15 = 0;

        s2 += s14 * 666643L
        s3 += s14 * 470296L
        s4 += s14 * 654183L
        s5 -= s14 * 997805L
        s6 += s14 * 136657L
        s7 -= s14 * 683901L
        // not used again
        //s14 = 0;

        s1 += s13 * 666643L
        s2 += s13 * 470296L
        s3 += s13 * 654183L
        s4 -= s13 * 997805L
        s5 += s13 * 136657L
        s6 -= s13 * 683901L
        // not used again
        //s13 = 0;

        s0 += s12 * 666643L
        s1 += s12 * 470296L
        s2 += s12 * 654183L
        s3 -= s12 * 997805L
        s4 += s12 * 136657L
        s5 -= s12 * 683901L
        // set below
        //s12 = 0;

        carry0 = s0 + (1 shl 20).toLong() shr 21
        s1 += carry0
        s0 -= carry0 shl 21
        carry2 = s2 + (1 shl 20).toLong() shr 21
        s3 += carry2
        s2 -= carry2 shl 21
        carry4 = s4 + (1 shl 20).toLong() shr 21
        s5 += carry4
        s4 -= carry4 shl 21
        carry6 = s6 + (1 shl 20).toLong() shr 21
        s7 += carry6
        s6 -= carry6 shl 21
        carry8 = s8 + (1 shl 20).toLong() shr 21
        s9 += carry8
        s8 -= carry8 shl 21
        carry10 = s10 + (1 shl 20).toLong() shr 21
        s11 += carry10
        s10 -= carry10 shl 21

        carry1 = s1 + (1 shl 20).toLong() shr 21
        s2 += carry1
        s1 -= carry1 shl 21
        carry3 = s3 + (1 shl 20).toLong() shr 21
        s4 += carry3
        s3 -= carry3 shl 21
        carry5 = s5 + (1 shl 20).toLong() shr 21
        s6 += carry5
        s5 -= carry5 shl 21
        carry7 = s7 + (1 shl 20).toLong() shr 21
        s8 += carry7
        s7 -= carry7 shl 21
        carry9 = s9 + (1 shl 20).toLong() shr 21
        s10 += carry9
        s9 -= carry9 shl 21
        //carry11 = (s11 + (1<<20)) >> 21; s12 += carry11; s11 -= carry11 << 21;
        carry11 = s11 + (1 shl 20).toLong() shr 21
        s12 = carry11
        s11 -= carry11 shl 21

        s0 += s12 * 666643L
        s1 += s12 * 470296L
        s2 += s12 * 654183L
        s3 -= s12 * 997805L
        s4 += s12 * 136657L
        s5 -= s12 * 683901L
        // set below
        //s12 = 0;

        carry0 = s0 shr 21
        s1 += carry0
        s0 -= carry0 shl 21
        carry1 = s1 shr 21
        s2 += carry1
        s1 -= carry1 shl 21
        carry2 = s2 shr 21
        s3 += carry2
        s2 -= carry2 shl 21
        carry3 = s3 shr 21
        s4 += carry3
        s3 -= carry3 shl 21
        carry4 = s4 shr 21
        s5 += carry4
        s4 -= carry4 shl 21
        carry5 = s5 shr 21
        s6 += carry5
        s5 -= carry5 shl 21
        carry6 = s6 shr 21
        s7 += carry6
        s6 -= carry6 shl 21
        carry7 = s7 shr 21
        s8 += carry7
        s7 -= carry7 shl 21
        carry8 = s8 shr 21
        s9 += carry8
        s8 -= carry8 shl 21
        carry9 = s9 shr 21
        s10 += carry9
        s9 -= carry9 shl 21
        carry10 = s10 shr 21
        s11 += carry10
        s10 -= carry10 shl 21
        //carry11 = s11 >> 21; s12 += carry11; s11 -= carry11 << 21;
        carry11 = s11 shr 21
        s12 = carry11
        s11 -= carry11 shl 21

        s0 += s12 * 666643L
        s1 += s12 * 470296L
        s2 += s12 * 654183L
        s3 -= s12 * 997805L
        s4 += s12 * 136657L
        s5 -= s12 * 683901L
        // not used again
        //s12 = 0;

        carry0 = s0 shr 21
        s1 += carry0
        s0 -= carry0 shl 21
        carry1 = s1 shr 21
        s2 += carry1
        s1 -= carry1 shl 21
        carry2 = s2 shr 21
        s3 += carry2
        s2 -= carry2 shl 21
        carry3 = s3 shr 21
        s4 += carry3
        s3 -= carry3 shl 21
        carry4 = s4 shr 21
        s5 += carry4
        s4 -= carry4 shl 21
        carry5 = s5 shr 21
        s6 += carry5
        s5 -= carry5 shl 21
        carry6 = s6 shr 21
        s7 += carry6
        s6 -= carry6 shl 21
        carry7 = s7 shr 21
        s8 += carry7
        s7 -= carry7 shl 21
        carry8 = s8 shr 21
        s9 += carry8
        s8 -= carry8 shl 21
        carry9 = s9 shr 21
        s10 += carry9
        s9 -= carry9 shl 21
        carry10 = s10 shr 21
        s11 += carry10
        s10 -= carry10 shl 21

        val result = ByteArray(32)
        result[0] = s0.toByte()
        result[1] = (s0 shr 8).toByte()
        result[2] = (s0 shr 16 or (s1 shl 5)).toByte()
        result[3] = (s1 shr 3).toByte()
        result[4] = (s1 shr 11).toByte()
        result[5] = (s1 shr 19 or (s2 shl 2)).toByte()
        result[6] = (s2 shr 6).toByte()
        result[7] = (s2 shr 14 or (s3 shl 7)).toByte()
        result[8] = (s3 shr 1).toByte()
        result[9] = (s3 shr 9).toByte()
        result[10] = (s3 shr 17 or (s4 shl 4)).toByte()
        result[11] = (s4 shr 4).toByte()
        result[12] = (s4 shr 12).toByte()
        result[13] = (s4 shr 20 or (s5 shl 1)).toByte()
        result[14] = (s5 shr 7).toByte()
        result[15] = (s5 shr 15 or (s6 shl 6)).toByte()
        result[16] = (s6 shr 2).toByte()
        result[17] = (s6 shr 10).toByte()
        result[18] = (s6 shr 18 or (s7 shl 3)).toByte()
        result[19] = (s7 shr 5).toByte()
        result[20] = (s7 shr 13).toByte()
        result[21] = s8.toByte()
        result[22] = (s8 shr 8).toByte()
        result[23] = (s8 shr 16 or (s9 shl 5)).toByte()
        result[24] = (s9 shr 3).toByte()
        result[25] = (s9 shr 11).toByte()
        result[26] = (s9 shr 19 or (s10 shl 2)).toByte()
        result[27] = (s10 shr 6).toByte()
        result[28] = (s10 shr 14 or (s11 shl 7)).toByte()
        result[29] = (s11 shr 1).toByte()
        result[30] = (s11 shr 9).toByte()
        result[31] = (s11 shr 17).toByte()
        return result
    }
}
