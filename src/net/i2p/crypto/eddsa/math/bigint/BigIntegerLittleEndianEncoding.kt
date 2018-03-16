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
package net.i2p.crypto.eddsa.math.bigint

import java.math.BigInteger

import net.i2p.crypto.eddsa.math.Encoding
import net.i2p.crypto.eddsa.math.FiniteField
import net.i2p.crypto.eddsa.math.FieldElement

class BigIntegerLittleEndianEncoding : Encoding() {
    /**
     * Mask where only the first b-1 bits are set.
     */
    private var mask: BigInteger? = null

    @Synchronized
    override fun setFiniteField(f: FiniteField) {
        super.setFiniteField(f)
        mask = BigInteger.ONE.shiftLeft(f.getb() - 1).subtract(BigInteger.ONE)
    }

    override fun encode(x: FieldElement): ByteArray {
        return encode((x as BigIntegerFieldElement).bi.and(mask!!))
    }

    /**
     * Convert $x$ to little endian.
     * Constant time.
     *
     * @param x the BigInteger value to encode
     * @return array of length $b/8$
     * @throws IllegalStateException if field not set
     */
    fun encode(x: BigInteger): ByteArray {
        if (null != finiteField) {
            val `in` = x.toByteArray()
            val out = ByteArray(finiteField!!.getb() / 8)
            val bound = `in`.size
            for (i1 in 0 until bound) {
                out[i1] = `in`[`in`.size - 1 - i1]
            }
            val bound1 = out.size
            for (i in `in`.size until bound1) {
                out[i] = 0.toByte()
            }
            return out
        } else {
            throw IllegalStateException("field not set")
        }
    }

    /**
     * Decode a FieldElement from its $(b-1)$-bit encoding.
     * The highest bit is masked out.
     *
     * @param in the $(b-1)$-bit encoding of a FieldElement.
     * @return the FieldElement represented by 'val'.
     * @throws IllegalStateException if field not set
     * @throws IllegalArgumentException if encoding is invalid
     */
    override fun decode(`in`: ByteArray): FieldElement {
        if (null != finiteField) {
            if (`in`.size == finiteField!!.getb() / 8)
                return BigIntegerFieldElement(finiteField, toBigInteger(`in`).and(mask!!))
            throw IllegalArgumentException("Not a valid encoding")
        }
        throw IllegalStateException("field not set")
    }

    /**
     * From the Ed25519 paper:<br></br>
     * $x$ is negative if the $(b-1)$-bit encoding of $x$ is lexicographically larger
     * than the $(b-1)$-bit encoding of $-x$. If $q$ is an odd prime and the encoding
     * is the little-endian representation of $\{0, 1,\dots, q-1\}$ then the negative
     * elements of $F_q$ are $\{1, 3, 5,\dots, q-2\}$.
     * @return true if negative
     */
    override fun isNegative(x: FieldElement): Boolean {
        return (x as BigIntegerFieldElement).bi.testBit(0)
    }

    companion object {
        private val serialVersionUID = 3984579843759837L

        /**
         * Convert in to big endian
         *
         * @param in the $(b-1)$-bit encoding of a FieldElement.
         * @return the decoded value as a BigInteger
         */
        fun toBigInteger(`in`: ByteArray): BigInteger {
            val out = ByteArray(`in`.size)
            val bound = `in`.size
            for (i in 0 until bound) {
                out[i] = `in`[`in`.size - 1 - i]
            }
            return BigInteger(1, out)
        }
    }
}
