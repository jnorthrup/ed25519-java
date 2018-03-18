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
import java.util.Objects

import net.i2p.crypto.eddsa.math.EmptyEncoding
import net.i2p.crypto.eddsa.math.EdDSAFiniteField

internal class BigIntegerLittleEndianEncoding {

    val emptyEncoding = MyEmptyEncoding(this)
    /**
     * Mask where only the first b-1 bits are set.
     */
    var mask: BigInteger? = null

    internal var edDSAFiniteField: EdDSAFiniteField?
        get() = emptyEncoding.edDSAFiniteField
        set(f) {
            emptyEncoding.edDSAFiniteField = f
        }

    /**
     * Convert $x$ to little endian.
     * Constant time.
     *
     * @param x the BigInteger value to encode
     * @return array of length $b/8$
     * @throws IllegalStateException if field not set
     */
    fun convertBigIntegerToLittleEndian(x: BigInteger): ByteArray {
        Objects.requireNonNull<EdDSAFiniteField>(edDSAFiniteField, "field not set")
        val `in` = x.toByteArray()
        val out = ByteArray(edDSAFiniteField!!.b / 8)
        val bound = `in`.size
        for (i1 in 0 until bound) {
            out[i1] = `in`[`in`.size - 1 - i1]
        }
        val bound1 = out.size
        for (i in `in`.size until bound1) {
            out[i] = 0.toByte()
        }
        return out
    }

    /**
     * Convert in to big endian
     *
     * @param in the $(b-1)$-bit encoding of a FieldElement.
     * @return the decoded value as a BigInteger
     */
    fun toBigInteger(`in`: ByteArray): BigInteger {
        val out = ByteArray(`in`.size)
        for (i in `in`.indices) {
            out[i] = `in`[`in`.size - 1 - i]
        }
        return BigInteger(1, out)
    }

    fun getEmptyEncoding(): EmptyEncoding {
        return emptyEncoding
    }
}
