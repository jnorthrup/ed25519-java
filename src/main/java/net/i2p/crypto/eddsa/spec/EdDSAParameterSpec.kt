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
package net.i2p.crypto.eddsa.spec

import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.spec.AlgorithmParameterSpec

import net.i2p.crypto.eddsa.math.Curve
import net.i2p.crypto.eddsa.math.GroupElement
import net.i2p.crypto.eddsa.math.ScalarOps

/**
 * Parameter specification for an EdDSA algorithm.
 * @author str4d
 */
open class EdDSAParameterSpec
/**
 * @param curve the curve
 * @param hashAlgo the JCA string for the hash algorithm
 * @param scalarOps the parameter L represented as ScalarOps
 * @param groupElement the parameter B
 * @throws IllegalArgumentException if hash algorithm is unsupported or length is wrong
 */
internal constructor(val curve: Curve, val hashAlgo: String,
                     val scalarOps: ScalarOps, val groupElement: GroupElement) : AlgorithmParameterSpec {

    init {
        try {
            val hash = MessageDigest.getInstance(hashAlgo)
            // EdDSA hash function must produce 2b-bit output
            assert(curve.edDSAFiniteField.b / 4 == hash.digestLength) { "Hash output is not 2b-bit" }
        } catch (e: NoSuchAlgorithmException) {
            throw IllegalArgumentException("Unsupported hash algorithm")
        }

    }

    override fun hashCode(): Int {
        return hashAlgo.hashCode() xor
                curve.hashCode() xor
                groupElement.hashCode()
    }

    override fun equals(o: Any?): Boolean {
        return o === this || o is EdDSAParameterSpec && hashAlgo == o.hashAlgo && curve == o.curve && groupElement == o.groupElement
    }
}
