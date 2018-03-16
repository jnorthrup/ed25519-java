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

import java.io.Serializable

/**
 * Parameter specification for an EdDSA algorithm.
 * @author str4d
 */
open class EdDSAParameterSpec
/**
 * @param curve the curve
 * @param hashAlgo the JCA string for the hash algorithm
 * @param sc the parameter L represented as ScalarOps
 * @param B the parameter B
 * @throws IllegalArgumentException if hash algorithm is unsupported or length is wrong
 */
internal constructor(val curve: Curve, val hashAlgorithm: String,
                     val scalarOps: ScalarOps,
                     /**
                      * @return the base (generator)
                      */
                     val b: GroupElement) : AlgorithmParameterSpec, Serializable {

    init {
        try {
            val hash = MessageDigest.getInstance(hashAlgorithm)
            // EdDSA hash function must produce 2b-bit output
            if (curve.field.getb() / 4 != hash.digestLength)
                throw IllegalArgumentException("Hash output is not 2b-bit")
        } catch (e: NoSuchAlgorithmException) {
            throw IllegalArgumentException("Unsupported hash algorithm")
        }

    }

    override fun hashCode(): Int {
        return hashAlgorithm.hashCode() xor
                curve.hashCode() xor
                b.hashCode()
    }

    override fun equals(o: Any?): Boolean {
        if (o === this)
            return true
        if (o !is EdDSAParameterSpec)
            return false
        val s = o as EdDSAParameterSpec?
        return hashAlgorithm == s!!.hashAlgorithm &&
                curve == s.curve &&
                b == s.b
    }

    companion object {
        private const val serialVersionUID = 8274987108472012L
    }
}
