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
import java.security.spec.KeySpec
import java.util.Arrays

import net.i2p.crypto.eddsa.math.GroupElement

/**
 * @author str4d
 */
class EdDSAPrivateKeySpec : KeySpec {
    val seed: ByteArray?
    val hashOfTheSeed: ByteArray
    val privateKey: ByteArray
    val groupElement: GroupElement
    val params: EdDSAParameterSpec

    /**
     * @param seed the private key
     * @param spec the parameter specification for this key
     * @throws IllegalArgumentException if seed length is wrong or hash algorithm is unsupported
     */
    constructor(seed: ByteArray, spec: EdDSAParameterSpec) {
        assert(seed.size == spec.curve.edDSAFiniteField.b / 8) { "seed length is wrong" }

        this.params = spec
        this.seed = seed.clone()

        try {
            val hash = MessageDigest.getInstance(spec.hashAlgo)
            val b = spec.curve.edDSAFiniteField.b

            // H(k)
            hashOfTheSeed = hash.digest(seed)

            /*a = BigInteger.valueOf(2).pow(b-2);
            for (int i=3;i<(b-2);i++) {
                a = a.add(BigInteger.valueOf(2).pow(i).multiply(BigInteger.valueOf(Utils.bit(h,i))));
            }*/
            // Saves ~0.4ms per key when running signing tests.
            // TODO: are these bitflips the same for any hash function?
            hashOfTheSeed[0] = (hashOfTheSeed[0] as Int  and 248).toByte()
            hashOfTheSeed[b / 8 - 1] = (hashOfTheSeed[b / 8 - 1] as Int  and 63).toByte()
            hashOfTheSeed[b / 8 - 1] = (hashOfTheSeed[b / 8 - 1] as Int  or 64).toByte()
            privateKey = Arrays.copyOfRange(hashOfTheSeed, 0, b / 8)

            groupElement = spec.groupElement.scalarMultiply(privateKey)
        } catch (e: NoSuchAlgorithmException) {
            throw IllegalArgumentException("Unsupported hash algorithm")
        }

    }

    /**
     * Initialize directly from the hash.
     * getSeed() will return null if this constructor is used.
     *
     * @param spec the parameter specification for this key
     * @param hashOfTheSeed the private key
     * @throws IllegalArgumentException if hash length is wrong
     * @since 0.1.1
     */
    constructor(spec: EdDSAParameterSpec, hashOfTheSeed: ByteArray) {
        assert(hashOfTheSeed.size == spec.curve.edDSAFiniteField.b / 4) { "hash length is wrong" }

        this.seed = null

        this.hashOfTheSeed = hashOfTheSeed/*.clone()*///TODO how is cloning the array of a hash possibly breaking a test?
        this.params = spec
        val b = spec.curve.edDSAFiniteField.b

        hashOfTheSeed[0] = (hashOfTheSeed[0] as Int and 248).toByte()
        hashOfTheSeed[b / 8 - 1] = (hashOfTheSeed[b / 8 - 1]as Int  and 63).toByte()
        hashOfTheSeed[b / 8 - 1] = (hashOfTheSeed[b / 8 - 1]as Int  or 64).toByte()
        privateKey = Arrays.copyOfRange(hashOfTheSeed, 0, b / 8)

        groupElement = spec.groupElement.scalarMultiply(privateKey)
    }

    constructor(seed: ByteArray, hashOfTheSeed: ByteArray, privateKey: ByteArray, groupElement: GroupElement, spec: EdDSAParameterSpec) {
        this.seed = seed.clone()
        this.hashOfTheSeed = hashOfTheSeed.clone()
        this.privateKey = privateKey.clone()
        this.groupElement = groupElement
        this.params = spec
    }
}
