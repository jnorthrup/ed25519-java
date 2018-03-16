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
    /**
     * @return will be null if constructed directly from the private key
     */
    val seed: ByteArray?
    /**
     * @return the hash
     */
    val h: ByteArray
    /**
     * @return the private key
     */
    val byteArr: ByteArray
    /**
     * @return the public key
     */
    val aPrime: GroupElement?
    val params: EdDSAParameterSpec

    /**
     * @param seed the private key
     * @param spec the parameter specification for this key
     * @throws IllegalArgumentException if seed length is wrong or hash algorithm is unsupported
     */
    constructor(seed: ByteArray, spec: EdDSAParameterSpec) {
        if (seed.size != spec.curve.field.getb() / 8)
            throw IllegalArgumentException("seed length is wrong")

        this.params = spec
        this.seed = seed.clone()

        try {
            val hash = MessageDigest.getInstance(spec.hashAlgorithm)
            val b = spec.curve.field.getb()

            // H(k)
            h = hash.digest(seed)

            /*a = BigInteger.valueOf(2).pow(b-2);
            for (int i=3;i<(b-2);i++) {
                a = a.add(BigInteger.valueOf(2).pow(i).multiply(BigInteger.valueOf(Utils.bit(h,i))));
            }*/
            // Saves ~0.4ms per key when running signing tests.
            // TODO: are these bitflips the same for any hash function?
            h[0] = (h[0] and 248).toByte()
            h[b / 8 - 1] = (h[b / 8 - 1] and 63).toByte()
            h[b / 8 - 1] = (h[b / 8 - 1] or 64).toByte()
            byteArr = Arrays.copyOfRange(h, 0, b / 8)

            aPrime = spec.b.scalarMultiply(byteArr)
        } catch (e: NoSuchAlgorithmException) {
            throw IllegalArgumentException("Unsupported hash algorithm")
        }

    }

    /**
     * Initialize directly from the hash.
     * getSeed() will return null if this constructor is used.
     *
     * @param spec the parameter specification for this key
     * @param h the private key
     * @throws IllegalArgumentException if hash length is wrong
     * @since 0.1.1
     */
    constructor(spec: EdDSAParameterSpec, h: ByteArray) {
        if (h.size != spec.curve.field.getb() / 4)
            throw IllegalArgumentException("hash length is wrong")

        seed = null

        this.h = h
        this.params = spec
        val b = spec.curve.field.getb()

        h[0] = (h[0] and 248).toByte()
        h[b / 8 - 1] = (h[b / 8 - 1] and 63).toByte()
        h[b / 8 - 1] = (h[b / 8 - 1] or 64).toByte()
        byteArr = Arrays.copyOfRange(h, 0, b / 8)

        aPrime = spec.b.scalarMultiply(byteArr)
    }

    constructor(seed: ByteArray, h: ByteArray, byteArr: ByteArray, A: GroupElement, spec: EdDSAParameterSpec) {
        this.seed = seed.clone()
        this.h = h.clone()
        this.byteArr = byteArr.clone()
        this.aPrime = A
        this.params = spec
    }
}
