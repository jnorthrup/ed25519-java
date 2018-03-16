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

import java.security.spec.KeySpec

import net.i2p.crypto.eddsa.math.GroupElement

/**
 * @author str4d
 */
class EdDSAPublicKeySpec : KeySpec {
    val a: GroupElement
    val negativeA: GroupElement
    val params: EdDSAParameterSpec

    /**
     * @param pk the public key
     * @param spec the parameter specification for this key
     * @throws IllegalArgumentException if key length is wrong
     */
    constructor(pk: ByteArray, spec: EdDSAParameterSpec) {
        if (pk.size != spec.curve.field.getb() / 8)
            throw IllegalArgumentException("public-key length is wrong")

        a = GroupElement(spec.curve, pk)
        // Precompute -A for use in verification.
        negativeA = a.negate()
        negativeA.precompute(false)
        this.params = spec
    }

    constructor(A: GroupElement, spec: EdDSAParameterSpec) {
        this.a = A
        negativeA = A.negate()
        negativeA.precompute(false)
        this.params = spec
    }
}
