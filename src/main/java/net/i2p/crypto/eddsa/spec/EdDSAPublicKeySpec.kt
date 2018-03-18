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
import net.i2p.crypto.eddsa.math.P3GroupElement

/**
 * @author str4d
 */
class EdDSAPublicKeySpec : KeySpec {
    val A: GroupElement
    private var Aneg: GroupElement? = null
    val params: EdDSAParameterSpec

    // Only read Aneg once, otherwise read re-ordering might occur between here and return. Requires all GroupElement's fields to be final.
    val negativeA: GroupElement
        get() {
            var ourAneg = Aneg
            if (null == ourAneg) {
                ourAneg = A.negate()
                Aneg = ourAneg
            }
            return ourAneg
        }

    /**
     * @param pk the public key
     * @param spec the parameter specification for this key
     * @throws IllegalArgumentException if key length is wrong
     */
    constructor(pk: ByteArray, spec: EdDSAParameterSpec) {
        assert(pk.size == spec.curve.edDSAFiniteField.b / 8) { "public-key length is wrong" }

        this.A = P3GroupElement(spec.curve, pk)
        this.params = spec
    }

    constructor(A: GroupElement, spec: EdDSAParameterSpec) {
        this.A = A
        this.params = spec
    }
}
