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
package net.i2p.crypto.eddsa.math

/**
 * Note: concrete subclasses must implement hashCode() and equals()
 */
abstract class BaseFieldElement protected constructor(override val edDSAFiniteField: EdDSAFiniteField?) : FieldElement {

    override val isNegative: Boolean
        get() = edDSAFiniteField!!.encoding.isNegative(this)

    init {
        assert(null != edDSAFiniteField) { "field cannot be null" }
    }

    /**
     * Encode a FieldElement in its $(b-1)$-bit encoding.
     * @return the $(b-1)$-bit encoding of this FieldElement.
     */
    override fun toByteArray(): ByteArray {
        return edDSAFiniteField!!.encoding.encode(this)
    }

    override fun addOne(): FieldElement {
        return add(edDSAFiniteField!!.ONE!!)
    }

    override fun subtractOne(): FieldElement {
        return subtract(edDSAFiniteField!!.ONE)
    }

    override fun divide(fieldElement: FieldElement): FieldElement {
        return multiply(fieldElement).invert()
    }

    // Note: concrete subclasses must implement hashCode() and equals()
}
