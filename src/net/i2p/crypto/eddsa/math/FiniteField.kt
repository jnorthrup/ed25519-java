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
 * An EdDSA finite field. Includes several pre-computed values.
 * @author str4d
 */
class FiniteField(val b: Int, q: ByteArray, val encoding: Encoding) {

    val ZERO: FieldElement
    val ONE: FieldElement
    val TWO: FieldElement
    private val FOUR: FieldElement
    private val FIVE: FieldElement
    private val EIGHT: FieldElement
    val q: FieldElement
    /**
     * q-2
     */
    val qm2: FieldElement
    /**
     * (q-5) / 8
     */
    val qm5d8: FieldElement

    init {
        this.encoding.setFiniteField(this)

        this.q = fromByteArray(q)

        // Set up constants
        ZERO = fromByteArray(Constants.ZERO)
        ONE = fromByteArray(Constants.ONE)
        TWO = fromByteArray(Constants.TWO)
        FOUR = fromByteArray(Constants.FOUR)
        FIVE = fromByteArray(Constants.FIVE)
        EIGHT = fromByteArray(Constants.EIGHT)

        // Precompute values
        qm2 = this.q.subtract(TWO)
        qm5d8 = this.q.subtract(FIVE).divide(EIGHT)
    }

    fun fromByteArray(x: ByteArray): FieldElement {
        return encoding.decode(x)
    }

    fun getb(): Int {
        return b
    }

    override fun hashCode(): Int {
        return q.hashCode()
    }

    override fun equals(obj: Any?): Boolean {
        if (obj !is FiniteField)
            return false
        val f = obj as FiniteField?
        return b == f!!.b && q == f.q
    }

    companion object {
        private val serialVersionUID = 8746587465875676L
    }

}
