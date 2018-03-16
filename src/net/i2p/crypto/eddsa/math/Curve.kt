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
 * A twisted Edwards curve.
 * Points on the curve satisfy $-x^2 + y^2 = 1 + d x^2y^2$
 * @author str4d
 */
class Curve(val field: FiniteField, d: ByteArray, val i: FieldElement) {
    val d: FieldElement
    val d2: FieldElement

    private val zeroP2: GroupElement
    private val zeroP3: GroupElement
    private val zeroPrecomp: GroupElement

    init {
        this.d = field.fromByteArray(d)
        d2 = this.d.add(this.d)

        val zero = field.ZERO
        val one = field.ONE
        zeroP2 = GroupElement.p2(this, zero, one, one)
        zeroP3 = GroupElement.p3(this, zero, one, one, zero)
        zeroPrecomp = GroupElement.precomp(this, one, one, zero)
    }

    fun getZero(repr: GroupElement.Representation): GroupElement? {
        when (repr) {
            GroupElement.Representation.P2 -> return zeroP2
            GroupElement.Representation.P3 -> return zeroP3
            GroupElement.Representation.PRECOMP -> return zeroPrecomp
            else -> return null
        }
    }

    fun createPoint(P: ByteArray, precompute: Boolean): GroupElement {
        val ge = GroupElement(this, P)
        if (precompute)
            ge.precompute(true)
        return ge
    }

    override fun hashCode(): Int {
        return field.hashCode() xor
                d.hashCode() xor
                i.hashCode()
    }

    override fun equals(o: Any?): Boolean {
        if (o === this)
            return true
        if (o !is Curve)
            return false
        val c = o as Curve?
        return field == c!!.field &&
                d == c.d &&
                i == c.i
    }

    companion object {
        private val serialVersionUID = 4578920872509827L
    }
}
