/**
 * EdDSA-Java by str4d
 *
 *
 * To the extent possible under law, the person who associated CC0 with
 * EdDSA-Java has waived all copyright and related or neighboring rights
 * to EdDSA-Java.
 *
 *
 * You should have received a copy of the CC0 legalcode along with this
 * work. If not, see <https:></https:>//creativecommons.org/publicdomain/zero/1.0/>.
 */
package net.i2p.crypto.eddsa.math

import java.util.EnumMap
import java.util.concurrent.Callable

/**
 * A twisted Edwards curve.
 * Points on the curve satisfy $-x^2 + y^2 = 1 + bytes x^2y^2$
 *
 * @author str4d
 */
class BaseCurve(override val edDSAFiniteField: EdDSAFiniteField, bytes: ByteArray, override val i: FieldElement, override val d: FieldElement= edDSAFiniteField.fromByteArray(bytes), override val d2: FieldElement= d.add(d)) : Curve {

    internal val source =  EnumMap<Representation, Callable<out GroupElement>>( Representation::class.java)

    internal val facade = EnumMap<Representation, GroupElement>(Representation::class.java)

    override val zeroP2: GroupElement
        @Throws(RuntimeException::class)
        get() = (facade as java.util.Map<Representation, GroupElement>).computeIfAbsent(Representation.P2,  { this.get(it) })

    override val zeroP3: GroupElement
        get() = (facade as java.util.Map<Representation, GroupElement>).computeIfAbsent(Representation.P3, { this.get(it) })

    override val zeroP3PrecomputedDouble: GroupElement
        get() = (facade as java.util.Map<Representation, GroupElement>).computeIfAbsent(Representation.P3PrecomputedDouble,  { this.get(it) })

    override val zeroPrecomp: GroupElement
        get() = (facade as java.util.Map<Representation, GroupElement>).computeIfAbsent(Representation.PRECOMP,  { this.get(it) })

    init {
        val zero = edDSAFiniteField.ZERO
        val one = edDSAFiniteField.ONE
        val c = this

        //        this is cost of an array to lazy biootstrap the 4 used curves

         source+=      (Representation.P2 to  Callable{ P2GroupElement(c, zero, one, one) })
         source+=    (Representation.P3 to Callable{ P3GroupElement(c, zero, one, one, zero) }  )
         source+=    (Representation.P3PrecomputedDouble to Callable{ P3PrecomputedDoubleGroupElement(c, zero, one) }  )
         source+=    (Representation.PRECOMP to Callable{ PrecompGroupElement(c, one, one, zero) }  )
        }



    override fun createPoint(P: ByteArray, precompute: Boolean): GroupElement {
        assert(precompute)
        return P3PreGroupElement(this, P)
    }

    override fun hashCode(): Int {
        return edDSAFiniteField.hashCode() xor
                d.hashCode() xor
                i.hashCode()
    }

    override fun equals(o: Any?): Boolean {
        if (o === this)
            return true
        if (o !is Curve)
            return false
        val c = o as Curve?
        return edDSAFiniteField == c!!.edDSAFiniteField &&
                d == c.d &&
                i == c.i
    }

override fun get(representation: Representation): GroupElement {
        return (facade as java.util.Map<Representation, GroupElement>).computeIfAbsent(representation) {source [it]!!.call() }
    }

}
