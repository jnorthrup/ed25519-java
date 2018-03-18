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
package net.i2p.crypto.eddsa.math.bigint

import java.math.BigInteger

import net.i2p.crypto.eddsa.math.BaseFieldElement
import net.i2p.crypto.eddsa.math.EdDSAFiniteField
import net.i2p.crypto.eddsa.math.FieldElement

/**
 * A particular element of the field \Z/(2^255-19).
 * @author str4d
 */
class BigIntegerFieldElement(f: EdDSAFiniteField,
                             /**
                              * Variable is package private for encoding.
                              */
                             internal val bi: BigInteger) : BaseFieldElement(f) {

    override val isNonZero: Boolean
        get() = bi != BigInteger.ZERO

    override fun add(element: FieldElement): FieldElement {
        return BigIntegerFieldElement(this!!.edDSAFiniteField!!, bi.add((element as BigIntegerFieldElement).bi)).mod(edDSAFiniteField!!.q)
    }

    override fun addOne(): FieldElement {
        return BigIntegerFieldElement(this!!.edDSAFiniteField!!, bi.add(BigInteger.ONE)).mod(edDSAFiniteField!!.q)
    }

    override fun subtract(fieldElement: FieldElement): FieldElement {
        return BigIntegerFieldElement(this!!.edDSAFiniteField!!, bi.subtract((fieldElement as BigIntegerFieldElement).bi)).mod(edDSAFiniteField!!.q)
    }

    override fun subtractOne(): FieldElement {
        return BigIntegerFieldElement(
                this.edDSAFiniteField!!,
                bi.subtract(BigInteger.ONE)
        ).mod(edDSAFiniteField!!.q)
    }

    override fun negate(): FieldElement {
        return edDSAFiniteField!!.q.subtract(this)
    }

    override fun divide(fieldElement: FieldElement): FieldElement {
        return divide((fieldElement as BigIntegerFieldElement).bi)
    }

    private fun divide(bigInteger: BigInteger): FieldElement {
        return BigIntegerFieldElement(this!!.edDSAFiniteField!!, bi.divide(bigInteger)).mod(edDSAFiniteField!!.q)
    }

    override fun multiply(fieldElement: FieldElement): FieldElement {
        return BigIntegerFieldElement(this!!.edDSAFiniteField!!, bi.multiply((fieldElement as BigIntegerFieldElement).bi)).mod(edDSAFiniteField!!.q)
    }

    override fun square(): FieldElement {
        return multiply(this)
    }

    override fun squareAndDouble(): FieldElement {
        val sq = square()
        return sq.add(sq)
    }

    override fun invert(): FieldElement {
        // Euler's theorem
        //return modPow(edDSAFiniteField.getQm2(), edDSAFiniteField.getQ());
        return BigIntegerFieldElement(edDSAFiniteField!!, bi.modInverse((edDSAFiniteField.q as BigIntegerFieldElement).bi))
    }

    private operator fun mod(m: FieldElement): FieldElement {
        return BigIntegerFieldElement(edDSAFiniteField!!, bi.mod((m as BigIntegerFieldElement).bi))
    }

    private fun modPow(e: FieldElement, m: FieldElement): FieldElement {
        return BigIntegerFieldElement(edDSAFiniteField!!, bi.modPow((e as BigIntegerFieldElement).bi, (m as BigIntegerFieldElement).bi))
    }

    private fun pow(e: FieldElement): FieldElement {
        return modPow(e, edDSAFiniteField!!.q)
    }

    override fun pow22523(): FieldElement {
        return pow(edDSAFiniteField!!.qm5d8)
    }

    override fun cmov(fieldElement: FieldElement, b: Int): FieldElement {
        // Not constant-time, but it doesn't really matter because none of the underlying BigInteger operations
        // are either, so there's not much point in trying hard here ...
        return if (0 == b) this else fieldElement
    }

    override fun hashCode(): Int {
        return bi.hashCode()
    }

    override fun equals(obj: Any?): Boolean {
        if (obj !is BigIntegerFieldElement)
            return false
        val fe = obj as BigIntegerFieldElement?
        return bi == fe!!.bi
    }

    override fun toString(): String {
        return "[BigIntegerFieldElement val=$bi]"
    }
}
