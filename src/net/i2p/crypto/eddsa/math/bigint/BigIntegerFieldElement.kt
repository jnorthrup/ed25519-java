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

import net.i2p.crypto.eddsa.math.FiniteField
import net.i2p.crypto.eddsa.math.FieldElement

/**
 * A particular element of the field \Z/(2^255-19).
 * @author str4d
 */
class BigIntegerFieldElement(f: FiniteField,
                             /**
                              * Variable is package private for encoding.
                              */
                             internal val bi: BigInteger) : FieldElement(f) {

    override val isNonZero: Boolean
        get() = bi != BigInteger.ZERO

    override fun add(`val`: FieldElement): FieldElement {
        return BigIntegerFieldElement(f, bi.add((`val` as BigIntegerFieldElement).bi)).mod(f.q)
    }

    override fun addOne(): FieldElement {
        return BigIntegerFieldElement(f, bi.add(BigInteger.ONE)).mod(f.q)
    }

    override fun subtract(`val`: FieldElement): FieldElement {
        return BigIntegerFieldElement(f, bi.subtract((`val` as BigIntegerFieldElement).bi)).mod(f.q)
    }

    override fun subtractOne(): FieldElement {
        return BigIntegerFieldElement(f, bi.subtract(BigInteger.ONE)).mod(f.q)
    }

    override fun negate(): FieldElement {
        return f.q.subtract(this)
    }

    override fun divide(`val`: FieldElement): FieldElement {
        return divide((`val` as BigIntegerFieldElement).bi)
    }

    private fun divide(`val`: BigInteger): FieldElement {
        return BigIntegerFieldElement(f, bi.divide(`val`)).mod(f.q)
    }

    override fun multiply(`val`: FieldElement): FieldElement {
        return BigIntegerFieldElement(f, bi.multiply((`val` as BigIntegerFieldElement).bi)).mod(f.q)
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
        //return modPow(field.getQm2(), finiteField.getQ());
        return BigIntegerFieldElement(f, bi.modInverse((f.q as BigIntegerFieldElement).bi))
    }

    private operator fun mod(m: FieldElement): FieldElement {
        return BigIntegerFieldElement(f, bi.mod((m as BigIntegerFieldElement).bi))
    }

    private fun modPow(e: FieldElement, m: FieldElement): FieldElement {
        return BigIntegerFieldElement(f, bi.modPow((e as BigIntegerFieldElement).bi, (m as BigIntegerFieldElement).bi))
    }

    private fun pow(e: FieldElement): FieldElement {
        return modPow(e, f.q)
    }

    override fun pow22523(): FieldElement {
        return pow(f.qm5d8)
    }

    override fun cmov(`val`: FieldElement, b: Int): FieldElement {
        // Not constant-time, but it doesn't really matter because none of the underlying BigInteger operations
        // are either, so there's not much point in trying hard here ...
        return if (0 == b) this else `val`
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
