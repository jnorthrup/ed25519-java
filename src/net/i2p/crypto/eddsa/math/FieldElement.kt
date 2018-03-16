package net.i2p.crypto.eddsa.math

/**
 * Note: concrete subclasses must implement hashCode() and equals()
 */
abstract class FieldElement protected constructor(protected val f: FiniteField?) {

    abstract val isNonZero: Boolean

    val isNegative: Boolean
        get() = f.encoding.isNegative(this)

    init {
        if (null == f) {
            throw IllegalArgumentException("field cannot be null")
        }
    }

    /**
     * Encode a FieldElement in its $(b-1)$-bit encoding.
     * @return the $(b-1)$-bit encoding of this FieldElement.
     */
    fun toByteArray(): ByteArray {
        return f.encoding.encode(this)
    }

    abstract fun add(`val`: FieldElement): FieldElement

    open fun addOne(): FieldElement {
        return add(f.ONE)
    }

    abstract fun subtract(`val`: FieldElement): FieldElement

    open fun subtractOne(): FieldElement {
        return subtract(f.ONE)
    }

    abstract fun negate(): FieldElement

    open fun divide(`val`: FieldElement): FieldElement {
        return multiply(`val`.invert())
    }

    abstract fun multiply(`val`: FieldElement): FieldElement

    abstract fun square(): FieldElement

    abstract fun squareAndDouble(): FieldElement

    abstract fun invert(): FieldElement

    abstract fun pow22523(): FieldElement

    abstract fun cmov(`val`: FieldElement, b: Int): FieldElement

    companion object {
        private val serialVersionUID = 1239527465875676L
    }

    // Note: concrete subclasses must implement hashCode() and equals()
}
