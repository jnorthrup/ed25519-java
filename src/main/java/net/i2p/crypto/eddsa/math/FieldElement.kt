package net.i2p.crypto.eddsa.math

interface FieldElement {

    val isNonZero: Boolean

    val isNegative: Boolean

    val edDSAFiniteField: EdDSAFiniteField?
    fun toByteArray(): ByteArray

    fun add(element: FieldElement): FieldElement

    fun addOne(): FieldElement

    fun subtract(fieldElement: FieldElement): FieldElement

    fun subtractOne(): FieldElement

    fun negate(): FieldElement

    fun divide(fieldElement: FieldElement): FieldElement

    fun multiply(fieldElement: FieldElement): FieldElement

    fun square(): FieldElement

    fun squareAndDouble(): FieldElement

    fun invert(): FieldElement

    fun pow22523(): FieldElement

    fun cmov(fieldElement: FieldElement, b: Int): FieldElement
}
