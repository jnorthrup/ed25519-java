package net.i2p.crypto.eddsa.math

interface Curve {

    val edDSAFiniteField: EdDSAFiniteField

    val d: FieldElement

    val d2: FieldElement

    val i: FieldElement

    val zeroP2: GroupElement

    val zeroP3: GroupElement

    val zeroP3PrecomputedDouble: GroupElement

    val zeroPrecomp: GroupElement
    operator fun get(repr: Representation): GroupElement

    fun createPoint(P: ByteArray, precompute: Boolean): GroupElement

    override fun hashCode(): Int

    override fun equals(o: Any?): Boolean
}
