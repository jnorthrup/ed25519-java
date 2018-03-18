package net.i2p.crypto.eddsa.math

/**
 * Creates a new group element in P3 representation.
 *
 * @param curve                The curve.
 * @param X                    The $X$ coordinate.
 * @param Y                    The $Y$ coordinate.
 * @param Z                    The $Z$ coordinate.
 * @param T                    The $T$ coordinate.
 * @param precomputeDoubleOnly populate dblPrecmp
 * @return The group element in P3 representation.
 */
open class P3PreGroupElement : P3GroupElement {
    constructor(curve: Curve, x: FieldElement, y: FieldElement, z: FieldElement, t: FieldElement) : super(curve, x, y, z, t, true) {}

    constructor(curve: Curve, bytes: ByteArray) : super(curve, bytes, true) {}
}
