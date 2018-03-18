package net.i2p.crypto.eddsa.math;

/**
 * Creates a new group element in P3 representation.
 *
 * @param curve                The curve.
 * @param X                    The $X$ coordinate.
 * @param Y                    The $Y$ coordinate.
 * @param Z                    The $Z$ coordinate.
 * @param T                    The $T$ coordinate.
 * @param precomputeDoubleOnly set to null.
 * @return The group element in P3 representation.
 */
class P3GroupElement extends GroupElement {
    public P3GroupElement(Curve curve, FieldElement x, FieldElement y, FieldElement z, FieldElement t) {
        super(curve, Representation.P3, x, y, z, t, false);
    }
}
