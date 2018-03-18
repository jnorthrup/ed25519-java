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
public class P3GroupElement extends GroupElement {
    public P3GroupElement(Curve curve, FieldElement x, FieldElement y, FieldElement z, FieldElement t) {
        super(curve, Representation.P3, x, y, z, t, false);
    }

    /**
     * Creates a group element for a curve from a given encoded point.
     * <p>
     * A point $(x,y)$ is encoded by storing $y$ in bit 0 to bit 254 and the sign of $x$ in bit 255.
     * $x$ is recovered in the following way:
     * </p><ul>
     * <li>$x = sign(x) * \sqrt{(y^2 - 1) / (d * y^2 + 1)} = sign(x) * \sqrt{u / v}$ with $u = y^2 - 1$ and $v = d * y^2 + 1$.
     * <li>Setting $β = (u * v^3) * (u * v^7)^{((q - 5) / 8)}$ one has $β^2 = \pm(u / v)$.
     * <li>If $v * β = -u$ multiply $β$ with $i=\sqrt{-1}$.
     * <li>Set $x := β$.
     * <li>If $sign(x) \ne$ bit 255 of $s$ then negate $x$.
     * </ul>
     *
     * @param curve The curve.
     * @param s     The encoded point.
     */
    public P3GroupElement(final Curve curve, final byte[] s) {
        /**
         * Creates a group element for a curve from a given encoded point.
         * <p>
         * A point $(x,y)$ is encoded by storing $y$ in bit 0 to bit 254 and the sign of $x$ in bit 255.
         * $x$ is recovered in the following way:
         * </p><ul>
         * <li>$x = sign(x) * \sqrt{(y^2 - 1) / (d * y^2 + 1)} = sign(x) * \sqrt{u / v}$ with $u = y^2 - 1$ and $v = d * y^2 + 1$.
         * <li>Setting $β = (u * v^3) * (u * v^7)^{((q - 5) / 8)}$ one has $β^2 = \pm(u / v)$.
         * <li>If $v * β = -u$ multiply $β$ with $i=\sqrt{-1}$.
         * <li>Set $x := β$.
         * <li>If $sign(x) \ne$ bit 255 of $s$ then negate $x$.
         * </ul>
         *
         * @param curve The curve.
         * @param s     The encoded point.
         */super(curve, s, false);
    }
}
