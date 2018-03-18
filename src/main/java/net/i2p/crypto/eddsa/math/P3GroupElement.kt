package net.i2p.crypto.eddsa.math

import net.i2p.crypto.eddsa.Utils

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
open class P3GroupElement : BaseGroupElement {
    constructor(curve: Curve, x: FieldElement, y: FieldElement, z: FieldElement, t: FieldElement, precompute: Boolean) : super(curve, Representation.P3, x, y, z, t, precompute) {}
    /**
     * Creates a group element for a curve from a given encoded point.
     *
     *
     * A point $(x,y)$ is encoded by storing $y$ in bit 0 to bit 254 and the sign of $x$ in bit 255.
     * $x$ is recovered in the following way:
     *
     *  * $x = sign(x) * \sqrt{(y^2 - 1) / (d * y^2 + 1)} = sign(x) * \sqrt{u / v}$ with $u = y^2 - 1$ and $v = d * y^2 + 1$.
     *  * Setting $β = (u * v^3) * (u * v^7)^{((q - 5) / 8)}$ one has $β^2 = \pm(u / v)$.
     *  * If $v * β = -u$ multiply $β$ with $i=\sqrt{-1}$.
     *  * Set $x := β$.
     *  * If $sign(x) \ne$ bit 255 of $s$ then negate $x$.
     *
     *
     * @param curve                     The curve.
     * @param s                         The encoded point.
     * @param precomputeSingleAndDouble If true, populate both precmp and dblPrecmp, else set both to null.
     */
    // TODO
    /*protected GroupElement(*/
    @JvmOverloads constructor(//Curve curve, Representation p3, FieldElement x, FieldElement y, FieldElement z, FieldElement t, boolean b) {


            curve: Curve, s: ByteArray, precomputeSingleAndDouble: Boolean = false) : super() {
        var x: FieldElement
        val y: FieldElement
        val yy: FieldElement
        val u: FieldElement
        val v: FieldElement
        val v3: FieldElement
        val vxx: FieldElement
        var check: FieldElement
        y = curve.edDSAFiniteField.fromByteArray(s)
        yy = y.square()

        // u = y^2-1
        u = yy.subtractOne()

        // v = dy^2+1
        v = yy.multiply(curve.d).addOne()

        // v3 = v^3
        v3 = v.square().multiply(v)

        // x = (v3^2)vu, aka x = uv^7
        x = v3.square().multiply(v).multiply(u)

        //  x = (uv^7)^((q-5)/8)
        x = x.pow22523()

        // x = uv^3(uv^7)^((q-5)/8)
        x = v3.multiply(u).multiply(x)

        vxx = x.square().multiply(v)
        check = vxx.subtract(u)            // vx^2-u
        if (check.isNonZero) {
            check = vxx.add(u)             // vx^2+u

            assert(!check.isNonZero) { "not a valid GroupElement" }
            x = x.multiply(curve.i)
        }

        if ((if (x.isNegative) 1 else 0) != Utils.bit(s, curve.edDSAFiniteField.b - 1)) {
            x = x.negate()
        }

        this.curve = curve
        this.repr = Representation.P3
        this.x = x
        this.y = y
        this.z = curve.edDSAFiniteField.ONE
        this.t = this.x.multiply(this.y)
        if (precomputeSingleAndDouble) {
            precmp = precomputeSingle()
            dblPrecmp = precomputeDouble()
        } else {
            precmp = null
            dblPrecmp = null
        }
    }

    constructor(curve2: Curve, x1: FieldElement, y1: FieldElement, z1: FieldElement, t1: FieldElement) : this(curve2, x1, y1, z1, t1, false) {}
}
/**
 * Creates a group element for a curve from a given encoded point.
 *
 *
 * A point $(x,y)$ is encoded by storing $y$ in bit 0 to bit 254 and the sign of $x$ in bit 255.
 * $x$ is recovered in the following way:
 *
 *  * $x = sign(x) * \sqrt{(y^2 - 1) / (d * y^2 + 1)} = sign(x) * \sqrt{u / v}$ with $u = y^2 - 1$ and $v = d * y^2 + 1$.
 *  * Setting $β = (u * v^3) * (u * v^7)^{((q - 5) / 8)}$ one has $β^2 = \pm(u / v)$.
 *  * If $v * β = -u$ multiply $β$ with $i=\sqrt{-1}$.
 *  * Set $x := β$.
 *  * If $sign(x) \ne$ bit 255 of $s$ then negate $x$.
 *
 *
 * @param curve The curve.
 * @param s     The encoded point.
 */
/**
 * Creates a group element for a curve from a given encoded point.
 *
 *
 * A point $(x,y)$ is encoded by storing $y$ in bit 0 to bit 254 and the sign of $x$ in bit 255.
 * $x$ is recovered in the following way:
 *
 *  * $x = sign(x) * \sqrt{(y^2 - 1) / (d * y^2 + 1)} = sign(x) * \sqrt{u / v}$ with $u = y^2 - 1$ and $v = d * y^2 + 1$.
 *  * Setting $β = (u * v^3) * (u * v^7)^{((q - 5) / 8)}$ one has $β^2 = \pm(u / v)$.
 *  * If $v * β = -u$ multiply $β$ with $i=\sqrt{-1}$.
 *  * Set $x := β$.
 *  * If $sign(x) \ne$ bit 255 of $s$ then negate $x$.
 *
 *
 * @param curve The curve.
 * @param s     The encoded point.
 */
