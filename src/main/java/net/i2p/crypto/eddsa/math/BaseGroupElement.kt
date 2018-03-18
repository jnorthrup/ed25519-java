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

import net.i2p.crypto.eddsa.Utils

import java.util.Arrays
import kotlin.experimental.or

/**
 * A point $(x,y)$ on an EdDSA curve.
 *
 *
 * Reviewed/commented by Bloody Rookie (nemproject@gmx.de)
 *
 *
 * Literature:<br></br>
 * [1] Daniel J. Bernstein, Niels Duif, Tanja Lange, Peter Schwabe and Bo-Yin Yang : High-speed high-security signatures<br></br>
 * [2] Huseyin Hisil, Kenneth Koon-Ho Wong, Gary Carter, Ed Dawson: Twisted Edwards Curves Revisited<br></br>
 * [3] Daniel J. Bernsteina, Tanja Lange: A complete set of addition laws for incomplete Edwards curves<br></br>
 * [4] Daniel J. Bernstein, Peter Birkner, Marc Joye, Tanja Lange and Christiane Peters: Twisted Edwards Curves<br></br>
 * [5] Christiane Pascale Peters: Curves, Codes, and Cryptography (PhD thesis)<br></br>
 * [6] Daniel J. Bernstein, Peter Birkner, Tanja Lange and Christiane Peters: Optimizing double-base elliptic-curve single-scalar multiplication<br></br>
 *
 * @author str4d
 */
open class BaseGroupElement : GroupElement {

    /**
     * Gets the curve of the group element.
     *
     * @return The curve.
     */
    override lateinit var curve: Curve
    /**
     * Variable is package public only so that tests run.
     */
    override lateinit var repr: Representation
    /**
     * Variable is package public only so that tests run.
     */
    override lateinit var x: FieldElement
    /**
     * Variable is package public only so that tests run.
     */
    override lateinit var y: FieldElement
    /**
     * Variable is package public only so that tests run.
     */
    override lateinit var z: FieldElement
    /**
     * Variable is package public only so that tests run.
     */
    override lateinit var t: FieldElement
    /**
     * Precomputed table for [.scalarMultiply],
     * filled if necessary.
     *
     *
     * Variable is package public only so that tests run.
     */
    override   var precmp: Array<Array<GroupElement>>  ?=null
    /**
     * Variable is package public only so that tests run.
     */

    /**
     * Precomputed table for [.doubleScalarMultiplyVariableTime],
     * filled if necessary.
     *
     *
     * Variable is package public only so that tests run.
     */
    override var dblPrecmp: Array<GroupElement>?=null

    /**
     * Gets the representation of the group element.
     *
     * @return The representation.
     */
    override val representation: Representation
        get() = this.repr

    /**
     * Verify that a point is on its curve.
     *
     * @return true if the point lies on its curve.
     */
    override val isOnCurve: Boolean
        get() = isOnCurve(curve)

    /**
     * Creates a group element for a curve.
     *
     * @param curve            The curve.
     * @param repr             The representation used to represent the group element.
     * @param X                The $X$ coordinate.
     * @param Y                The $Y$ coordinate.
     * @param Z                The $Z$ coordinate.
     * @param T                The $T$ coordinate.
     * @param precomputeDouble If true, populate dblPrecmp, else set to null.
     */
    protected constructor(
            curve: Curve,
            repr: Representation,
            X: FieldElement,
            Y: FieldElement,
            Z: FieldElement,
            T: FieldElement?,
            precomputeDouble: Boolean) {
        this.curve = curve
        this.repr = repr
        this.x = X
        this.y = Y
        this.z = Z
        this.t = T!!
        this.precmp = null
        this.dblPrecmp = if (precomputeDouble) precomputeDouble() else null
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
     * @param curve                     The curve.
     * @param s                         The encoded point.
     * @param precomputeSingleAndDouble If true, populate both precmp and dblPrecmp, else set both to null.
     */
    // TODO
    constructor(curve: Curve, s: ByteArray, precomputeSingleAndDouble: Boolean) {
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

    constructor() {

    }

    /**
     * Converts the group element to an encoded point on the curve.
     *
     * @return The encoded point as byte array.
     */
    override fun toByteArray(): ByteArray {
        when (this.repr) {
            Representation.P2, Representation.P3 -> {
                val recip = z.invert()
                val x = x.multiply(recip)
                val y = y.multiply(recip)
                val s = y.toByteArray()
                s[s.size - 1] = s[s.size - 1] or if (x.isNegative) 0x80.toByte() else 0.toByte()
                return s
            }
            else -> return Representation.P2.toRep(this).toByteArray()
        }
    }

    /**
     * Precomputes table for [.scalarMultiply].
     */
    override fun precomputeSingle(): Array<Array<GroupElement>> {
        // Precomputation for single scalar multiplication.
        val precmp = Array<Array<GroupElement?>>(32) { arrayOfNulls(8) }
        // TODO-CR BR: check that this == base point when the method is called.
        var Bi: GroupElement = this
        var i = 0
        while (32 > i) {
            var Bij = Bi
            var j = 0
            while (8 > j) {
                val recip = Bij.z.invert()
                val x = Bij.x.multiply(recip)
                val y = Bij.y.multiply(recip)
                precmp[i][j] = PrecompGroupElement(this.curve, y.add(x), y.subtract(x), x.multiply(y).multiply(this.curve.d2))
                Bij = Representation.P3.toRep(Bij.add(Representation.CACHED.toRep(Bi)))
                j++
            }
            // Only every second summand is precomputed (16^2 = 256)
            var k = 0
            while (8 > k) {
                Bi = Representation.P3.toRep(Bi.add(Representation.CACHED.toRep(Bi)))
                k++
            }
            i++
        }
        return precmp as Array<Array<GroupElement>>
    }

    /**
     * Precomputes table for [.doubleScalarMultiplyVariableTime].
     */
    override fun precomputeDouble(): Array<GroupElement> {
        // Precomputation for double scalar multiplication.
        // P,3P,5P,7P,9P,11P,13P,15P
        val dblPrecmp = arrayOfNulls<GroupElement?>(8)
        var Bi: GroupElement = this
        var i = 0
        while (8 > i) {
            val recip = Bi.z.invert()
            val x = Bi.x.multiply(recip)
            val y = Bi.y.multiply(recip)
            dblPrecmp[i] = PrecompGroupElement(this.curve, y.add(x), y.subtract(x), x.multiply(y).multiply(this.curve.d2))
            // Bi = edwards(B,edwards(B,Bi))
            Bi = Representation.P3.toRep(this.add(Representation.CACHED.toRep(Representation.P3.toRep(this.add(Representation.CACHED.toRep(Bi))))))
            i++
        }
        return dblPrecmp as Array<GroupElement>
    }

    /**
     * Doubles a given group element $p$ in $P^2$ or $P^3$ representation and returns the result in $P \times P$ representation.
     * $r = 2 * p$ where $p = (X : Y : Z)$ or $p = (X : Y : Z : T)$
     *
     *
     * $r$ in $P \times P$ representation:
     *
     *
     * $r = ((X' : Z'), (Y' : T'))$ where
     *
     *  * $X' = (X + Y)^2 - (Y^2 + X^2)$
     *  * $Y' = Y^2 + X^2$
     *  * $Z' = y^2 - X^2$
     *  * $T' = 2 * Z^2 - (y^2 - X^2)$
     *
     *
     * $r$ converted from $P \times P$ to $P^2$ representation:
     *
     *
     * $r = (X'' : Y'' : Z'')$ where
     *
     *  * $X'' = X' * Z' = ((X + Y)^2 - Y^2 - X^2) * (2 * Z^2 - (y^2 - X^2))$
     *  * $Y'' = Y' * T' = (Y^2 + X^2) * (2 * Z^2 - (y^2 - X^2))$
     *  * $Z'' = Z' * T' = (y^2 - X^2) * (2 * Z^2 - (y^2 - X^2))$
     *
     *
     * Formula for the $P^2$ representation is in agreement with the formula given in [4] page 12 (with $a = -1$)
     * up to a common factor -1 which does not matter:
     *
     *
     * $$
     * B = (X + Y)^2; C = X^2; D = Y^2; E = -C = -X^2; F := E + D = Y^2 - X^2; H = Z^2; J = F − 2 * H; \\
     * X3 = (B − C − D) · J = X' * (-T'); \\
     * Y3 = F · (E − D) = Z' * (-Y'); \\
     * Z3 = F · J = Z' * (-T').
     * $$
     *
     * @return The P1P1 representation
     */
    override fun dbl(): GroupElement {
        when (this.repr) {
            Representation.P2, Representation.P3 // Ignore T for P3 representation
            -> {
                val XX: FieldElement
                val YY: FieldElement
                val B: FieldElement
                val A: FieldElement
                val AA: FieldElement
                val Yn: FieldElement
                val Zn: FieldElement
                XX = this.x.square()
                YY = this.y.square()
                B = this.z.squareAndDouble()
                A = this.x.add(this.y)
                AA = A.square()
                Yn = YY.add(XX)
                Zn = YY.subtract(XX)

                /**
                 * Creates a new group element in P1P1 representation.
                 *
                 * @param curve The curve.
                 * @param X The $X$ coordinate.
                 * @param Y The $Y$ coordinate.
                 * @param Z The $Z$ coordinate.
                 * @param T The $T$ coordinate.
                 * @return The group element in P1P1 representation.
                 */
                return P1pGroupElement(this.curve, AA.subtract(Yn), Yn, Zn, B.subtract(Zn))
            }
            else -> throw UnsupportedOperationException()
        }
    }

    /**
     * GroupElement addition using the twisted Edwards addition law with
     * extended coordinates (Hisil2008).
     *
     *
     * this must be in $P^3$ representation and $q$ in PRECOMP representation.
     * $r = p + q$ where $p = this = (X1 : Y1 : Z1 : T1), q = (q.X, q.Y, q.Z) = (Y2/Z2 + X2/Z2, Y2/Z2 - X2/Z2, 2 * d * X2/Z2 * Y2/Z2)$
     *
     *
     * $r$ in $P \times P$ representation:
     *
     *
     * $r = ((X' : Z'), (Y' : T'))$ where
     *
     *
     *  * $X' = (Y1 + X1) * q.X - (Y1 - X1) * q.Y = ((Y1 + X1) * (Y2 + X2) - (Y1 - X1) * (Y2 - X2)) * 1/Z2$
     *  * $Y' = (Y1 + X1) * q.X + (Y1 - X1) * q.Y = ((Y1 + X1) * (Y2 + X2) + (Y1 - X1) * (Y2 - X2)) * 1/Z2$
     *  * $Z' = 2 * Z1 + T1 * q.Z = 2 * Z1 + T1 * 2 * d * X2 * Y2 * 1/Z2^2 = (2 * Z1 * Z2 + 2 * d * T1 * T2) * 1/Z2$
     *  * $T' = 2 * Z1 - T1 * q.Z = 2 * Z1 - T1 * 2 * d * X2 * Y2 * 1/Z2^2 = (2 * Z1 * Z2 - 2 * d * T1 * T2) * 1/Z2$
     *
     *
     * Setting $A = (Y1 - X1) * (Y2 - X2), B = (Y1 + X1) * (Y2 + X2), C = 2 * d * T1 * T2, D = 2 * Z1 * Z2$ we get
     *
     *
     *  * $X' = (B - A) * 1/Z2$
     *  * $Y' = (B + A) * 1/Z2$
     *  * $Z' = (D + C) * 1/Z2$
     *  * $T' = (D - C) * 1/Z2$
     *
     *
     * $r$ converted from $P \times P$ to $P^2$ representation:
     *
     *
     * $r = (X'' : Y'' : Z'' : T'')$ where
     *
     *
     *  * $X'' = X' * Z' = (B - A) * (D + C) * 1/Z2^2$
     *  * $Y'' = Y' * T' = (B + A) * (D - C) * 1/Z2^2$
     *  * $Z'' = Z' * T' = (D + C) * (D - C) * 1/Z2^2$
     *  * $T'' = X' * Y' = (B - A) * (B + A) * 1/Z2^2$
     *
     *
     * TODO-CR BR: Formula for the $P^2$ representation is not in agreement with the formula given in [2] page 6<br></br>
     * TODO-CR BR: (the common factor $1/Z2^2$ does not matter):<br></br>
     * $$
     * E = B - A, F = D - C, G = D + C, H = B + A \\
     * X3 = E * F = (B - A) * (D - C); \\
     * Y3 = G * H = (D + C) * (B + A); \\
     * Z3 = F * G = (D - C) * (D + C); \\
     * T3 = E * H = (B - A) * (B + A);
     * $$
     *
     * @param q the PRECOMP representation of the GroupElement to add.
     * @return the P1P1 representation of the result.
     */
    override fun madd(q: GroupElement): GroupElement {
        assert(Representation.P3 === this.repr)
        assert(Representation.PRECOMP === q.repr)

        val YpX: FieldElement
        val YmX: FieldElement
        val A: FieldElement
        val B: FieldElement
        val C: FieldElement
        val D: FieldElement
        YpX = this.y.add(this.x)
        YmX = this.y.subtract(this.x)
        A = YpX.multiply(q.x) // q->y+x
        B = YmX.multiply(q.y) // q->y-x
        C = q.z.multiply(this.t) // q->2dxy
        D = this.z.add(this.z)

        /**
         * Creates a new group element in P1P1 representation.
         *
         * @param curve The curve.
         * @param X The $X$ coordinate.
         * @param Y The $Y$ coordinate.
         * @param Z The $Z$ coordinate.
         * @param T The $T$ coordinate.
         * @return The group element in P1P1 representation.
         */
        return P1pGroupElement(this.curve, A.subtract(B), A.add(B), D.add(C), D.subtract(C))
    }

    /**
     * GroupElement subtraction using the twisted Edwards addition law with
     * extended coordinates (Hisil2008).
     *
     *
     * this must be in $P^3$ representation and $q$ in PRECOMP representation.
     * $r = p - q$ where $p = this = (X1 : Y1 : Z1 : T1), q = (q.X, q.Y, q.Z) = (Y2/Z2 + X2/Z2, Y2/Z2 - X2/Z2, 2 * d * X2/Z2 * Y2/Z2)$
     *
     *
     * Negating $q$ means negating the value of $X2$ and $T2$ (the latter is irrelevant here).
     * The formula is in accordance to [the above addition][.madd].
     *
     * @param q the PRECOMP representation of the GroupElement to subtract.
     * @return the P1P1 representation of the result.
     */
    override fun msub(q: GroupElement): GroupElement {
        assert(Representation.P3 === this.repr)
        assert(Representation.PRECOMP === q.repr)

        val YpX: FieldElement
        val YmX: FieldElement
        val A: FieldElement
        val B: FieldElement
        val C: FieldElement
        val D: FieldElement
        YpX = this.y.add(this.x)
        YmX = this.y.subtract(this.x)
        A = YpX.multiply(q.y) // q->y-x
        B = YmX.multiply(q.x) // q->y+x
        C = q.z.multiply(this.t) // q->2dxy
        D = this.z.add(this.z)

        /**
         * Creates a new group element in P1P1 representation.
         *
         * @param curve The curve.
         * @param X The $X$ coordinate.
         * @param Y The $Y$ coordinate.
         * @param Z The $Z$ coordinate.
         * @param T The $T$ coordinate.
         * @return The group element in P1P1 representation.
         */
        return P1pGroupElement(this.curve, A.subtract(B), A.add(B), D.subtract(C), D.add(C))
    }

    /**
     * GroupElement addition using the twisted Edwards addition law with
     * extended coordinates (Hisil2008).
     *
     *
     * this must be in $P^3$ representation and $q$ in CACHED representation.
     * $r = p + q$ where $p = this = (X1 : Y1 : Z1 : T1), q = (q.X, q.Y, q.Z, q.T) = (Y2 + X2, Y2 - X2, Z2, 2 * d * T2)$
     *
     *
     * $r$ in $P \times P$ representation:
     *
     *  * $X' = (Y1 + X1) * (Y2 + X2) - (Y1 - X1) * (Y2 - X2)$
     *  * $Y' = (Y1 + X1) * (Y2 + X2) + (Y1 - X1) * (Y2 - X2)$
     *  * $Z' = 2 * Z1 * Z2 + 2 * d * T1 * T2$
     *  * $T' = 2 * Z1 * T2 - 2 * d * T1 * T2$
     *
     *
     * Setting $A = (Y1 - X1) * (Y2 - X2), B = (Y1 + X1) * (Y2 + X2), C = 2 * d * T1 * T2, D = 2 * Z1 * Z2$ we get
     *
     *  * $X' = (B - A)$
     *  * $Y' = (B + A)$
     *  * $Z' = (D + C)$
     *  * $T' = (D - C)$
     *
     *
     * Same result as in [.madd] (up to a common factor which does not matter).
     *
     * @param q the CACHED representation of the GroupElement to add.
     * @return the P1P1 representation of the result.
     */
    override fun add(q: GroupElement): GroupElement {
        assert(Representation.P3 === this.repr)
        assert(Representation.CACHED === q.repr)

        val YpX: FieldElement
        val YmX: FieldElement
        val A: FieldElement
        val B: FieldElement
        val C: FieldElement
        val ZZ: FieldElement
        val D: FieldElement
        YpX = this.y.add(this.x)
        YmX = this.y.subtract(this.x)
        A = YpX.multiply(q.x) // q->Y+X
        B = YmX.multiply(q.y) // q->Y-X
        C = q.t.multiply(this.t) // q->2dT
        ZZ = this.z.multiply(q.z)
        D = ZZ.add(ZZ)

        /**
         * Creates a new group element in P1P1 representation.
         *
         * @param curve The curve.
         * @param X The $X$ coordinate.
         * @param Y The $Y$ coordinate.
         * @param Z The $Z$ coordinate.
         * @param T The $T$ coordinate.
         * @return The group element in P1P1 representation.
         */
        return P1pGroupElement(this.curve, A.subtract(B), A.add(B), D.add(C), D.subtract(C))
    }

    /**
     * GroupElement subtraction using the twisted Edwards addition law with
     * extended coordinates (Hisil2008).
     *
     *
     * $r = p - q$
     *
     *
     * Negating $q$ means negating the value of the coordinate $X2$ and $T2$.
     * The formula is in accordance to [the above addition][.add].
     *
     * @param q the PRECOMP representation of the GroupElement to subtract.
     * @return the P1P1 representation of the result.
     */
    override fun sub(q: GroupElement): GroupElement {
        assert(Representation.P3 === this.repr)
        assert(Representation.CACHED === q.repr)

        val YpX: FieldElement
        val YmX: FieldElement
        val A: FieldElement
        val B: FieldElement
        val C: FieldElement
        val ZZ: FieldElement
        val D: FieldElement
        YpX = y.add(x)
        YmX = y.subtract(x)
        A = YpX.multiply(q.y) // q->Y-X
        B = YmX.multiply(q.x) // q->Y+X
        C = q.t.multiply(t) // q->2dT
        ZZ = z.multiply(q.z)
        D = ZZ.add(ZZ)

        /**
         * Creates a new group element in P1P1 representation.
         *
         * @param curve The curve.
         * @param X The $X$ coordinate.
         * @param Y The $Y$ coordinate.
         * @param Z The $Z$ coordinate.
         * @param T The $T$ coordinate.
         * @return The group element in P1P1 representation.
         */
        return P1pGroupElement(curve, A.subtract(B), A.add(B), D.subtract(C), D.add(C))
    }

    /**
     * Negates this group element by subtracting it from the neutral group element.
     *
     *
     * TODO-CR BR: why not simply negate the coordinates $X$ and $T$?
     *
     * @return The negative of this group element.
     */
    override fun negate(): GroupElement {
        assert(Representation.P3 === this.repr)
        return Representation.P3PrecomputedDouble.toRep(this.curve.get(Representation.P3).sub(Representation.CACHED.toRep(this)))
    }

    override fun hashCode(): Int {
        return Arrays.hashCode(this.toByteArray())
    }

    override fun equals(obj: Any?): Boolean {
        if (obj === this)
            return true
        if (obj !is GroupElement)
            return false
        var ge: GroupElement = obj
        if (this.repr !== ge.repr) {
            try {
                ge = this.repr.toRep(ge)
            } catch (e: RuntimeException) {
                return false
            }

        }
        when (this.repr) {
            Representation.P2, Representation.P3 -> {
                // Try easy way first
                if (this.z == ge.z)
                    return this.x == ge.x && this.y == ge.y
                // X1/Z1 = X2/Z2 --> X1*Z2 = X2*Z1
                val x1 = this.x.multiply(ge.z)
                val y1 = this.y.multiply(ge.z)
                val x2 = ge.x.multiply(this.z)
                val y2 = ge.y.multiply(this.z)
                return x1 == x2 && y1 == y2
            }
            Representation.P1P1 -> return Representation.P2.toRep(this) == ge
            Representation.PRECOMP ->
                // Compare directly, PRECOMP is derived directly from x and y
                return this.x == ge.x && this.y == ge.y && this.z == ge.z
            Representation.CACHED -> {
                // Try easy way first
                if (this.z == ge.z)
                    return this.x == ge.x && this.y == ge.y && this.t == ge.t
                // (Y+X)/Z = y+x etc.
                val x3 = this.x.multiply(ge.z)
                val y3 = this.y.multiply(ge.z)
                val t3 = this.t.multiply(ge.z)
                val x4 = ge.x.multiply(this.z)
                val y4 = ge.y.multiply(this.z)
                val t4 = ge.t.multiply(this.z)
                return x3 == x4 && y3 == y4 && t3 == t4
            }
            else -> return false
        }
    }

    /**
     * Constant-time conditional move.
     *
     *
     * Replaces this with $u$ if $b == 1$.<br></br>
     * Replaces this with this if $b == 0$.
     *
     *
     * Method is package public only so that tests run.
     *
     * @param u The group element to return if $b == 1$.
     * @param b in $\{0, 1\}$
     * @return $u$ if $b == 1$; this if $b == 0$. Results undefined if $b$ is not in $\{0, 1\}$.
     */
    override fun cmov(u: GroupElement, b: Int): PrecompGroupElement {

        return PrecompGroupElement(curve, x.cmov(u.x, b), y.cmov(u.y, b), z.cmov(u.z, b))
    }

    /**
     * Look up $16^i r_i B$ in the precomputed table.
     *
     *
     * No secret array indices, no secret branching.
     * Constant time.
     *
     *
     * Must have previously precomputed.
     *
     *
     * Method is package public only so that tests run.
     *
     * @param pos $= i/2$ for $i$ in $\{0, 2, 4,..., 62\}$
     * @param b   $= r_i$
     * @return the GroupElement
     */
    override fun select(pos: Int, b: Int): PrecompGroupElement {
        // Is r_i negative?
        val bnegative = Utils.negative(b)
        // |r_i|
        val babs = b - (-bnegative and b shl 1)

        // 16^i |r_i| B
        val t = this.curve.get(Representation.PRECOMP)
                .cmov(this.precmp!![pos][0], Utils.equal(babs, 1))
                .cmov(this.precmp!![pos][1], Utils.equal(babs, 2))
                .cmov(this.precmp!![pos][2], Utils.equal(babs, 3))
                .cmov(this.precmp!![pos][3], Utils.equal(babs, 4))
                .cmov(this.precmp!![pos][4], Utils.equal(babs, 5))
                .cmov(this.precmp!![pos][5], Utils.equal(babs, 6))
                .cmov(this.precmp!![pos][6], Utils.equal(babs, 7))
                .cmov(this.precmp!![pos][7], Utils.equal(babs, 8))
        // -16^i |r_i| B
        val tminus = PrecompGroupElement(curve, t.y, t.x, t.z.negate())
        // 16^i r_i B
        return t.cmov(tminus, bnegative)
    }

    /**
     * $h = a * B$ where $a = a[0]+256*a[1]+\dots+256^{31} a[31]$ and
     * $B$ is this point. If its lookup table has not been precomputed, it
     * will be at the start of the method (and cached for later calls).
     * Constant time.
     *
     *
     * Preconditions: (TODO: Check this applies here)
     * $a[31] \le 127$
     *
     * @param a $= a[0]+256*a[1]+\dots+256^{31} a[31]$
     * @return the GroupElement
     */
    override fun scalarMultiply(a: ByteArray): GroupElement {
        var t: GroupElement
        var i: Int

        val e = GroupElement.toRadix16(a)

        var h = this.curve.get(Representation.P3)
        i = 1
        while (64 > i) {
            t = select(i / 2, e[i].toInt())
            h = Representation.P3.toRep(h.madd(t))
            i += 2
        }

        h = Representation.P3.toRep(Representation.P2.toRep(Representation.P2.toRep(Representation.P2.toRep(h.dbl()).dbl()).dbl()).dbl())

        i = 0
        while (64 > i) {
            t = select(i / 2, e[i].toInt())
            h = Representation.P3.toRep(h.madd(t))
            i += 2
        }

        return h
    }

    /**
     * $r = a * A + b * B$ where $a = a[0]+256*a[1]+\dots+256^{31} a[31]$,
     * $b = b[0]+256*b[1]+\dots+256^{31} b[31]$ and $B$ is this point.
     *
     *
     * $A$ must have been previously precomputed.
     *
     * @param A in P3 representation.
     * @param a $= a[0]+256*a[1]+\dots+256^{31} a[31]$
     * @param b $= b[0]+256*b[1]+\dots+256^{31} b[31]$
     * @return the GroupElement
     */
    override fun doubleScalarMultiplyVariableTime(A: GroupElement, a: ByteArray, b: ByteArray): GroupElement {
        // TODO-CR BR: A check that this is the base point is needed.
        val aslide = GroupElement.slide(a)
        val bslide = GroupElement.slide(b)

        var r = this.curve.get(Representation.P2)

        var i: Int
        i = 255
        while (0 <= i) {
            if (0 != aslide[i].toInt() || 0 != bslide[i].toInt()) break
            --i
        }

        while (0 <= i) {
            var t = r.dbl()

            if (0 < aslide[i]) {
                t = Representation.P3.toRep(t).madd(A.dblPrecmp!![aslide[i] / 2])
            } else if (0 > aslide[i]) {
                t = Representation.P3.toRep(t).msub(A.dblPrecmp!![-aslide[i] / 2])
            }

            if (0 < bslide[i]) {
                t = Representation.P3.toRep(t).madd(this.dblPrecmp!![bslide[i] / 2])
            } else if (0 > bslide[i]) {
                t = Representation.P3.toRep(t).msub(this.dblPrecmp!![-bslide[i] / 2])
            }

            r = Representation.P2.toRep(t)
            --i
        }

        return r
    }

    /**
     * Verify that a point is on the curve.
     *
     * @param curve The curve to check.
     * @return true if the point lies on the curve.
     */
    override fun isOnCurve(curve: Curve): Boolean {
        when (repr) {
            Representation.P2, Representation.P3 -> {
                val recip = z.invert()
                val x = x.multiply(recip)
                val y = y.multiply(recip)
                val xx = x.square()
                val yy = y.square()
                val dxxyy = curve.d.multiply(xx).multiply(yy)
                return curve.edDSAFiniteField.ONE.add(dxxyy).add(xx) == yy
            }

            else -> return Representation.P2.toRep(this).isOnCurve(curve)
        }
    }

    override fun toString(): String {
        return "[GroupElement\nX=$x\nY=$y\nZ=$z\nT=$t\n]"
    }

}
