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
class GroupElement {
    /**
     * Variable is package private only so that tests run.
     */
    /**
     * Gets the curve of the group element.
     *
     * @return The curve.
     */
    val curve: Curve
    /**
     * Variable is package private only so that tests run.
     */
    /**
     * Gets the representation of the group element.
     *
     * @return The representation.
     */
    val representation: Representation
    /**
     * Variable is package private only so that tests run.
     */
    /**
     * Gets the $X$ value of the group element.
     * This is for most representation the projective $X$ coordinate.
     *
     * @return The $X$ value.
     */
    val x: FieldElement
    /**
     * Variable is package private only so that tests run.
     */
    /**
     * Gets the $Y$ value of the group element.
     * This is for most representation the projective $Y$ coordinate.
     *
     * @return The $Y$ value.
     */
    val y: FieldElement
    /**
     * Variable is package private only so that tests run.
     */
    /**
     * Gets the $Z$ value of the group element.
     * This is for most representation the projective $Z$ coordinate.
     *
     * @return The $Z$ value.
     */
    val z: FieldElement
    /**
     * Variable is package private only so that tests run.
     */
    /**
     * Gets the $T$ value of the group element.
     * This is for most representation the projective $T$ coordinate.
     *
     * @return The $T$ value.
     */
    val t: FieldElement
    /**
     * Precomputed table for [.scalarMultiply],
     * filled if necessary.
     *
     *
     * Variable is package private only so that tests run.
     */
    internal var precmp: Array<Array<GroupElement>>? = null
    /**
     * Precomputed table for [.doubleScalarMultiplyVariableTime],
     * filled if necessary.
     *
     *
     * Variable is package private only so that tests run.
     */
    internal var dblPrecmp: Array<GroupElement>? = null

    /**
     * Verify that a point is on its curve.
     * @return true if the point lies on its curve.
     */
    val isOnCurve: Boolean
        get() = isOnCurve(curve)

    /**
     * Creates a group element for a curve.
     *
     * @param curve The curve.
     * @param repr The representation used to represent the group element.
     * @param X The $X$ coordinate.
     * @param Y The $Y$ coordinate.
     * @param Z The $Z$ coordinate.
     * @param T The $T$ coordinate.
     */
    constructor(
            curve: Curve,
            repr: Representation,
            X: FieldElement,
            Y: FieldElement,
            Z: FieldElement,
            T: FieldElement) {
        this.curve = curve
        this.representation = repr
        this.x = X
        this.y = Y
        this.z = Z
        this.t = T
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
     * @param s The encoded point.
     */
    constructor(curve: Curve, s: ByteArray) {
        var x: FieldElement
        val y: FieldElement
        val yy: FieldElement
        val u: FieldElement
        val v: FieldElement
        val v3: FieldElement
        val vxx: FieldElement
        var check: FieldElement
        y = curve.field.fromByteArray(s)
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

            if (check.isNonZero)
                throw IllegalArgumentException("not a valid GroupElement")
            x = x.multiply(curve.i)
        }

        if ((if (x.isNegative) 1 else 0) != Utils.bit(s, curve.field.getb() - 1)) {
            x = x.negate()
        }

        this.curve = curve
        representation = Representation.P3
        this.x = x
        this.y = y
        z = curve.field.ONE
        t = this.x.multiply(this.y)
    }

    /**
     * Converts the group element to an encoded point on the curve.
     *
     * @return The encoded point as byte array.
     */
    fun toByteArray(): ByteArray {
        when (representation) {
            GroupElement.Representation.P2, GroupElement.Representation.P3 -> {
                val recip = z.invert()
                val x = this.x.multiply(recip)
                val y = this.y.multiply(recip)
                val s = y.toByteArray()
                val i = s.size - 1
                val negative = x.isNegative
                val b = (if (negative) 0x80 else 0).toByte()
                s[i] = (s[i] or b.toInt()).toByte()
                return s
            }
            else -> return toP2().toByteArray()
        }
    }

    /**
     * Converts the group element to the P2 representation.
     *
     * @return The group element in the P2 representation.
     */
    fun toP2(): GroupElement {
        return toRep(Representation.P2)
    }

    /**
     * Converts the group element to the P3 representation.
     *
     * @return The group element in the P3 representation.
     */
    fun toP3(): GroupElement {
        return toRep(Representation.P3)
    }

    /**
     * Converts the group element to the CACHED representation.
     *
     * @return The group element in the CACHED representation.
     */
    fun toCached(): GroupElement {
        return toRep(Representation.CACHED)
    }

    /**
     * Convert a GroupElement from one Representation to another.
     * TODO-CR: Add additional conversion?
     * $r = p$
     * Supported conversions:
     *
     *
     *  * P3 $\rightarrow$ P2
     *  * P3 $\rightarrow$ CACHED (1 multiply, 1 add, 1 subtract)
     *  * P1P1 $\rightarrow$ P2 (3 multiply)
     *  * P1P1 $\rightarrow$ P3 (4 multiply)
     *
     * @param repr The representation to convert to.
     * @return A new group element in the given representation.
     */
    private fun toRep(repr: Representation): GroupElement {
        when (this.representation) {
            GroupElement.Representation.P2 -> when (repr) {
                GroupElement.Representation.P2 -> return p2(curve, x, y, z)
                else -> throw IllegalArgumentException()
            }
            GroupElement.Representation.P3 -> when (repr) {
                GroupElement.Representation.P2 -> return p2(curve, x, y, z)
                GroupElement.Representation.P3 -> return p3(curve, x, y, z, t)
                GroupElement.Representation.CACHED -> return cached(curve, y.add(x), y.subtract(x), z, t.multiply(curve.d2))
                else -> throw IllegalArgumentException()
            }
            GroupElement.Representation.P1P1 -> when (repr) {
                GroupElement.Representation.P2 -> return p2(curve, x.multiply(t), y.multiply(z), z.multiply(t))
                GroupElement.Representation.P3 -> return p3(curve, x.multiply(t), y.multiply(z), z.multiply(t), x.multiply(y))
                GroupElement.Representation.P1P1 -> return p1p1(curve, x, y, z, t)
                else -> throw IllegalArgumentException()
            }
            GroupElement.Representation.PRECOMP -> when (repr) {
                GroupElement.Representation.PRECOMP -> return precomp(curve, x, y, z)
                else -> throw IllegalArgumentException()
            }
            GroupElement.Representation.CACHED -> when (repr) {
                GroupElement.Representation.CACHED -> return cached(curve, x, y, z, t)
                else -> throw IllegalArgumentException()
            }
            else -> throw UnsupportedOperationException()
        }
    }

    /**
     * Precomputes several tables.
     *
     *
     * The precomputed tables are used for [.scalarMultiply]
     * and [.doubleScalarMultiplyVariableTime].
     *
     * @param precomputeSingle should the matrix for scalarMultiply() be precomputed?
     */
    @Synchronized
    fun precompute(precomputeSingle: Boolean) {
        var Bi: GroupElement

        if (precomputeSingle && null == precmp) {
            // Precomputation for single scalar multiplication.
            precmp = Array(32) { arrayOfNulls(8) }
            // TODO-CR BR: check that this == base point when the method is called.
            Bi = this
            var i = 0
            while (32 > i) {
                var Bij = Bi
                var j = 0
                while (8 > j) {
                    val recip = Bij.z.invert()
                    val x = Bij.x.multiply(recip)
                    val y = Bij.y.multiply(recip)
                    precmp!![i][j] = precomp(curve, y.add(x), y.subtract(x), x.multiply(y).multiply(curve.d2))
                    Bij = Bij.add(Bi.toCached()).toP3()
                    j++
                }
                // Only every second summand is precomputed (16^2 = 256)
                Bi = Bi.add(Bi.toCached()).toP3()
                Bi = Bi.add(Bi.toCached()).toP3()
                Bi = Bi.add(Bi.toCached()).toP3()
                Bi = Bi.add(Bi.toCached()).toP3()
                Bi = Bi.add(Bi.toCached()).toP3()
                Bi = Bi.add(Bi.toCached()).toP3()
                Bi = Bi.add(Bi.toCached()).toP3()
                Bi = Bi.add(Bi.toCached()).toP3()
                i++
            }
        }

        // Precomputation for double scalar multiplication.
        // P,3P,5P,7P,9P,11P,13P,15P
        if (null == dblPrecmp) {
            dblPrecmp = arrayOfNulls(8)
            Bi = this
            var i = 0
            while (8 > i) {
                val recip = Bi.z.invert()
                val x = Bi.x.multiply(recip)
                val y = Bi.y.multiply(recip)
                dblPrecmp[i] = precomp(curve, y.add(x), y.subtract(x), x.multiply(y).multiply(curve.d2))
                // Bi = edwards(B,edwards(B,Bi))
                Bi = add(add(Bi.toCached()).toP3().toCached()).toP3()
                i++
            }
        }
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
    fun dbl(): GroupElement {
        when (representation) {
            GroupElement.Representation.P2, GroupElement.Representation.P3 // Ignore T for P3 representation
            -> {
                val XX: FieldElement
                val YY: FieldElement
                val B: FieldElement
                val A: FieldElement
                val AA: FieldElement
                val Yn: FieldElement
                val Zn: FieldElement
                XX = x.square()
                YY = y.square()
                B = z.squareAndDouble()
                A = x.add(y)
                AA = A.square()
                Yn = YY.add(XX)
                Zn = YY.subtract(XX)
                return p1p1(curve, AA.subtract(Yn), Yn, Zn, B.subtract(Zn))
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
    private fun madd(q: GroupElement): GroupElement {
        if (Representation.P3 != representation)
            throw UnsupportedOperationException()
        if (Representation.PRECOMP != q.representation)
            throw IllegalArgumentException()

        val YpX: FieldElement
        val YmX: FieldElement
        val A: FieldElement
        val B: FieldElement
        val C: FieldElement
        val D: FieldElement
        YpX = y.add(x)
        YmX = y.subtract(x)
        A = YpX.multiply(q.x) // q->y+x
        B = YmX.multiply(q.y) // q->y-x
        C = q.z.multiply(t) // q->2dxy
        D = z.add(z)
        return p1p1(curve, A.subtract(B), A.add(B), D.add(C), D.subtract(C))
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
    private fun msub(q: GroupElement): GroupElement {
        if (Representation.P3 != representation)
            throw UnsupportedOperationException()
        if (Representation.PRECOMP != q.representation)
            throw IllegalArgumentException()

        val YpX: FieldElement
        val YmX: FieldElement
        val A: FieldElement
        val B: FieldElement
        val C: FieldElement
        val D: FieldElement
        YpX = y.add(x)
        YmX = y.subtract(x)
        A = YpX.multiply(q.y) // q->y-x
        B = YmX.multiply(q.x) // q->y+x
        C = q.z.multiply(t) // q->2dxy
        D = z.add(z)
        return p1p1(curve, A.subtract(B), A.add(B), D.subtract(C), D.add(C))
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
    fun add(q: GroupElement): GroupElement {
        if (Representation.P3 != representation)
            throw UnsupportedOperationException()
        if (Representation.CACHED != q.representation)
            throw IllegalArgumentException()

        val YpX: FieldElement
        val YmX: FieldElement
        val A: FieldElement
        val B: FieldElement
        val C: FieldElement
        val ZZ: FieldElement
        val D: FieldElement
        YpX = y.add(x)
        YmX = y.subtract(x)
        A = YpX.multiply(q.x) // q->Y+X
        B = YmX.multiply(q.y) // q->Y-X
        C = q.t.multiply(t) // q->2dT
        ZZ = z.multiply(q.z)
        D = ZZ.add(ZZ)
        return p1p1(curve, A.subtract(B), A.add(B), D.add(C), D.subtract(C))
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
    fun sub(q: GroupElement): GroupElement {
        if (Representation.P3 != representation)
            throw UnsupportedOperationException()
        if (Representation.CACHED != q.representation)
            throw IllegalArgumentException()

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
        return p1p1(curve, A.subtract(B), A.add(B), D.subtract(C), D.add(C))
    }

    /**
     * Negates this group element by subtracting it from the neutral group element.
     *
     *
     * TODO-CR BR: why not simply negate the coordinates $X$ and $T$?
     *
     * @return The negative of this group element.
     */
    fun negate(): GroupElement {
        if (Representation.P3 != representation)
            throw UnsupportedOperationException()
        return curve.getZero(Representation.P3)!!.sub(toCached()).toP3()
    }

    override fun hashCode(): Int {
        return Arrays.hashCode(toByteArray())
    }

    override fun equals(obj: Any?): Boolean {
        if (obj === this)
            return true
        if (obj !is GroupElement)
            return false
        var ge: GroupElement = obj
        if (representation != ge.representation) {
            try {
                ge = ge.toRep(representation)
            } catch (e: RuntimeException) {
                return false
            }

        }
        when (representation) {
            GroupElement.Representation.P2, GroupElement.Representation.P3 -> {
                // Try easy way first
                if (z == ge.z)
                    return x == ge.x && y == ge.y
                // X1/Z1 = X2/Z2 --> X1*Z2 = X2*Z1
                val x1 = x.multiply(ge.z)
                val y1 = y.multiply(ge.z)
                val x2 = ge.x.multiply(z)
                val y2 = ge.y.multiply(z)
                return x1 == x2 && y1 == y2
            }
            GroupElement.Representation.P1P1 -> return toP2() == ge
            GroupElement.Representation.PRECOMP ->
                // Compare directly, PRECOMP is derived directly from x and y
                return x == ge.x && y == ge.y && z == ge.z
            GroupElement.Representation.CACHED -> {
                // Try easy way first
                if (z == ge.z)
                    return x == ge.x && y == ge.y && t == ge.t
                // (Y+X)/Z = y+x etc.
                val x3 = x.multiply(ge.z)
                val y3 = y.multiply(ge.z)
                val t3 = t.multiply(ge.z)
                val x4 = ge.x.multiply(z)
                val y4 = ge.y.multiply(z)
                val t4 = ge.t.multiply(z)
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
     * Method is package private only so that tests run.
     *
     * @param u The group element to return if $b == 1$.
     * @param b in $\{0, 1\}$
     * @return $u$ if $b == 1$; this if $b == 0$. Results undefined if $b$ is not in $\{0, 1\}$.
     */
    internal fun cmov(u: GroupElement, b: Int): GroupElement {
        return precomp(curve, x.cmov(u.x, b), y.cmov(u.y, b), z.cmov(u.z, b))
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
     * Method is package private only so that tests run.
     *
     * @param pos $= i/2$ for $i$ in $\{0, 2, 4,..., 62\}$
     * @param b $= r_i$
     * @return the GroupElement
     */
    internal fun select(pos: Int, b: Int): GroupElement {
        // Is r_i negative?
        val bnegative = Utils.negative(b)
        // |r_i|
        val babs = b - (-bnegative and b shl 1)

        // 16^i |r_i| B
        val t = curve.getZero(Representation.PRECOMP)!!
                .cmov(precmp!![pos][0], Utils.equal(babs, 1))
                .cmov(precmp!![pos][1], Utils.equal(babs, 2))
                .cmov(precmp!![pos][2], Utils.equal(babs, 3))
                .cmov(precmp!![pos][3], Utils.equal(babs, 4))
                .cmov(precmp!![pos][4], Utils.equal(babs, 5))
                .cmov(precmp!![pos][5], Utils.equal(babs, 6))
                .cmov(precmp!![pos][6], Utils.equal(babs, 7))
                .cmov(precmp!![pos][7], Utils.equal(babs, 8))
        // -16^i |r_i| B
        val tminus = precomp(curve, t.y, t.x, t.z.negate())
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
     * @param a $= a[0]+256*a[1]+\dots+256^{31} a[31]$
     * @return the GroupElement
     */
    fun scalarMultiply(a: ByteArray): GroupElement? {
        var i: Int

        val e = toRadix16(a)

        var h = curve.getZero(Representation.P3)
        synchronized(this) {
            // TODO: Get opinion from a crypto professional.
            // This should in practice never be necessary, the only point that
            // this should get called on is EdDSA's B.
            //precompute();
            i = 1
            while (64 > i) {
                h = h!!.madd(select(i / 2, e[i].toInt())).toP3()
                i = i + 2
            }

            h = h!!.dbl().toP2().dbl().toP2().dbl().toP2().dbl().toP3()

            i = 0
            while (64 > i) {
                h = h!!.madd(select(i / 2, e[i].toInt())).toP3()
                i = i + 2
            }
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
    fun doubleScalarMultiplyVariableTime(A: GroupElement, a: ByteArray, b: ByteArray): GroupElement? {
        // TODO-CR BR: A check that this is the base point is needed.
        val aslide = slide(a)
        val bslide = slide(b)

        var r = curve.getZero(Representation.P2)

        var i: Int
        i = 255
        while (0 <= i) {
            if (0 != aslide[i].toInt() || 0 != bslide[i].toInt()) break
            --i
        }

        synchronized(this) {
            // TODO-CR BR strange comment below.
            // TODO: Get opinion from a crypto professional.
            // This should in practice never be necessary, the only point that
            // this should get called on is EdDSA's B.
            //precompute();
            while (0 <= i) {
                var t = r!!.dbl()

                if (0 < aslide[i]) {
                    t = t.toP3().madd(A.dblPrecmp!![aslide[i] / 2])
                } else if (0 > aslide[i]) {
                    t = t.toP3().msub(A.dblPrecmp!![-aslide[i] / 2])
                }

                if (0 < bslide[i]) {
                    t = t.toP3().madd(dblPrecmp!![bslide[i] / 2])
                } else if (0 > bslide[i]) {
                    t = t.toP3().msub(dblPrecmp!![-bslide[i] / 2])
                }

                r = t.toP2()
                --i
            }
        }

        return r
    }

    /**
     * Verify that a point is on the curve.
     * @param curve The curve to check.
     * @return true if the point lies on the curve.
     */
    fun isOnCurve(curve: Curve): Boolean {
        when (representation) {
            GroupElement.Representation.P2, GroupElement.Representation.P3 -> {
                val recip = z.invert()
                val x = this.x.multiply(recip)
                val y = this.y.multiply(recip)
                val xx = x.square()
                val yy = y.square()
                val dxxyy = curve.d.multiply(xx).multiply(yy)
                return curve.field.ONE.add(dxxyy).add(xx) == yy
            }

            else -> return toP2().isOnCurve(curve)
        }
    }

    override fun toString(): String {
        return "[GroupElement\nX=$x\nY=$y\nZ=$z\nT=$t\n]"
    }

    /**
     * Available representations for a group element.
     *
     *  * P2: Projective representation $(X:Y:Z)$ satisfying $x=X/Z, y=Y/Z$.
     *  * P3: Extended projective representation $(X:Y:Z:T)$ satisfying $x=X/Z, y=Y/Z, XY=ZT$.
     *  * P1P1: Completed representation $((X:Z), (Y:T))$ satisfying $x=X/Z, y=Y/T$.
     *  * PRECOMP: Precomputed representation $(y+x, y-x, 2dxy)$.
     *  * CACHED: Cached representation $(Y+X, Y-X, Z, 2dT)$
     *
     */
    enum class Representation {
        /** Projective ($P^2$): $(X:Y:Z)$ satisfying $x=X/Z, y=Y/Z$  */
        P2,
        /** Extended ($P^3$): $(X:Y:Z:T)$ satisfying $x=X/Z, y=Y/Z, XY=ZT$  */
        P3,
        /** Completed ($P \times P$): $((X:Z),(Y:T))$ satisfying $x=X/Z, y=Y/T$  */
        P1P1,
        /** Precomputed (Duif): $(y+x,y-x,2dxy)$  */
        PRECOMP,
        /** Cached: $(Y+X,Y-X,Z,2dT)$  */
        CACHED
    }

    companion object {
        private val serialVersionUID = 2395879087349587L

        /**
         * Creates a new group element in P2 representation.
         *
         * @param curve The curve.
         * @param X The $X$ coordinate.
         * @param Y The $Y$ coordinate.
         * @param Z The $Z$ coordinate.
         * @return The group element in P2 representation.
         */
        fun p2(
                curve: Curve,
                X: FieldElement,
                Y: FieldElement,
                Z: FieldElement): GroupElement {
            return GroupElement(curve, Representation.P2, X, Y, Z, null)
        }

        /**
         * Creates a new group element in P3 representation.
         *
         * @param curve The curve.
         * @param X The $X$ coordinate.
         * @param Y The $Y$ coordinate.
         * @param Z The $Z$ coordinate.
         * @param T The $T$ coordinate.
         * @return The group element in P3 representation.
         */
        fun p3(
                curve: Curve,
                X: FieldElement,
                Y: FieldElement,
                Z: FieldElement,
                T: FieldElement): GroupElement {
            return GroupElement(curve, Representation.P3, X, Y, Z, T)
        }

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
        fun p1p1(
                curve: Curve,
                X: FieldElement,
                Y: FieldElement,
                Z: FieldElement,
                T: FieldElement): GroupElement {
            return GroupElement(curve, Representation.P1P1, X, Y, Z, T)
        }

        /**
         * Creates a new group element in PRECOMP representation.
         *
         * @param curve The curve.
         * @param ypx The $y + x$ value.
         * @param ymx The $y - x$ value.
         * @param xy2d The $2 * d * x * y$ value.
         * @return The group element in PRECOMP representation.
         */
        fun precomp(
                curve: Curve,
                ypx: FieldElement,
                ymx: FieldElement,
                xy2d: FieldElement): GroupElement {
            return GroupElement(curve, Representation.PRECOMP, ypx, ymx, xy2d, null)
        }

        /**
         * Creates a new group element in CACHED representation.
         *
         * @param curve The curve.
         * @param YpX The $Y + X$ value.
         * @param YmX The $Y - X$ value.
         * @param Z The $Z$ coordinate.
         * @param T2d The $2 * d * T$ value.
         * @return The group element in CACHED representation.
         */
        fun cached(
                curve: Curve,
                YpX: FieldElement,
                YmX: FieldElement,
                Z: FieldElement,
                T2d: FieldElement): GroupElement {
            return GroupElement(curve, Representation.CACHED, YpX, YmX, Z, T2d)
        }

        /**
         * Convert a to radix 16.
         *
         *
         * Method is package private only so that tests run.
         *
         * @param a $= a[0]+256*a[1]+...+256^{31} a[31]$
         * @return 64 bytes, each between -8 and 7
         */
        internal fun toRadix16(a: ByteArray): ByteArray {
            val e = ByteArray(64)
            var i: Int
            // Radix 16 notation
            i = 0
            while (32 > i) {
                val i1 = 2 * i
                e[i1] = (a[i] and 15).toByte()
                e[i1 + 1] = (a[i] shr 4 and 15).toByte()
                i++
            }
            /* each e[i] is between 0 and 15 */
            /* e[63] is between 0 and 7 */
            var carry = 0
            i = 0
            while (63 > i) {
                e[i] = (e[i] + carry).toByte()
                carry = e[i] + 8
                carry = carry shr 4
                e[i] = (e[i] - (carry shl 4)).toByte()
                i++
            }
            e[63] = (e[63] + carry).toByte()
            /* each e[i] is between -8 and 7 */
            return e
        }

        /**
         * Calculates a sliding-windows base 2 representation for a given value $a$.
         * To learn more about it see [6] page 8.
         *
         *
         * Output: $r$ which satisfies
         * $a = r0 * 2^0 + r1 * 2^1 + \dots + r255 * 2^{255}$ with $ri$ in $\{-15, -13, -11, -9, -7, -5, -3, -1, 0, 1, 3, 5, 7, 9, 11, 13, 15\}$
         *
         *
         * Method is package private only so that tests run.
         *
         * @param a $= a[0]+256*a[1]+\dots+256^{31} a[31]$.
         * @return The byte array $r$ in the above described form.
         */
        private fun slide(a: ByteArray): ByteArray {
            val r = ByteArray(256)

            // Put each bit of 'a' into a separate byte, 0 or 1
            run {
                var i = 0
                while (256 > i) {
                    r[i] = (1 and (a[i shr 3] shr (i and 7))).toByte()
                    ++i
                }
            }

            // Note: r[i] will always be odd.
            var i = 0
            while (256 > i) {
                if (0 != r[i].toInt()) {
                    // Accumulate bits if possible
                    var b = 1
                    while (6 >= b && 256 > i + b) {
                        if (0 != r[i + b].toInt()) {
                            if (15 >= r[i] + (r[i + b] shl b)) {
                                r[i] = (r[i] + (r[i + b] shl b)).toByte()
                                r[i + b] = 0.toByte()
                            } else if (-15 <= r[i] - (r[i + b] shl b)) {
                                r[i] = (r[i] - (r[i + b] shl b)).toByte()
                                var k = i + b
                                while (256 > k) {
                                    if (0 == r[k].toInt()) {
                                        r[k] = 1.toByte()
                                        break
                                    }
                                    r[k] = 0.toByte()
                                    ++k
                                }
                            } else
                                break
                        }
                        ++b
                    }
                }
                ++i
            }

            return r
        }
    }
}
