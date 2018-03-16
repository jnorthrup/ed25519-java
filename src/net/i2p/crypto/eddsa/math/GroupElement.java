/**
 * EdDSA-Java by str4d
 *
 * To the extent possible under law, the person who associated CC0 with
 * EdDSA-Java has waived all copyright and related or neighboring rights
 * to EdDSA-Java.
 *
 * You should have received a copy of the CC0 legalcode along with this
 * work. If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
 *
 */
package net.i2p.crypto.eddsa.math;

import net.i2p.crypto.eddsa.Utils;

import java.io.Serializable;
import java.util.Arrays;

/**
 * A point $(x,y)$ on an EdDSA curve.
 * <p>
 * Reviewed/commented by Bloody Rookie (nemproject@gmx.de)
 * <p>
 * Literature:<br>
 * [1] Daniel J. Bernstein, Niels Duif, Tanja Lange, Peter Schwabe and Bo-Yin Yang : High-speed high-security signatures<br>
 * [2] Huseyin Hisil, Kenneth Koon-Ho Wong, Gary Carter, Ed Dawson: Twisted Edwards Curves Revisited<br>
 * [3] Daniel J. Bernsteina, Tanja Lange: A complete set of addition laws for incomplete Edwards curves<br>
 * [4] Daniel J. Bernstein, Peter Birkner, Marc Joye, Tanja Lange and Christiane Peters: Twisted Edwards Curves<br>
 * [5] Christiane Pascale Peters: Curves, Codes, and Cryptography (PhD thesis)<br>
 * [6] Daniel J. Bernstein, Peter Birkner, Tanja Lange and Christiane Peters: Optimizing double-base elliptic-curve single-scalar multiplication<br>
 *
 * @author str4d
 */
public class GroupElement   {
    private static final long serialVersionUID = 2395879087349587L;

    /**
     * Available representations for a group element.
     * <ul>
     * <li>P2: Projective representation $(X:Y:Z)$ satisfying $x=X/Z, y=Y/Z$.
     * <li>P3: Extended projective representation $(X:Y:Z:T)$ satisfying $x=X/Z, y=Y/Z, XY=ZT$.
     * <li>P1P1: Completed representation $((X:Z), (Y:T))$ satisfying $x=X/Z, y=Y/T$.
     * <li>PRECOMP: Precomputed representation $(y+x, y-x, 2dxy)$.
     * <li>CACHED: Cached representation $(Y+X, Y-X, Z, 2dT)$
     * </ul>
     */
    public enum Representation {
        /** Projective ($P^2$): $(X:Y:Z)$ satisfying $x=X/Z, y=Y/Z$ */
        P2,
        /** Extended ($P^3$): $(X:Y:Z:T)$ satisfying $x=X/Z, y=Y/Z, XY=ZT$ */
        P3,
        /** Completed ($P \times P$): $((X:Z),(Y:T))$ satisfying $x=X/Z, y=Y/T$ */
        P1P1,
        /** Precomputed (Duif): $(y+x,y-x,2dxy)$ */
        PRECOMP,
        /** Cached: $(Y+X,Y-X,Z,2dT)$ */
        CACHED
    }

    /**
     * Creates a new group element in P2 representation.
     *
     * @param curve The curve.
     * @param X The $X$ coordinate.
     * @param Y The $Y$ coordinate.
     * @param Z The $Z$ coordinate.
     * @return The group element in P2 representation.
     */
    public static GroupElement p2(
            Curve curve,
            FieldElement X,
            FieldElement Y,
            FieldElement Z) {
        return new GroupElement(curve, Representation.P2, X, Y, Z, null);
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
    public static GroupElement p3(
            Curve curve,
            FieldElement X,
            FieldElement Y,
            FieldElement Z,
            FieldElement T) {
        return new GroupElement(curve, Representation.P3, X, Y, Z, T);
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
    public static GroupElement p1p1(
            Curve curve,
            FieldElement X,
            FieldElement Y,
            FieldElement Z,
            FieldElement T) {
        return new GroupElement(curve, Representation.P1P1, X, Y, Z, T);
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
    public static GroupElement precomp(
            Curve curve,
            FieldElement ypx,
            FieldElement ymx,
            FieldElement xy2d) {
        return new GroupElement(curve, Representation.PRECOMP, ypx, ymx, xy2d, null);
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
    public static GroupElement cached(
            Curve curve,
            FieldElement YpX,
            FieldElement YmX,
            FieldElement Z,
            FieldElement T2d) {
        return new GroupElement(curve, Representation.CACHED, YpX, YmX, Z, T2d);
    }

    /**
     * Variable is package private only so that tests run.
     */
    final Curve curve;

    /**
     * Variable is package private only so that tests run.
     */
    final Representation repr;

    /**
     * Variable is package private only so that tests run.
     */
    final FieldElement X;

    /**
     * Variable is package private only so that tests run.
     */
    final FieldElement Y;

    /**
     * Variable is package private only so that tests run.
     */
    final FieldElement Z;

    /**
     * Variable is package private only so that tests run.
     */
    final FieldElement T;

    /**
     * Precomputed table for {@link #scalarMultiply(byte[])},
     * filled if necessary.
     * <p>
     * Variable is package private only so that tests run.
     */
    GroupElement[][] precmp;

    /**
     * Precomputed table for {@link #doubleScalarMultiplyVariableTime(GroupElement, byte[], byte[])},
     * filled if necessary.
     * <p>
     * Variable is package private only so that tests run.
     */
    GroupElement[] dblPrecmp;

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
    public GroupElement(
            Curve curve,
            Representation repr,
            FieldElement X,
            FieldElement Y,
            FieldElement Z,
            FieldElement T) {
        this.curve = curve;
        this.repr = repr;
        this.X = X;
        this.Y = Y;
        this.Z = Z;
        this.T = T;
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
     * @param s The encoded point.
     */
    public GroupElement(Curve curve, byte[] s) {
        FieldElement x;
        FieldElement y;
        FieldElement yy;
        FieldElement u;
        FieldElement v;
        FieldElement v3;
        FieldElement vxx;
        FieldElement check;
        y = curve.getField().fromByteArray(s);
        yy = y.square();

        // u = y^2-1
        u = yy.subtractOne();

        // v = dy^2+1
        v = yy.multiply(curve.getD()).addOne();

        // v3 = v^3
        v3 = v.square().multiply(v);

        // x = (v3^2)vu, aka x = uv^7
        x = v3.square().multiply(v).multiply(u);

        //  x = (uv^7)^((q-5)/8)
        x = x.pow22523();

        // x = uv^3(uv^7)^((q-5)/8)
        x = v3.multiply(u).multiply(x);

        vxx = x.square().multiply(v);
        check = vxx.subtract(u);            // vx^2-u
        if (check.isNonZero()) {
            check = vxx.add(u);             // vx^2+u

            if (check.isNonZero())
                throw new IllegalArgumentException("not a valid GroupElement");
            x = x.multiply(curve.getI());
        }

        if ((x.isNegative() ? 1 : 0) != Utils.bit(s, curve.getField().getb()-1)) {
            x = x.negate();
        }

        this.curve = curve;
        repr = Representation.P3;
        X = x;
        Y = y;
        Z = curve.getField().ONE;
        T = X.multiply(Y);
    }

    /**
     * Gets the curve of the group element.
     *
     * @return The curve.
     */
    public Curve getCurve() {
        return curve;
    }

    /**
     * Gets the representation of the group element.
     *
     * @return The representation.
     */
    public Representation getRepresentation() {
        return repr;
    }

    /**
     * Gets the $X$ value of the group element.
     * This is for most representation the projective $X$ coordinate.
     *
     * @return The $X$ value.
     */
    public FieldElement getX() {
        return X;
    }

    /**
     * Gets the $Y$ value of the group element.
     * This is for most representation the projective $Y$ coordinate.
     *
     * @return The $Y$ value.
     */
    public FieldElement getY() {
        return Y;
    }

    /**
     * Gets the $Z$ value of the group element.
     * This is for most representation the projective $Z$ coordinate.
     *
     * @return The $Z$ value.
     */
    public FieldElement getZ() {
        return Z;
    }

    /**
     * Gets the $T$ value of the group element.
     * This is for most representation the projective $T$ coordinate.
     *
     * @return The $T$ value.
     */
    public FieldElement getT() {
        return T;
    }

    /**
     * Converts the group element to an encoded point on the curve.
     *
     * @return The encoded point as byte array.
     */
    public byte[] toByteArray() {
        switch (repr) {
            case P2:
            case P3:
                FieldElement recip = Z.invert();
                FieldElement x = X.multiply(recip);
                FieldElement y = Y.multiply(recip);
                byte[] s = y.toByteArray();
                int i = s.length - 1;
                boolean negative = x.isNegative();
                byte b = negative ? (byte) 0x80  : (byte) 0 ;
                s[i] = (byte) (s[i] | (int) b);
                return s;
            default:
                return toP2().toByteArray();
        }
    }

    /**
     * Converts the group element to the P2 representation.
     *
     * @return The group element in the P2 representation.
     */
    public GroupElement toP2() {
        return toRep(Representation.P2);
    }

    /**
     * Converts the group element to the P3 representation.
     *
     * @return The group element in the P3 representation.
     */
    public GroupElement toP3() {
        return toRep(Representation.P3);
    }

    /**
     * Converts the group element to the CACHED representation.
     *
     * @return The group element in the CACHED representation.
     */
    public GroupElement toCached() {
        return toRep(Representation.CACHED);
    }

    /**
     * Convert a GroupElement from one Representation to another.
     * TODO-CR: Add additional conversion?
     * $r = p$
     * <p>
     * Supported conversions:
     * <p><ul>
     * <li>P3 $\rightarrow$ P2
     * <li>P3 $\rightarrow$ CACHED (1 multiply, 1 add, 1 subtract)
     * <li>P1P1 $\rightarrow$ P2 (3 multiply)
     * <li>P1P1 $\rightarrow$ P3 (4 multiply)
     *
     * @param repr The representation to convert to.
     * @return A new group element in the given representation.
     */
    private GroupElement toRep(Representation repr) {
        switch (this.repr) {
            case P2:
                switch (repr) {
                    case P2:
                        return p2(curve, X, Y, Z);
                    default:
                        throw new IllegalArgumentException();
                }
            case P3:
                switch (repr) {
                    case P2:
                        return p2(curve, X, Y, Z);
                    case P3:
                        return p3(curve, X, Y, Z, T);
                    case CACHED:
                        return cached(curve, Y.add(X), Y.subtract(X), Z, T.multiply(curve.getD2()));
                    default:
                        throw new IllegalArgumentException();
                }
            case P1P1:
                switch (repr) {
                    case P2:
                        return p2(curve, X.multiply(T), Y.multiply(Z), Z.multiply(T));
                    case P3:
                        return p3(curve, X.multiply(T), Y.multiply(Z), Z.multiply(T), X.multiply(Y));
                    case P1P1:
                        return p1p1(curve, X, Y, Z, T);
                    default:
                        throw new IllegalArgumentException();
                }
            case PRECOMP:
                switch (repr) {
                    case PRECOMP:
                        return precomp(curve, X, Y, Z);
                    default:
                        throw new IllegalArgumentException();
                }
            case CACHED:
                switch (repr) {
                    case CACHED:
                        return cached(curve, X, Y, Z, T);
                    default:
                        throw new IllegalArgumentException();
                }
            default:
                throw new UnsupportedOperationException();
        }
    }

    /**
     * Precomputes several tables.
     * <p>
     * The precomputed tables are used for {@link #scalarMultiply(byte[])}
     * and {@link #doubleScalarMultiplyVariableTime(GroupElement, byte[], byte[])}.
     *
     * @param precomputeSingle should the matrix for scalarMultiply() be precomputed?
     */
    public synchronized void precompute(boolean precomputeSingle) {
        GroupElement Bi;

        if (precomputeSingle && precmp == null) {
            // Precomputation for single scalar multiplication.
            precmp = new GroupElement[32][8];
            // TODO-CR BR: check that this == base point when the method is called.
            Bi = this;
            for (int i = 0; i < 32; i++) {
                GroupElement Bij = Bi;
                for (int j = 0; j < 8; j++) {
                    FieldElement recip = Bij.Z.invert();
                    FieldElement x = Bij.X.multiply(recip);
                    FieldElement y = Bij.Y.multiply(recip);
                    precmp[i][j] = precomp(curve, y.add(x), y.subtract(x), x.multiply(y).multiply(curve.getD2()));
                    Bij = Bij.add(Bi.toCached()).toP3();
                }
                // Only every second summand is precomputed (16^2 = 256)
                Bi = Bi.add(Bi.toCached()).toP3();
                Bi = Bi.add(Bi.toCached()).toP3();
                Bi = Bi.add(Bi.toCached()).toP3();
                Bi = Bi.add(Bi.toCached()).toP3();
                Bi = Bi.add(Bi.toCached()).toP3();
                Bi = Bi.add(Bi.toCached()).toP3();
                Bi = Bi.add(Bi.toCached()).toP3();
                Bi = Bi.add(Bi.toCached()).toP3();
            }
        }

        // Precomputation for double scalar multiplication.
        // P,3P,5P,7P,9P,11P,13P,15P
        if (dblPrecmp == null) {
            dblPrecmp = new GroupElement[8];
            Bi = this;
            for (int i = 0; i < 8; i++) {
                FieldElement recip = Bi.Z.invert();
                FieldElement x = Bi.X.multiply(recip);
                FieldElement y = Bi.Y.multiply(recip);
                dblPrecmp[i] = precomp(curve, y.add(x), y.subtract(x), x.multiply(y).multiply(curve.getD2()));
                // Bi = edwards(B,edwards(B,Bi))
                Bi = add(add(Bi.toCached()).toP3().toCached()).toP3();
            }
        }
    }

    /**
     * Doubles a given group element $p$ in $P^2$ or $P^3$ representation and returns the result in $P \times P$ representation.
     * $r = 2 * p$ where $p = (X : Y : Z)$ or $p = (X : Y : Z : T)$
     * <p>
     * $r$ in $P \times P$ representation:
     * <p>
     * $r = ((X' : Z'), (Y' : T'))$ where
     * </p><ul>
     * <li>$X' = (X + Y)^2 - (Y^2 + X^2)$
     * <li>$Y' = Y^2 + X^2$
     * <li>$Z' = y^2 - X^2$
     * <li>$T' = 2 * Z^2 - (y^2 - X^2)$
     * </ul><p>
     * $r$ converted from $P \times P$ to $P^2$ representation:
     * <p>
     * $r = (X'' : Y'' : Z'')$ where
     * </p><ul>
     * <li>$X'' = X' * Z' = ((X + Y)^2 - Y^2 - X^2) * (2 * Z^2 - (y^2 - X^2))$
     * <li>$Y'' = Y' * T' = (Y^2 + X^2) * (2 * Z^2 - (y^2 - X^2))$
     * <li>$Z'' = Z' * T' = (y^2 - X^2) * (2 * Z^2 - (y^2 - X^2))$
     * </ul><p>
     * Formula for the $P^2$ representation is in agreement with the formula given in [4] page 12 (with $a = -1$)
     * up to a common factor -1 which does not matter:
     * <p>
     * $$
     * B = (X + Y)^2; C = X^2; D = Y^2; E = -C = -X^2; F := E + D = Y^2 - X^2; H = Z^2; J = F − 2 * H; \\
     * X3 = (B − C − D) · J = X' * (-T'); \\
     * Y3 = F · (E − D) = Z' * (-Y'); \\
     * Z3 = F · J = Z' * (-T').
     * $$
     *
     * @return The P1P1 representation
     */
    public GroupElement dbl() {
        switch (repr) {
        case P2:
        case P3: // Ignore T for P3 representation
            FieldElement XX;
            FieldElement YY;
            FieldElement B;
            FieldElement A;
            FieldElement AA;
            FieldElement Yn;
            FieldElement Zn;
            XX = X.square();
            YY = Y.square();
            B = Z.squareAndDouble();
            A = X.add(Y);
            AA = A.square();
            Yn = YY.add(XX);
            Zn = YY.subtract(XX);
            return p1p1(curve, AA.subtract(Yn), Yn, Zn, B.subtract(Zn));
        default:
            throw new UnsupportedOperationException();
        }
    }

    /**
     * GroupElement addition using the twisted Edwards addition law with
     * extended coordinates (Hisil2008).
     * <p>
     * this must be in $P^3$ representation and $q$ in PRECOMP representation.
     * $r = p + q$ where $p = this = (X1 : Y1 : Z1 : T1), q = (q.X, q.Y, q.Z) = (Y2/Z2 + X2/Z2, Y2/Z2 - X2/Z2, 2 * d * X2/Z2 * Y2/Z2)$
     * <p>
     * $r$ in $P \times P$ representation:
     * <p>
     * $r = ((X' : Z'), (Y' : T'))$ where
     * <p><ul>
     * <li>$X' = (Y1 + X1) * q.X - (Y1 - X1) * q.Y = ((Y1 + X1) * (Y2 + X2) - (Y1 - X1) * (Y2 - X2)) * 1/Z2$
     * <li>$Y' = (Y1 + X1) * q.X + (Y1 - X1) * q.Y = ((Y1 + X1) * (Y2 + X2) + (Y1 - X1) * (Y2 - X2)) * 1/Z2$
     * <li>$Z' = 2 * Z1 + T1 * q.Z = 2 * Z1 + T1 * 2 * d * X2 * Y2 * 1/Z2^2 = (2 * Z1 * Z2 + 2 * d * T1 * T2) * 1/Z2$
     * <li>$T' = 2 * Z1 - T1 * q.Z = 2 * Z1 - T1 * 2 * d * X2 * Y2 * 1/Z2^2 = (2 * Z1 * Z2 - 2 * d * T1 * T2) * 1/Z2$
     * </ul><p>
     * Setting $A = (Y1 - X1) * (Y2 - X2), B = (Y1 + X1) * (Y2 + X2), C = 2 * d * T1 * T2, D = 2 * Z1 * Z2$ we get
     * <p><ul>
     * <li>$X' = (B - A) * 1/Z2$
     * <li>$Y' = (B + A) * 1/Z2$
     * <li>$Z' = (D + C) * 1/Z2$
     * <li>$T' = (D - C) * 1/Z2$
     * </ul><p>
     * $r$ converted from $P \times P$ to $P^2$ representation:
     * <p>
     * $r = (X'' : Y'' : Z'' : T'')$ where
     * <p><ul>
     * <li>$X'' = X' * Z' = (B - A) * (D + C) * 1/Z2^2$
     * <li>$Y'' = Y' * T' = (B + A) * (D - C) * 1/Z2^2$
     * <li>$Z'' = Z' * T' = (D + C) * (D - C) * 1/Z2^2$
     * <li>$T'' = X' * Y' = (B - A) * (B + A) * 1/Z2^2$
     * </ul><p>
     * TODO-CR BR: Formula for the $P^2$ representation is not in agreement with the formula given in [2] page 6<br>
     * TODO-CR BR: (the common factor $1/Z2^2$ does not matter):<br>
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
    private GroupElement madd(GroupElement q) {
        if (repr != Representation.P3)
            throw new UnsupportedOperationException();
        if (q.repr != Representation.PRECOMP)
            throw new IllegalArgumentException();

        FieldElement YpX;
        FieldElement YmX;
        FieldElement A;
        FieldElement B;
        FieldElement C;
        FieldElement D;
        YpX = Y.add(X);
        YmX = Y.subtract(X);
        A = YpX.multiply(q.X); // q->y+x
        B = YmX.multiply(q.Y); // q->y-x
        C = q.Z.multiply(T); // q->2dxy
        D = Z.add(Z);
        return p1p1(curve, A.subtract(B), A.add(B), D.add(C), D.subtract(C));
    }

    /**
     * GroupElement subtraction using the twisted Edwards addition law with
     * extended coordinates (Hisil2008).
     * <p>
     * this must be in $P^3$ representation and $q$ in PRECOMP representation.
     * $r = p - q$ where $p = this = (X1 : Y1 : Z1 : T1), q = (q.X, q.Y, q.Z) = (Y2/Z2 + X2/Z2, Y2/Z2 - X2/Z2, 2 * d * X2/Z2 * Y2/Z2)$
     * <p>
     * Negating $q$ means negating the value of $X2$ and $T2$ (the latter is irrelevant here).
     * The formula is in accordance to {@link #madd the above addition}.
     *
     * @param q the PRECOMP representation of the GroupElement to subtract.
     * @return the P1P1 representation of the result.
     */
    private GroupElement msub(GroupElement q) {
        if (repr != Representation.P3)
            throw new UnsupportedOperationException();
        if (q.repr != Representation.PRECOMP)
            throw new IllegalArgumentException();

        FieldElement YpX;
        FieldElement YmX;
        FieldElement A;
        FieldElement B;
        FieldElement C;
        FieldElement D;
        YpX = Y.add(X);
        YmX = Y.subtract(X);
        A = YpX.multiply(q.Y); // q->y-x
        B = YmX.multiply(q.X); // q->y+x
        C = q.Z.multiply(T); // q->2dxy
        D = Z.add(Z);
        return p1p1(curve, A.subtract(B), A.add(B), D.subtract(C), D.add(C));
    }

    /**
     * GroupElement addition using the twisted Edwards addition law with
     * extended coordinates (Hisil2008).
     * <p>
     * this must be in $P^3$ representation and $q$ in CACHED representation.
     * $r = p + q$ where $p = this = (X1 : Y1 : Z1 : T1), q = (q.X, q.Y, q.Z, q.T) = (Y2 + X2, Y2 - X2, Z2, 2 * d * T2)$
     * <p>
     * $r$ in $P \times P$ representation:
     * </p><ul>
     * <li>$X' = (Y1 + X1) * (Y2 + X2) - (Y1 - X1) * (Y2 - X2)$
     * <li>$Y' = (Y1 + X1) * (Y2 + X2) + (Y1 - X1) * (Y2 - X2)$
     * <li>$Z' = 2 * Z1 * Z2 + 2 * d * T1 * T2$
     * <li>$T' = 2 * Z1 * T2 - 2 * d * T1 * T2$
     * </ul><p>
     * Setting $A = (Y1 - X1) * (Y2 - X2), B = (Y1 + X1) * (Y2 + X2), C = 2 * d * T1 * T2, D = 2 * Z1 * Z2$ we get
     * </p><ul>
     * <li>$X' = (B - A)$
     * <li>$Y' = (B + A)$
     * <li>$Z' = (D + C)$
     * <li>$T' = (D - C)$
     * </ul><p>
     * Same result as in {@link #madd} (up to a common factor which does not matter).
     *
     * @param q the CACHED representation of the GroupElement to add.
     * @return the P1P1 representation of the result.
     */
    public GroupElement add(GroupElement q) {
        if (repr != Representation.P3)
            throw new UnsupportedOperationException();
        if (q.repr != Representation.CACHED)
            throw new IllegalArgumentException();

        FieldElement YpX;
        FieldElement YmX;
        FieldElement A;
        FieldElement B;
        FieldElement C;
        FieldElement ZZ;
        FieldElement D;
        YpX = Y.add(X);
        YmX = Y.subtract(X);
        A = YpX.multiply(q.X); // q->Y+X
        B = YmX.multiply(q.Y); // q->Y-X
        C = q.T.multiply(T); // q->2dT
        ZZ = Z.multiply(q.Z);
        D = ZZ.add(ZZ);
        return p1p1(curve, A.subtract(B), A.add(B), D.add(C), D.subtract(C));
    }

    /**
     * GroupElement subtraction using the twisted Edwards addition law with
     * extended coordinates (Hisil2008).
     * <p>
     * $r = p - q$
     * <p>
     * Negating $q$ means negating the value of the coordinate $X2$ and $T2$.
     * The formula is in accordance to {@link #add the above addition}.
     *
     * @param q the PRECOMP representation of the GroupElement to subtract.
     * @return the P1P1 representation of the result.
     */
    public GroupElement sub(GroupElement q) {
        if (repr != Representation.P3)
            throw new UnsupportedOperationException();
        if (q.repr != Representation.CACHED)
            throw new IllegalArgumentException();

        FieldElement YpX;
        FieldElement YmX;
        FieldElement A;
        FieldElement B;
        FieldElement C;
        FieldElement ZZ;
        FieldElement D;
        YpX = Y.add(X);
        YmX = Y.subtract(X);
        A = YpX.multiply(q.Y); // q->Y-X
        B = YmX.multiply(q.X); // q->Y+X
        C = q.T.multiply(T); // q->2dT
        ZZ = Z.multiply(q.Z);
        D = ZZ.add(ZZ);
        return p1p1(curve, A.subtract(B), A.add(B), D.subtract(C), D.add(C));
    }

    /**
     * Negates this group element by subtracting it from the neutral group element.
     * <p>
     * TODO-CR BR: why not simply negate the coordinates $X$ and $T$?
     *
     * @return The negative of this group element.
     */
    public GroupElement negate() {
        if (repr != Representation.P3)
            throw new UnsupportedOperationException();
        return curve.getZero(Representation.P3).sub(toCached()).toP3();
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(toByteArray());
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this)
            return true;
        if (!(obj instanceof GroupElement))
            return false;
        GroupElement ge = (GroupElement) obj;
        if (!repr.equals(ge.repr)) {
            try {
                ge = ge.toRep(repr);
            } catch (RuntimeException e) {
                return false;
            }
        }
        switch (repr) {
            case P2:
            case P3:
                // Try easy way first
                if (Z.equals(ge.Z))
                    return X.equals(ge.X) && Y.equals(ge.Y);
                // X1/Z1 = X2/Z2 --> X1*Z2 = X2*Z1
                FieldElement x1 = X.multiply(ge.Z);
                FieldElement y1 = Y.multiply(ge.Z);
                FieldElement x2 = ge.X.multiply(Z);
                FieldElement y2 = ge.Y.multiply(Z);
                return x1.equals(x2) && y1.equals(y2);
            case P1P1:
                return toP2().equals(ge);
            case PRECOMP:
                // Compare directly, PRECOMP is derived directly from x and y
                return X.equals(ge.X) && Y.equals(ge.Y) && Z.equals(ge.Z);
            case CACHED:
                // Try easy way first
                if (Z.equals(ge.Z))
                    return X.equals(ge.X) && Y.equals(ge.Y) && T.equals(ge.T);
                // (Y+X)/Z = y+x etc.
                FieldElement x3 = X.multiply(ge.Z);
                FieldElement y3 = Y.multiply(ge.Z);
                FieldElement t3 = T.multiply(ge.Z);
                FieldElement x4 = ge.X.multiply(Z);
                FieldElement y4 = ge.Y.multiply(Z);
                FieldElement t4 = ge.T.multiply(Z);
                return x3.equals(x4) && y3.equals(y4) && t3.equals(t4);
            default:
                return false;
        }
    }

    /**
     * Convert a to radix 16.
     * <p>
     * Method is package private only so that tests run.
     *
     * @param a $= a[0]+256*a[1]+...+256^{31} a[31]$
     * @return 64 bytes, each between -8 and 7
     */
    static byte[] toRadix16(byte[] a) {
        byte[] e = new byte[64];
        int i;
        // Radix 16 notation
        for (i = 0; i < 32; i++) {
            int i1 = 2 * i;
            e[i1] = (byte) (a[i] & 15);
            e[i1 +1] = (byte) ((a[i] >> 4) & 15);
        }
        /* each e[i] is between 0 and 15 */
        /* e[63] is between 0 and 7 */
        int carry = 0;
        for (i = 0; i < 63; i++) {
            e[i] = (byte) (e[i] + carry);
            carry = e[i] + 8;
            carry = carry >> 4;
            e[i] = (byte) (e[i] - (carry << 4));
        }
        e[63] = (byte) (e[63] + carry);
        /* each e[i] is between -8 and 7 */
        return e;
    }

    /**
     * Constant-time conditional move.
     * <p>
     * Replaces this with $u$ if $b == 1$.<br>
     * Replaces this with this if $b == 0$.
     * <p>
     * Method is package private only so that tests run.
     *
     * @param u The group element to return if $b == 1$.
     * @param b in $\{0, 1\}$
     * @return $u$ if $b == 1$; this if $b == 0$. Results undefined if $b$ is not in $\{0, 1\}$.
     */
    GroupElement cmov(GroupElement u, int b) {
        return precomp(curve, X.cmov(u.X, b), Y.cmov(u.Y, b), Z.cmov(u.Z, b));
    }

    /**
     * Look up $16^i r_i B$ in the precomputed table.
     * <p>
     * No secret array indices, no secret branching.
     * Constant time.
     * <p>
     * Must have previously precomputed.
     * <p>
     * Method is package private only so that tests run.
     *
     * @param pos $= i/2$ for $i$ in $\{0, 2, 4,..., 62\}$
     * @param b $= r_i$
     * @return the GroupElement
     */
    GroupElement select(int pos, int b) {
        // Is r_i negative?
        int bnegative = Utils.negative(b);
        // |r_i|
        int babs = b - (((-bnegative) & b) << 1);

        // 16^i |r_i| B
        GroupElement t = curve.getZero(Representation.PRECOMP)
                .cmov(precmp[pos][0], Utils.equal(babs, 1))
                .cmov(precmp[pos][1], Utils.equal(babs, 2))
                .cmov(precmp[pos][2], Utils.equal(babs, 3))
                .cmov(precmp[pos][3], Utils.equal(babs, 4))
                .cmov(precmp[pos][4], Utils.equal(babs, 5))
                .cmov(precmp[pos][5], Utils.equal(babs, 6))
                .cmov(precmp[pos][6], Utils.equal(babs, 7))
                .cmov(precmp[pos][7], Utils.equal(babs, 8));
        // -16^i |r_i| B
        GroupElement tminus = precomp(curve, t.Y, t.X, t.Z.negate());
        // 16^i r_i B
        return t.cmov(tminus, bnegative);
    }

    /**
     * $h = a * B$ where $a = a[0]+256*a[1]+\dots+256^{31} a[31]$ and
     * $B$ is this point. If its lookup table has not been precomputed, it
     * will be at the start of the method (and cached for later calls).
     * Constant time.
     * <p>
     * Preconditions: (TODO: Check this applies here)
     *   $a[31] \le 127$
     * @param a $= a[0]+256*a[1]+\dots+256^{31} a[31]$
     * @return the GroupElement
     */
    public GroupElement scalarMultiply(byte[] a) {
        int i;

        byte[] e = toRadix16(a);

        GroupElement h = curve.getZero(Representation.P3);
        synchronized(this) {
            // TODO: Get opinion from a crypto professional.
            // This should in practice never be necessary, the only point that
            // this should get called on is EdDSA's B.
            //precompute();
            for (i = 1; i < 64; i = i + 2) {
                h = h.madd(select(i/2, e[i])).toP3();
            }

            h = h.dbl().toP2().dbl().toP2().dbl().toP2().dbl().toP3();

            for (i = 0; i < 64; i = i + 2) {
                h = h.madd(select(i/2, e[i])).toP3();
            }
        }

        return h;
    }

    /**
     * Calculates a sliding-windows base 2 representation for a given value $a$.
     * To learn more about it see [6] page 8.
     * <p>
     * Output: $r$ which satisfies
     * $a = r0 * 2^0 + r1 * 2^1 + \dots + r255 * 2^{255}$ with $ri$ in $\{-15, -13, -11, -9, -7, -5, -3, -1, 0, 1, 3, 5, 7, 9, 11, 13, 15\}$
     * <p>
     * Method is package private only so that tests run.
     *
     * @param a $= a[0]+256*a[1]+\dots+256^{31} a[31]$.
     * @return The byte array $r$ in the above described form.
     */
    static byte[] slide(byte[] a) {
        byte[] r = new byte[256];

        // Put each bit of 'a' into a separate byte, 0 or 1
        for (int i = 0; i < 256; ++i) {
            r[i] = (byte) (1 & (a[i >> 3] >> (i & 7)));
        }

        // Note: r[i] will always be odd.
        for (int i = 0; i < 256; ++i) {
            if (r[i] != 0) {
                // Accumulate bits if possible
                for (int b = 1; b <= 6 && i + b < 256; ++b) {
                    if (r[i + b] != 0) {
                        if (r[i] + (r[i + b] << b) <= 15) {
                            r[i] = (byte) (r[i] + (r[i + b] << b));
                            r[i + b] = (byte) 0;
                        } else if (r[i] - (r[i + b] << b) >= -15) {
                            r[i] = (byte) (r[i] - (r[i + b] << b));
                            for (int k = i + b; k < 256; ++k) {
                                if (r[k] == 0) {
                                    r[k] = (byte) 1;
                                    break;
                                }
                                r[k] = (byte) 0;
                            }
                        } else
                            break;
                    }
                }
            }
        }

        return r;
    }

    /**
     * $r = a * A + b * B$ where $a = a[0]+256*a[1]+\dots+256^{31} a[31]$,
     * $b = b[0]+256*b[1]+\dots+256^{31} b[31]$ and $B$ is this point.
     * <p>
     * $A$ must have been previously precomputed.
     *
     * @param A in P3 representation.
     * @param a $= a[0]+256*a[1]+\dots+256^{31} a[31]$
     * @param b $= b[0]+256*b[1]+\dots+256^{31} b[31]$
     * @return the GroupElement
     */
    public GroupElement doubleScalarMultiplyVariableTime(GroupElement A, byte[] a, byte[] b) {
        // TODO-CR BR: A check that this is the base point is needed.
        byte[] aslide = slide(a);
        byte[] bslide = slide(b);

        GroupElement r = curve.getZero(Representation.P2);

        int i;
        for (i = 255; i >= 0; --i) {
            if (aslide[i] != 0 || bslide[i] != 0) break;
        }

        synchronized(this) {
            // TODO-CR BR strange comment below.
            // TODO: Get opinion from a crypto professional.
            // This should in practice never be necessary, the only point that
            // this should get called on is EdDSA's B.
            //precompute();
            while (i >= 0) {
                GroupElement t = r.dbl();

                if (aslide[i] > 0) {
                    t = t.toP3().madd(A.dblPrecmp[aslide[i]/2]);
                } else if(aslide[i] < 0) {
                    t = t.toP3().msub(A.dblPrecmp[(-aslide[i])/2]);
                }

                if (bslide[i] > 0) {
                    t = t.toP3().madd(dblPrecmp[bslide[i]/2]);
                } else if(bslide[i] < 0) {
                    t = t.toP3().msub(dblPrecmp[(-bslide[i])/2]);
                }

                r = t.toP2();
                --i;
            }
        }

        return r;
    }

    /**
     * Verify that a point is on its curve.
     * @return true if the point lies on its curve.
     */
    public boolean isOnCurve() {
        return isOnCurve(curve);
    }

    /**
     * Verify that a point is on the curve.
     * @param curve The curve to check.
     * @return true if the point lies on the curve.
     */
    public boolean isOnCurve(Curve curve) {
        switch (repr) {
        case P2:
        case P3:
            FieldElement recip = Z.invert();
            FieldElement x = X.multiply(recip);
            FieldElement y = Y.multiply(recip);
            FieldElement xx = x.square();
            FieldElement yy = y.square();
            FieldElement dxxyy = curve.getD().multiply(xx).multiply(yy);
            return curve.getField().ONE.add(dxxyy).add(xx).equals(yy);

        default:
            return toP2().isOnCurve(curve);
        }
    }

    @Override
    public String toString() {
        return "[GroupElement\nX="+X+"\nY="+Y+"\nZ="+Z+"\nT="+T+"\n]";
    }
}
