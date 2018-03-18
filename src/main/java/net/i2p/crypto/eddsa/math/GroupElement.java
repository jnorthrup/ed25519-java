/**
 * EdDSA-Java by str4d
 * <p>
 * To the extent possible under law, the person who associated CC0 with
 * EdDSA-Java has waived all copyright and related or neighboring rights
 * to EdDSA-Java.
 * <p>
 * You should have received a copy of the CC0 legalcode along with this
 * work. If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
 */
package net.i2p.crypto.eddsa.math;

import net.i2p.crypto.eddsa.Utils;

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
public class GroupElement {

    public Curve curve;
    public Representation repr;
    public FieldElement X;
    public FieldElement Y;
    public FieldElement Z;
    public FieldElement T;
    public GroupElement[][] precmp;
    public GroupElement[] dblPrecmp;

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
    protected GroupElement(
            final Curve curve,
            final Representation repr,
            final FieldElement X,
            final FieldElement Y,
            final FieldElement Z,
            final FieldElement T,
            final boolean precomputeDouble) {
        this.curve = curve;
        this.repr = repr;
        this.X = X;
        this.Y = Y;
        this.Z = Z;
        this.T = T;
        this.precmp = null;
        this.dblPrecmp = precomputeDouble ? precomputeDouble() : null;
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
     * @param curve                     The curve.
     * @param s                         The encoded point.
     * @param precomputeSingleAndDouble If true, populate both precmp and dblPrecmp, else set both to null.
     */
    // TODO
    protected GroupElement(final Curve curve, final byte[] s, final boolean precomputeSingleAndDouble) {
        FieldElement x;
        final FieldElement y;
        final FieldElement yy;
        final FieldElement u;
        final FieldElement v;
        final FieldElement v3;
        final FieldElement vxx;
        FieldElement check;
        y = curve.getEdDSAFiniteField().fromByteArray(s);
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

            assert !check.isNonZero() : "not a valid GroupElement";
            x = x.multiply(curve.getI());
        }

        if ((x.isNegative() ? 1 : 0) != Utils.bit(s, curve.getEdDSAFiniteField().getb() - 1)) {
            x = x.negate();
        }

        this.curve = curve;
        this.repr = Representation.P3;
        this.X = x;
        this.Y = y;
        this.Z = curve.getEdDSAFiniteField().ONE;
        this.T = this.getX().multiply(this.getY());
        if (precomputeSingleAndDouble) {
            precmp = precomputeSingle();
            dblPrecmp = precomputeDouble();
        } else {
            precmp = null;
            dblPrecmp = null;
        }
    }

    public GroupElement() {

    }

    /**
     * Creates a new group element in P1P1 representation.
     *
     * @param curve The curve.
     * @param X     The $X$ coordinate.
     * @param Y     The $Y$ coordinate.
     * @param Z     The $Z$ coordinate.
     * @param T     The $T$ coordinate.
     * @return The group element in P1P1 representation.
     */
    public static GroupElement p1p1(
            final Curve curve,
            final FieldElement X,
            final FieldElement Y,
            final FieldElement Z,
            final FieldElement T) {

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
        return new P1pGroupElement(curve, X, Y, Z, T);
    }

    /**
     * Creates a new group element in CACHED representation.
     *
     * @param curve The curve.
     * @param YpX   The $Y + X$ value.
     * @param YmX   The $Y - X$ value.
     * @param Z     The $Z$ coordinate.
     * @param T2d   The $2 * d * T$ value.
     * @return The group element in CACHED representation.
     */
    public static GroupElement cached(
            final Curve curve,
            final FieldElement YpX,
            final FieldElement YmX,
            final FieldElement Z,
            final FieldElement T2d) {
        return new CachedGroupElement(curve, YpX, YmX, Z, T2d);
    }

    /**
     * Convert a to radix 16.
     *
     * Method is package public only so that tests run.
     *
     * @param a $= a[0]+256*a[1]+...+256^{31} a[31]$
     * @return 64 bytes, each between -8 and 7
     */
    static byte[] toRadix16(final byte[] a) {
        final byte[] e = new byte[64];

        // Radix 16 notation
        e[2 * 0] = (byte) (a[0] & 15);
        e[2 * 0 + 1] = (byte) ((a[0] >> 4) & 15);
        e[2 * 1] = (byte) (a[1] & 15);
        e[2 * 1 + 1] = (byte) ((a[1] >> 4) & 15);
        e[2 * 2] = (byte) (a[2] & 15);
        e[2 * 2 + 1] = (byte) ((a[2] >> 4) & 15);
        e[2 * 3] = (byte) (a[3] & 15);
        e[2 * 3 + 1] = (byte) ((a[3] >> 4) & 15);
        e[2 * 4] = (byte) (a[4] & 15);
        e[2 * 4 + 1] = (byte) ((a[4] >> 4) & 15);
        e[2 * 5] = (byte) (a[5] & 15);
        e[2 * 5 + 1] = (byte) ((a[5] >> 4) & 15);
        e[2 * 6] = (byte) (a[6] & 15);
        e[2 * 6 + 1] = (byte) ((a[6] >> 4) & 15);
        e[2 * 7] = (byte) (a[7] & 15);
        e[2 * 7 + 1] = (byte) ((a[7] >> 4) & 15);
        e[2 * 8] = (byte) (a[8] & 15);
        e[2 * 8 + 1] = (byte) ((a[8] >> 4) & 15);
        e[2 * 9] = (byte) (a[9] & 15);
        e[2 * 9 + 1] = (byte) ((a[9] >> 4) & 15);
        e[2 * 10] = (byte) (a[10] & 15);
        e[2 * 10 + 1] = (byte) ((a[10] >> 4) & 15);
        e[2 * 11] = (byte) (a[11] & 15);
        e[2 * 11 + 1] = (byte) ((a[11] >> 4) & 15);
        e[2 * 12] = (byte) (a[12] & 15);
        e[2 * 12 + 1] = (byte) ((a[12] >> 4) & 15);
        e[2 * 13] = (byte) (a[13] & 15);
        e[2 * 13 + 1] = (byte) ((a[13] >> 4) & 15);
        e[2 * 14] = (byte) (a[14] & 15);
        e[2 * 14 + 1] = (byte) ((a[14] >> 4) & 15);
        e[2 * 15] = (byte) (a[15] & 15);
        e[2 * 15 + 1] = (byte) ((a[15] >> 4) & 15);
        e[2 * 16] = (byte) (a[16] & 15);
        e[2 * 16 + 1] = (byte) ((a[16] >> 4) & 15);
        e[2 * 17] = (byte) (a[17] & 15);
        e[2 * 17 + 1] = (byte) ((a[17] >> 4) & 15);
        e[2 * 18] = (byte) (a[18] & 15);
        e[2 * 18 + 1] = (byte) ((a[18] >> 4) & 15);
        e[2 * 19] = (byte) (a[19] & 15);
        e[2 * 19 + 1] = (byte) ((a[19] >> 4) & 15);
        e[2 * 20] = (byte) (a[20] & 15);
        e[2 * 20 + 1] = (byte) ((a[20] >> 4) & 15);
        e[2 * 21] = (byte) (a[21] & 15);
        e[2 * 21 + 1] = (byte) ((a[21] >> 4) & 15);
        e[2 * 22] = (byte) (a[22] & 15);
        e[2 * 22 + 1] = (byte) ((a[22] >> 4) & 15);
        e[2 * 23] = (byte) (a[23] & 15);
        e[2 * 23 + 1] = (byte) ((a[23] >> 4) & 15);
        e[2 * 24] = (byte) (a[24] & 15);
        e[2 * 24 + 1] = (byte) ((a[24] >> 4) & 15);
        e[2 * 25] = (byte) (a[25] & 15);
        e[2 * 25 + 1] = (byte) ((a[25] >> 4) & 15);
        e[2 * 26] = (byte) (a[26] & 15);
        e[2 * 26 + 1] = (byte) ((a[26] >> 4) & 15);
        e[2 * 27] = (byte) (a[27] & 15);
        e[2 * 27 + 1] = (byte) ((a[27] >> 4) & 15);
        e[2 * 28] = (byte) (a[28] & 15);
        e[2 * 28 + 1] = (byte) ((a[28] >> 4) & 15);
        e[2 * 29] = (byte) (a[29] & 15);
        e[2 * 29 + 1] = (byte) ((a[29] >> 4) & 15);
        e[2 * 30] = (byte) (a[30] & 15);
        e[2 * 30 + 1] = (byte) ((a[30] >> 4) & 15);
        e[2 * 31] = (byte) (a[31] & 15);
        e[2 * 31 + 1] = (byte) ((a[31] >> 4) & 15);
        /* each e[i] is between 0 and 15 */
        /* e[63] is between 0 and 7 */
        int carry = 0;
        e[0] = (byte) (e[0] + carry);
        carry = e[0] + 8;
        carry = carry >> 4;
        e[0] = (byte) (e[0] - (carry << 4));
        e[1] = (byte) (e[1] + carry);
        carry = e[1] + 8;
        carry = carry >> 4;
        e[1] = (byte) (e[1] - (carry << 4));
        e[2] = (byte) (e[2] + carry);
        carry = e[2] + 8;
        carry = carry >> 4;
        e[2] = (byte) (e[2] - (carry << 4));
        e[3] = (byte) (e[3] + carry);
        carry = e[3] + 8;
        carry = carry >> 4;
        e[3] = (byte) (e[3] - (carry << 4));
        e[4] = (byte) (e[4] + carry);
        carry = e[4] + 8;
        carry = carry >> 4;
        e[4] = (byte) (e[4] - (carry << 4));
        e[5] = (byte) (e[5] + carry);
        carry = e[5] + 8;
        carry = carry >> 4;
        e[5] = (byte) (e[5] - (carry << 4));
        e[6] = (byte) (e[6] + carry);
        carry = e[6] + 8;
        carry = carry >> 4;
        e[6] = (byte) (e[6] - (carry << 4));
        e[7] = (byte) (e[7] + carry);
        carry = e[7] + 8;
        carry = carry >> 4;
        e[7] = (byte) (e[7] - (carry << 4));
        e[8] = (byte) (e[8] + carry);
        carry = e[8] + 8;
        carry = carry >> 4;
        e[8] = (byte) (e[8] - (carry << 4));
        e[9] = (byte) (e[9] + carry);
        carry = e[9] + 8;
        carry = carry >> 4;
        e[9] = (byte) (e[9] - (carry << 4));
        e[10] = (byte) (e[10] + carry);
        carry = e[10] + 8;
        carry = carry >> 4;
        e[10] = (byte) (e[10] - (carry << 4));
        e[11] = (byte) (e[11] + carry);
        carry = e[11] + 8;
        carry = carry >> 4;
        e[11] = (byte) (e[11] - (carry << 4));
        e[12] = (byte) (e[12] + carry);
        carry = e[12] + 8;
        carry = carry >> 4;
        e[12] = (byte) (e[12] - (carry << 4));
        e[13] = (byte) (e[13] + carry);
        carry = e[13] + 8;
        carry = carry >> 4;
        e[13] = (byte) (e[13] - (carry << 4));
        e[14] = (byte) (e[14] + carry);
        carry = e[14] + 8;
        carry = carry >> 4;
        e[14] = (byte) (e[14] - (carry << 4));
        e[15] = (byte) (e[15] + carry);
        carry = e[15] + 8;
        carry = carry >> 4;
        e[15] = (byte) (e[15] - (carry << 4));
        e[16] = (byte) (e[16] + carry);
        carry = e[16] + 8;
        carry = carry >> 4;
        e[16] = (byte) (e[16] - (carry << 4));
        e[17] = (byte) (e[17] + carry);
        carry = e[17] + 8;
        carry = carry >> 4;
        e[17] = (byte) (e[17] - (carry << 4));
        e[18] = (byte) (e[18] + carry);
        carry = e[18] + 8;
        carry = carry >> 4;
        e[18] = (byte) (e[18] - (carry << 4));
        e[19] = (byte) (e[19] + carry);
        carry = e[19] + 8;
        carry = carry >> 4;
        e[19] = (byte) (e[19] - (carry << 4));
        e[20] = (byte) (e[20] + carry);
        carry = e[20] + 8;
        carry = carry >> 4;
        e[20] = (byte) (e[20] - (carry << 4));
        e[21] = (byte) (e[21] + carry);
        carry = e[21] + 8;
        carry = carry >> 4;
        e[21] = (byte) (e[21] - (carry << 4));
        e[22] = (byte) (e[22] + carry);
        carry = e[22] + 8;
        carry = carry >> 4;
        e[22] = (byte) (e[22] - (carry << 4));
        e[23] = (byte) (e[23] + carry);
        carry = e[23] + 8;
        carry = carry >> 4;
        e[23] = (byte) (e[23] - (carry << 4));
        e[24] = (byte) (e[24] + carry);
        carry = e[24] + 8;
        carry = carry >> 4;
        e[24] = (byte) (e[24] - (carry << 4));
        e[25] = (byte) (e[25] + carry);
        carry = e[25] + 8;
        carry = carry >> 4;
        e[25] = (byte) (e[25] - (carry << 4));
        e[26] = (byte) (e[26] + carry);
        carry = e[26] + 8;
        carry = carry >> 4;
        e[26] = (byte) (e[26] - (carry << 4));
        e[27] = (byte) (e[27] + carry);
        carry = e[27] + 8;
        carry = carry >> 4;
        e[27] = (byte) (e[27] - (carry << 4));
        e[28] = (byte) (e[28] + carry);
        carry = e[28] + 8;
        carry = carry >> 4;
        e[28] = (byte) (e[28] - (carry << 4));
        e[29] = (byte) (e[29] + carry);
        carry = e[29] + 8;
        carry = carry >> 4;
        e[29] = (byte) (e[29] - (carry << 4));
        e[30] = (byte) (e[30] + carry);
        carry = e[30] + 8;
        carry = carry >> 4;
        e[30] = (byte) (e[30] - (carry << 4));
        e[31] = (byte) (e[31] + carry);
        carry = e[31] + 8;
        carry = carry >> 4;
        e[31] = (byte) (e[31] - (carry << 4));
        e[32] = (byte) (e[32] + carry);
        carry = e[32] + 8;
        carry = carry >> 4;
        e[32] = (byte) (e[32] - (carry << 4));
        e[33] = (byte) (e[33] + carry);
        carry = e[33] + 8;
        carry = carry >> 4;
        e[33] = (byte) (e[33] - (carry << 4));
        e[34] = (byte) (e[34] + carry);
        carry = e[34] + 8;
        carry = carry >> 4;
        e[34] = (byte) (e[34] - (carry << 4));
        e[35] = (byte) (e[35] + carry);
        carry = e[35] + 8;
        carry = carry >> 4;
        e[35] = (byte) (e[35] - (carry << 4));
        e[36] = (byte) (e[36] + carry);
        carry = e[36] + 8;
        carry = carry >> 4;
        e[36] = (byte) (e[36] - (carry << 4));
        e[37] = (byte) (e[37] + carry);
        carry = e[37] + 8;
        carry = carry >> 4;
        e[37] = (byte) (e[37] - (carry << 4));
        e[38] = (byte) (e[38] + carry);
        carry = e[38] + 8;
        carry = carry >> 4;
        e[38] = (byte) (e[38] - (carry << 4));
        e[39] = (byte) (e[39] + carry);
        carry = e[39] + 8;
        carry = carry >> 4;
        e[39] = (byte) (e[39] - (carry << 4));
        e[40] = (byte) (e[40] + carry);
        carry = e[40] + 8;
        carry = carry >> 4;
        e[40] = (byte) (e[40] - (carry << 4));
        e[41] = (byte) (e[41] + carry);
        carry = e[41] + 8;
        carry = carry >> 4;
        e[41] = (byte) (e[41] - (carry << 4));
        e[42] = (byte) (e[42] + carry);
        carry = e[42] + 8;
        carry = carry >> 4;
        e[42] = (byte) (e[42] - (carry << 4));
        e[43] = (byte) (e[43] + carry);
        carry = e[43] + 8;
        carry = carry >> 4;
        e[43] = (byte) (e[43] - (carry << 4));
        e[44] = (byte) (e[44] + carry);
        carry = e[44] + 8;
        carry = carry >> 4;
        e[44] = (byte) (e[44] - (carry << 4));
        e[45] = (byte) (e[45] + carry);
        carry = e[45] + 8;
        carry = carry >> 4;
        e[45] = (byte) (e[45] - (carry << 4));
        e[46] = (byte) (e[46] + carry);
        carry = e[46] + 8;
        carry = carry >> 4;
        e[46] = (byte) (e[46] - (carry << 4));
        e[47] = (byte) (e[47] + carry);
        carry = e[47] + 8;
        carry = carry >> 4;
        e[47] = (byte) (e[47] - (carry << 4));
        e[48] = (byte) (e[48] + carry);
        carry = e[48] + 8;
        carry = carry >> 4;
        e[48] = (byte) (e[48] - (carry << 4));
        e[49] = (byte) (e[49] + carry);
        carry = e[49] + 8;
        carry = carry >> 4;
        e[49] = (byte) (e[49] - (carry << 4));
        e[50] = (byte) (e[50] + carry);
        carry = e[50] + 8;
        carry = carry >> 4;
        e[50] = (byte) (e[50] - (carry << 4));
        e[51] = (byte) (e[51] + carry);
        carry = e[51] + 8;
        carry = carry >> 4;
        e[51] = (byte) (e[51] - (carry << 4));
        e[52] = (byte) (e[52] + carry);
        carry = e[52] + 8;
        carry = carry >> 4;
        e[52] = (byte) (e[52] - (carry << 4));
        e[53] = (byte) (e[53] + carry);
        carry = e[53] + 8;
        carry = carry >> 4;
        e[53] = (byte) (e[53] - (carry << 4));
        e[54] = (byte) (e[54] + carry);
        carry = e[54] + 8;
        carry = carry >> 4;
        e[54] = (byte) (e[54] - (carry << 4));
        e[55] = (byte) (e[55] + carry);
        carry = e[55] + 8;
        carry = carry >> 4;
        e[55] = (byte) (e[55] - (carry << 4));
        e[56] = (byte) (e[56] + carry);
        carry = e[56] + 8;
        carry = carry >> 4;
        e[56] = (byte) (e[56] - (carry << 4));
        e[57] = (byte) (e[57] + carry);
        carry = e[57] + 8;
        carry = carry >> 4;
        e[57] = (byte) (e[57] - (carry << 4));
        e[58] = (byte) (e[58] + carry);
        carry = e[58] + 8;
        carry = carry >> 4;
        e[58] = (byte) (e[58] - (carry << 4));
        e[59] = (byte) (e[59] + carry);
        carry = e[59] + 8;
        carry = carry >> 4;
        e[59] = (byte) (e[59] - (carry << 4));
        e[60] = (byte) (e[60] + carry);
        carry = e[60] + 8;
        carry = carry >> 4;
        e[60] = (byte) (e[60] - (carry << 4));
        e[61] = (byte) (e[61] + carry);
        carry = e[61] + 8;
        carry = carry >> 4;
        e[61] = (byte) (e[61] - (carry << 4));
        e[62] = (byte) (e[62] + carry);
        carry = e[62] + 8;
        carry = carry >> 4;
        e[62] = (byte) (e[62] - (carry << 4));
        e[63] = (byte) (e[63] + carry);
        /* each e[i] is between -8 and 7 */
        return e;
    }

    /**
     * Calculates a sliding-windows base 2 representation for a given value $a$.
     * To learn more about it see [6] page 8.
     * <p>
     * Output: $r$ which satisfies
     * $a = r0 * 2^0 + r1 * 2^1 + \dots + r255 * 2^{255}$ with $ri$ in $\{-15, -13, -11, -9, -7, -5, -3, -1, 0, 1, 3, 5, 7, 9, 11, 13, 15\}$
     * <p>
     * Method is package public only so that tests run.
     *
     * @param a $= a[0]+256*a[1]+\dots+256^{31} a[31]$.
     * @return The byte array $r$ in the above described form.
     */
    public static byte[] slide(final byte[] a) {
        final byte[] r = new byte[256];

        // Put each bit of 'a' into a separate byte, 0 or 1
        for (int i = 0; 256 > i; ++i) {
            r[i] = (byte) (1 & (a[i >> 3] >> (i & 7)));
        }

        // Note: r[i] will always be odd.
        for (int i = 0; 256 > i; ++i) {
            if (0 != r[i]) {
                for (int b = 1; 6 >= b && 256 > i + b; ++b) {
                    // Accumulate bits if possible
                    if (0 != r[i + b]) {
                        if (15 >= r[i] + (r[i + b] << b)) {
                            r[i] = (byte) (r[i] + (r[i + b] << b));
                            r[i + b] = (byte) 0;
                        } else if (-15 <= r[i] - (r[i + b] << b)) {
                            r[i] = (byte) (r[i] - (r[i + b] << b));
                            for (int k = i + b; 256 > k; ++k) {
                                if (0 == r[k]) {
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
     * Variable is package public only so that tests run.
     */
    public Representation getRepr() {
        return repr;
    }

    /**
     * Variable is package public only so that tests run.
     */
    public FieldElement getX() {
        return X;
    }

    /**
     * Variable is package public only so that tests run.
     */
    public FieldElement getY() {
        return Y;
    }

    /**
     * Variable is package public only so that tests run.
     */
    public FieldElement getZ() {
        return Z;
    }

    /**
     * Variable is package public only so that tests run.
     */
    public FieldElement getT() {
        return T;
    }

    /**
     * Precomputed table for {@link #scalarMultiply(byte[])},
     * filled if necessary.
     * <p>
     * Variable is package public only so that tests run.
     */
    public GroupElement[][] getPrecmp() {
        return precmp;
    }

    /**
     * Variable is package public only so that tests run.
     */

    /**
     * Precomputed table for {@link #doubleScalarMultiplyVariableTime(GroupElement, byte[], byte[])},
     * filled if necessary.
     * <p>
     * Variable is package public only so that tests run.
     */
    public GroupElement[] getDblPrecmp() {
        return dblPrecmp;
    }

    /**
     * Gets the curve of the group element.
     *
     * @return The curve.
     */
    public Curve getCurve() {
        return this.curve;
    }

    /**
     * Gets the representation of the group element.
     *
     * @return The representation.
     */
    public Representation getRepresentation() {
        return this.getRepr();
    }

    /**
     * Converts the group element to an encoded point on the curve.
     *
     * @return The encoded point as byte array.
     */
    public byte[] toByteArray() {
        switch (this.getRepr()) {
            case P2:
            case P3:
                final FieldElement recip = getZ().invert();
                final FieldElement x = getX().multiply(recip);
                final FieldElement y = getY().multiply(recip);
                final byte[] s = y.toByteArray();
                s[s.length - 1] |= (x.isNegative() ? (byte) 0x80 : (byte) 0);
                return s;
            default:
                return Representation.P2.toRep(this).toByteArray();
        }
    }

    /**
     * Precomputes table for {@link #scalarMultiply(byte[])}.
     */
    public GroupElement[][] precomputeSingle() {
        // Precomputation for single scalar multiplication.
        final GroupElement[][] precmp = new GroupElement[32][8];
        // TODO-CR BR: check that this == base point when the method is called.
        GroupElement Bi = this;
        for (int i = 0; 32 > i; i++) {
            GroupElement Bij = Bi;
            for (int j = 0; 8 > j; j++) {
                final FieldElement recip = Bij.getZ().invert();
                final FieldElement x = Bij.getX().multiply(recip);
                final FieldElement y = Bij.getY().multiply(recip);
                precmp[i][j] = new PrecompGroupElement(this.getCurve(), y.add(x), y.subtract(x), x.multiply(y).multiply(this.getCurve().getD2()));
                Bij = Representation.P3.toRep(Bij.add(Representation.CACHED.toRep(Bi)));
            }
            // Only every second summand is precomputed (16^2 = 256)
            for (int k = 0; 8 > k; k++) {
                Bi = Representation.P3.toRep(Bi.add(Representation.CACHED.toRep(Bi)));
            }
        }
        return precmp;
    }

    /**
     * Precomputes table for {@link #doubleScalarMultiplyVariableTime(GroupElement, byte[], byte[])}.
     */
    public GroupElement[] precomputeDouble() {
        // Precomputation for double scalar multiplication.
        // P,3P,5P,7P,9P,11P,13P,15P
        final GroupElement[] dblPrecmp = new GroupElement[8];
        GroupElement Bi = this;
        for (int i = 0; 8 > i; i++) {
            final FieldElement recip = Bi.getZ().invert();
            final FieldElement x = Bi.getX().multiply(recip);
            final FieldElement y = Bi.getY().multiply(recip);
            dblPrecmp[i] = new PrecompGroupElement(this.getCurve(), y.add(x), y.subtract(x), x.multiply(y).multiply(this.getCurve().getD2()));
            // Bi = edwards(B,edwards(B,Bi))
            Bi = Representation.P3.toRep(this.add(Representation.CACHED.toRep(Representation.P3.toRep(this.add(Representation.CACHED.toRep(Bi))))));
        }
        return dblPrecmp;
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
        switch (this.getRepr()) {
            case P2:
            case P3: // Ignore T for P3 representation
                final FieldElement XX;
                final FieldElement YY;
                final FieldElement B;
                final FieldElement A;
                final FieldElement AA;
                final FieldElement Yn;
                final FieldElement Zn;
                XX = this.getX().square();
                YY = this.getY().square();
                B = this.getZ().squareAndDouble();
                A = this.getX().add(this.getY());
                AA = A.square();
                Yn = YY.add(XX);
                Zn = YY.subtract(XX);

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
                return new P1pGroupElement(this.getCurve(), AA.subtract(Yn), Yn, Zn, B.subtract(Zn));
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
    public GroupElement madd(final GroupElement q) {
        assert Representation.P3 == this.getRepr();
        assert Representation.PRECOMP == q.getRepr();

        final FieldElement YpX;
        final FieldElement YmX;
        final FieldElement A;
        final FieldElement B;
        final FieldElement C;
        final FieldElement D;
        YpX = this.getY().add(this.getX());
        YmX = this.getY().subtract(this.getX());
        A = YpX.multiply(q.getX()); // q->y+x
        B = YmX.multiply(q.getY()); // q->y-x
        C = q.getZ().multiply(this.getT()); // q->2dxy
        D = this.getZ().add(this.getZ());

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
        return new P1pGroupElement(this.getCurve(), A.subtract(B), A.add(B), D.add(C), D.subtract(C));
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
    public GroupElement msub(final GroupElement q) {
        assert Representation.P3 == this.getRepr();
        assert Representation.PRECOMP == q.getRepr();

        final FieldElement YpX;
        final FieldElement YmX;
        final FieldElement A;
        final FieldElement B;
        final FieldElement C;
        final FieldElement D;
        YpX = this.getY().add(this.getX());
        YmX = this.getY().subtract(this.getX());
        A = YpX.multiply(q.getY()); // q->y-x
        B = YmX.multiply(q.getX()); // q->y+x
        C = q.getZ().multiply(this.getT()); // q->2dxy
        D = this.getZ().add(this.getZ());

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
        return new P1pGroupElement(this.getCurve(), A.subtract(B), A.add(B), D.subtract(C), D.add(C));
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
    public GroupElement add(final GroupElement q) {
        assert Representation.P3 == this.getRepr();
        assert Representation.CACHED == q.getRepr();

        final FieldElement YpX;
        final FieldElement YmX;
        final FieldElement A;
        final FieldElement B;
        final FieldElement C;
        final FieldElement ZZ;
        final FieldElement D;
        YpX = this.getY().add(this.getX());
        YmX = this.getY().subtract(this.getX());
        A = YpX.multiply(q.getX()); // q->Y+X
        B = YmX.multiply(q.getY()); // q->Y-X
        C = q.getT().multiply(this.getT()); // q->2dT
        ZZ = this.getZ().multiply(q.getZ());
        D = ZZ.add(ZZ);

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
        return new P1pGroupElement(this.getCurve(), A.subtract(B), A.add(B), D.add(C), D.subtract(C));
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
    public GroupElement sub(final GroupElement q) {
        assert Representation.P3 == this.getRepr();
        assert Representation.CACHED == q.getRepr();

        final FieldElement YpX;
        final FieldElement YmX;
        final FieldElement A;
        final FieldElement B;
        final FieldElement C;
        final FieldElement ZZ;
        final FieldElement D;
        YpX = getY().add(getX());
        YmX = getY().subtract(getX());
        A = YpX.multiply(q.getY()); // q->Y-X
        B = YmX.multiply(q.getX()); // q->Y+X
        C = q.getT().multiply(getT()); // q->2dT
        ZZ = getZ().multiply(q.getZ());
        D = ZZ.add(ZZ);

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
        return new P1pGroupElement(getCurve(), A.subtract(B), A.add(B), D.subtract(C), D.add(C));
    }

    /**
     * Negates this group element by subtracting it from the neutral group element.
     * <p>
     * TODO-CR BR: why not simply negate the coordinates $X$ and $T$?
     *
     * @return The negative of this group element.
     */
    public GroupElement negate() {
        assert Representation.P3 == this.getRepr();
        return Representation.P3PrecomputedDouble.toRep(this.getCurve().get(Representation.P3).sub(Representation.CACHED.toRep(this)));
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(this.toByteArray());
    }

    @Override
    public boolean equals(final Object obj) {
        if (obj == this)
            return true;
        if (!(obj instanceof GroupElement))
            return false;
        GroupElement ge = (GroupElement) obj;
        if (this.getRepr() != ge.getRepr()) {
            try {
                ge = this.getRepr().toRep(ge);
            } catch (final RuntimeException e) {
                return false;
            }
        }
        switch (this.getRepr()) {
            case P2:
            case P3:
                // Try easy way first
                if (this.getZ().equals(ge.getZ()))
                    return this.getX().equals(ge.getX()) && this.getY().equals(ge.getY());
                // X1/Z1 = X2/Z2 --> X1*Z2 = X2*Z1
                final FieldElement x1 = this.getX().multiply(ge.getZ());
                final FieldElement y1 = this.getY().multiply(ge.getZ());
                final FieldElement x2 = ge.getX().multiply(this.getZ());
                final FieldElement y2 = ge.getY().multiply(this.getZ());
                return x1.equals(x2) && y1.equals(y2);
            case P1P1:
                return Representation.P2.toRep(this).equals(ge);
            case PRECOMP:
                // Compare directly, PRECOMP is derived directly from x and y
                return this.getX().equals(ge.getX()) && this.getY().equals(ge.getY()) && this.getZ().equals(ge.getZ());
            case CACHED:
                // Try easy way first
                if (this.getZ().equals(ge.getZ()))
                    return this.getX().equals(ge.getX()) && this.getY().equals(ge.getY()) && this.getT().equals(ge.getT());
                // (Y+X)/Z = y+x etc.
                final FieldElement x3 = this.getX().multiply(ge.getZ());
                final FieldElement y3 = this.getY().multiply(ge.getZ());
                final FieldElement t3 = this.getT().multiply(ge.getZ());
                final FieldElement x4 = ge.getX().multiply(this.getZ());
                final FieldElement y4 = ge.getY().multiply(this.getZ());
                final FieldElement t4 = ge.getT().multiply(this.getZ());
                return x3.equals(x4) && y3.equals(y4) && t3.equals(t4);
            default:
                return false;
        }
    }

    /**
     * Constant-time conditional move.
     * <p>
     * Replaces this with $u$ if $b == 1$.<br>
     * Replaces this with this if $b == 0$.
     * <p>
     * Method is package public only so that tests run.
     *
     * @param u The group element to return if $b == 1$.
     * @param b in $\{0, 1\}$
     * @return $u$ if $b == 1$; this if $b == 0$. Results undefined if $b$ is not in $\{0, 1\}$.
     */
    GroupElement cmov(final GroupElement u, final int b) {
        return
                /**
                 * Creates a new group element in PRECOMP representation.
                 *
                 * @param curve The curve.
                 * @param ypx The $y + x$ value.
                 * @param ymx The $y - x$ value.
                 * @param xy2d The $2 * d * x * y$ value.
                 * @return The group element in PRECOMP representation.
                 */new PrecompGroupElement(getCurve(), getX().cmov(u.getX(), b), getY().cmov(u.getY(), b), getZ().cmov(u.getZ(), b));
    }

    /**
     * Look up $16^i r_i B$ in the precomputed table.
     * <p>
     * No secret array indices, no secret branching.
     * Constant time.
     * <p>
     * Must have previously precomputed.
     * <p>
     * Method is package public only so that tests run.
     *
     * @param pos $= i/2$ for $i$ in $\{0, 2, 4,..., 62\}$
     * @param b   $= r_i$
     * @return the GroupElement
     */
    GroupElement select(final int pos, final int b) {
        // Is r_i negative?
        final int bnegative = Utils.negative(b);
        // |r_i|
        final int babs = b - (((-bnegative) & b) << 1);

        // 16^i |r_i| B
        final GroupElement t = this.getCurve().get(Representation.PRECOMP)
                .cmov(this.getPrecmp()[pos][0], Utils.equal(babs, 1))
                .cmov(this.getPrecmp()[pos][1], Utils.equal(babs, 2))
                .cmov(this.getPrecmp()[pos][2], Utils.equal(babs, 3))
                .cmov(this.getPrecmp()[pos][3], Utils.equal(babs, 4))
                .cmov(this.getPrecmp()[pos][4], Utils.equal(babs, 5))
                .cmov(this.getPrecmp()[pos][5], Utils.equal(babs, 6))
                .cmov(this.getPrecmp()[pos][6], Utils.equal(babs, 7))
                .cmov(this.getPrecmp()[pos][7], Utils.equal(babs, 8));
        // -16^i |r_i| B
        final GroupElement tminus = new PrecompGroupElement(getCurve(), t.getY(), t.getX(), t.getZ().negate());
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
     * $a[31] \le 127$
     *
     * @param a $= a[0]+256*a[1]+\dots+256^{31} a[31]$
     * @return the GroupElement
     */
    public GroupElement scalarMultiply(final byte[] a) {
        GroupElement t;
        int i;

        final byte[] e = toRadix16(a);

        GroupElement h = this.getCurve().get(Representation.P3);
        for (i = 1; 64 > i; i += 2) {
            t = select(i / 2, e[i]);
            h = Representation.P3.toRep(h.madd(t));
        }

        h = Representation.P3.toRep(Representation.P2.toRep(Representation.P2.toRep(Representation.P2.toRep(h.dbl()).dbl()).dbl()).dbl());

        for (i = 0; 64 > i; i += 2) {
            t = select(i / 2, e[i]);
            h = Representation.P3.toRep(h.madd(t));
        }

        return h;
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
    public GroupElement doubleScalarMultiplyVariableTime(final GroupElement A, final byte[] a, final byte[] b) {
        // TODO-CR BR: A check that this is the base point is needed.
        final byte[] aslide = slide(a);
        final byte[] bslide = slide(b);

        GroupElement r = this.getCurve().get(Representation.P2);

        int i;
        i = 255;
        while (0 <= i) {
            if (0 != aslide[i] || 0 != bslide[i]) break;
            --i;
        }

        while (0 <= i) {
            GroupElement t = r.dbl();

            if (0 < aslide[i]) {
                t = Representation.P3.toRep(t).madd(A.getDblPrecmp()[aslide[i] / 2]);
            } else if (0 > aslide[i]) {
                t = Representation.P3.toRep(t).msub(A.getDblPrecmp()[(-aslide[i]) / 2]);
            }

            if (0 < bslide[i]) {
                t = Representation.P3.toRep(t).madd(this.getDblPrecmp()[bslide[i] / 2]);
            } else if (0 > bslide[i]) {
                t = Representation.P3.toRep(t).msub(this.getDblPrecmp()[(-bslide[i]) / 2]);
            }

            r = Representation.P2.toRep(t);
            --i;
        }

        return r;
    }

    /**
     * Verify that a point is on its curve.
     *
     * @return true if the point lies on its curve.
     */
    public boolean isOnCurve() {
        return isOnCurve(getCurve());
    }

    /**
     * Verify that a point is on the curve.
     *
     * @param curve The curve to check.
     * @return true if the point lies on the curve.
     */
    public boolean isOnCurve(final Curve curve) {
        switch (getRepr()) {
            case P2:
            case P3:
                final FieldElement recip = getZ().invert();
                final FieldElement x = getX().multiply(recip);
                final FieldElement y = getY().multiply(recip);
                final FieldElement xx = x.square();
                final FieldElement yy = y.square();
                final FieldElement dxxyy = curve.getD().multiply(xx).multiply(yy);
                return curve.getEdDSAFiniteField().ONE.add(dxxyy).add(xx).equals(yy);

            default:
                return Representation.P2.toRep(this).isOnCurve(curve);
        }
    }

    @Override
    public String toString() {
        return "[GroupElement\nX=" + getX() + "\nY=" + getY() + "\nZ=" + getZ() + "\nT=" + getT() + "\n]";
    }

}
