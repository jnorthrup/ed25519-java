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

import java.io.Serializable;

/**
 * A twisted Edwards curve.
 * Points on the curve satisfy $-x^2 + y^2 = 1 + d x^2y^2$
 * @author str4d
 *
 */
public final class Curve   {
    private static final long serialVersionUID = 4578920872509827L;
    private final Field f;
    private final FieldElement d;
    private final FieldElement d2;
    private final FieldElement I;

    private final GroupElement zeroP2;
    private final GroupElement zeroP3;
    private final GroupElement zeroPrecomp;

    public Curve(final Field f, final byte[] d, final FieldElement I) {
        this.f = f;
        this.d = f.fromByteArray(d);
        this.d2 = this.d.add(this.d);
        this.I = I;

        final FieldElement zero = f.ZERO;
        final FieldElement one = f.ONE;
        zeroP2 = GroupElement.p2(this, zero, one, one);
        zeroP3 = GroupElement.p3(this, zero, one, one, zero);
        zeroPrecomp = GroupElement.precomp(this, one, one, zero);
    }

    public final Field getField() {
        return f;
    }

    public final FieldElement getD() {
        return d;
    }

    public final FieldElement getD2() {
        return d2;
    }

    public final FieldElement getI() {
        return I;
    }

    public final GroupElement getZero(final GroupElement.Representation repr) {
        switch (repr) {
        case P2:
            return zeroP2;
        case P3:
            return zeroP3;
        case PRECOMP:
            return zeroPrecomp;
        default:
            return null;
        }
    }

    public final GroupElement createPoint(final byte[] P, final boolean precompute) {
        final GroupElement ge = new GroupElement(this, P);
        if (precompute)
            ge.precompute(true);
        return ge;
    }

    @Override
    public final int hashCode() {
        return f.hashCode() ^
               d.hashCode() ^
               I.hashCode();
    }

    @Override
    public final boolean equals(final Object o) {
        if (o == this)
            return true;
        if (!(o instanceof Curve))
            return false;
        final Curve c = (Curve) o;
        return f.equals(c.getField()) &&
               d.equals(c.getD()) &&
               I.equals(c.getI());
    }
}
