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

/**
 * A twisted Edwards curve.
 * Points on the curve satisfy $-x^2 + y^2 = 1 + d x^2y^2$
 * @author str4d
 *
 */
public class Curve  {

    public final EdDSAFiniteField edDSAFiniteField;
    public final FieldElement d;
    public final FieldElement d2;
    public final FieldElement I;

    public final GroupElement zeroP2;
    public final GroupElement zeroP3;
    public final GroupElement zeroP3PrecomputedDouble;
    public final GroupElement zeroPrecomp;

    public Curve(final EdDSAFiniteField edDSAFiniteField, final byte[] d, final FieldElement I) {
        this.edDSAFiniteField = edDSAFiniteField;
        this.d = edDSAFiniteField.fromByteArray(d);
        this.d2 = this.d.add(this.d);
        this.I = I;

        final FieldElement zero = edDSAFiniteField.ZERO;
        final FieldElement one = edDSAFiniteField.ONE;
        zeroP2 = GroupElement.p2(this, zero, one, one);
        zeroP3 = GroupElement.p3(this, zero, one, one, zero, false);
        zeroP3PrecomputedDouble = GroupElement.p3(this, zero, one, one, zero, true);
        zeroPrecomp = GroupElement.precomp(this, one, one, zero);
    }

    public EdDSAFiniteField getField() {
        return edDSAFiniteField;
    }

    public FieldElement getD() {
        return d;
    }

    public FieldElement get2D() {
        return d2;
    }

    public FieldElement getI() {
        return I;
    }

    public GroupElement getZero(final GroupElement.Representation repr) {
        switch (repr) {
        case P2:
            return zeroP2;
        case P3:
            return zeroP3;
        case P3PrecomputedDouble:
            return zeroP3PrecomputedDouble;
        case PRECOMP:
            return zeroPrecomp;
        default:
            return null;
        }
    }

    public GroupElement createPoint(final byte[] P, final boolean precompute) {
        final GroupElement ge = new GroupElement(this, P, precompute);
        return ge;
    }

    @Override
    public int hashCode() {
        return edDSAFiniteField.hashCode() ^
               d.hashCode() ^
               I.hashCode();
    }

    @Override
    public boolean equals(final Object o) {
        if (o == this)
            return true;
        if (!(o instanceof Curve))
            return false;
        final Curve c = (Curve) o;
        return edDSAFiniteField.equals(c.getField()) &&
               d.equals(c.getD()) &&
               I.equals(c.getI());
    }
}
