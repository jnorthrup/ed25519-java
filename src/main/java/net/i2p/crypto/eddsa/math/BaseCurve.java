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

/**
 * A twisted Edwards curve.
 * Points on the curve satisfy $-x^2 + y^2 = 1 + d x^2y^2$
 * @author str4d
 *
 */
@SuppressWarnings("ThisEscapedInObjectConstruction")
public class BaseCurve implements Curve {

    private final EdDSAFiniteField   edDSAFiniteField;
    private final FieldElement       d;
    private final FieldElement       d2;
    private final FieldElement       I;
    private final GroupElement       zeroP2;
    private final GroupElement       zeroP3;
    private final GroupElement       zeroP3PrecomputedDouble;
    private final GroupElement       zeroPrecomp;

    public BaseCurve(final EdDSAFiniteField edDSAFiniteField, final byte[] d, final FieldElement I) {
        this.edDSAFiniteField = edDSAFiniteField;
        this.d = edDSAFiniteField.fromByteArray(d);
        this.d2 = this.getD().add(this.getD());
        this.I = I;
        final FieldElement zero = edDSAFiniteField.ZERO;
        final FieldElement one = edDSAFiniteField.ONE;
        zeroP2 = GroupElement.p2(this, zero, one, one);
        zeroP3 = GroupElement.p3(this, zero, one, one, zero, false);
        zeroP3PrecomputedDouble = GroupElement.p3(this, zero, one, one, zero, true);
        zeroPrecomp = GroupElement.precomp(this, one, one, zero);
    }

    public GroupElement getZero(final GroupElement.Representation repr) {
        switch (repr) {
            case P2:
                return getZeroP2();
            case P3:
                return getZeroP3();
            case P3PrecomputedDouble:
                return getZeroP3PrecomputedDouble();
            case PRECOMP:
                return getZeroPrecomp();
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
        return getEdDSAFiniteField().hashCode() ^
                getD().hashCode() ^
                getI().hashCode();
    }

    @Override
    public boolean equals(final Object o) {
        if (o == this)
            return true;
        if (!(o instanceof BaseCurve))
            return false;
        final BaseCurve c = (BaseCurve) o;
        return getEdDSAFiniteField().equals(c.getEdDSAFiniteField()) &&
                getD().equals(c.getD()) &&
                getI().equals(c.getI());
    }

    public EdDSAFiniteField getEdDSAFiniteField() {
        return edDSAFiniteField;
    }

    public FieldElement getD() {
        return d;
    }

    public FieldElement getD2() {
        return d2;
    }

    public FieldElement getI() {
        return I;
    }

    public GroupElement getZeroP2() {
        return zeroP2;
    }

    public GroupElement getZeroP3() {
        return zeroP3;
    }

    public GroupElement getZeroP3PrecomputedDouble() {
        return zeroP3PrecomputedDouble;
    }

    public GroupElement getZeroPrecomp() {
        return zeroPrecomp;
    }
}
