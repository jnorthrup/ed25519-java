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

import java.util.EnumMap;
import java.util.concurrent.Callable;

/**
 * A twisted Edwards curve.
 * Points on the curve satisfy $-x^2 + y^2 = 1 + d x^2y^2$
 *
 * @author str4d
 */
@SuppressWarnings("ThisEscapedInObjectConstruction")
public class BaseCurve implements Curve {

    final EnumMap<Representation, Callable<? extends GroupElement>> source;
    final EnumMap<Representation, GroupElement> facade = new EnumMap<>(Representation.class);
    private final EdDSAFiniteField edDSAFiniteField;
    private final FieldElement d;
    private final FieldElement d2;
    private final FieldElement I;

    public BaseCurve(EdDSAFiniteField edDSAFiniteField, byte[] d, FieldElement I) {
        this.edDSAFiniteField = edDSAFiniteField;
        this.d = edDSAFiniteField.fromByteArray(d);
        d2 = getD().add(getD());
        this.I = I;
        FieldElement zero = edDSAFiniteField.ZERO;
        FieldElement one = edDSAFiniteField.ONE;
        Curve c = this;

        //        this is cost of an array to lazy biootstrap the 4 used curves
        source = new EnumMap<Representation, Callable<?extends GroupElement>>(Representation.class) {
            {
                put(Representation.P2, () -> new P2GroupElement(c, zero, one, one));
                put(Representation.P3, () -> new P3GroupElement(c, zero, one, one, zero));
                put(Representation.P3PrecomputedDouble, () -> new P3PrecomputedDoubleGroupElement(c, zero, one));
                put(Representation.PRECOMP, () -> new PrecompGroupElement(c, one, one, zero));
            }
        };
    }


    @Override
    public GroupElement createPoint(byte[] P, boolean precompute) {assert precompute;
        GroupElement ge = new P3PreGroupElement(this, P );
        return ge;
    }

    @Override
    public int hashCode() {
        return getEdDSAFiniteField().hashCode() ^
                getD().hashCode() ^
                getI().hashCode();
    }

    @Override
    public boolean equals(Object o) {
        if (o == this)
            return true;
        if (!(o instanceof Curve))
            return false;
        Curve c = (Curve) o;
        return getEdDSAFiniteField().equals(c.getEdDSAFiniteField()) &&
                getD().equals(c.getD()) &&
                getI().equals(c.getI());
    }

    @Override
    public EdDSAFiniteField getEdDSAFiniteField() {
        return edDSAFiniteField;
    }

    @Override
    public FieldElement getD() {
        return d;
    }

    @Override
    public FieldElement getD2() {
        return d2;
    }

    @Override
    public FieldElement getI() {
        return I;
    }

    @Override
    public GroupElement getZeroP2() throws RuntimeException {
        return facade.computeIfAbsent(Representation.P2, this::get);

    }

    @Override
    public GroupElement getZeroP3() {
        return facade.computeIfAbsent(Representation.P3, this::get);

    }

    @Override
    public GroupElement getZeroP3PrecomputedDouble() {
        return facade.computeIfAbsent(Representation.P3PrecomputedDouble, this::get);
    }

    @Override
    public GroupElement getZeroPrecomp() {
        return facade.computeIfAbsent(Representation.PRECOMP, this::get);

    }

    public GroupElement get(Representation Representation) {
        return facade.computeIfAbsent(Representation, representation -> {
            try {
                return source.get(Representation).call();
            } catch (Exception e) {
                throw new Error(e);
            }
        });
    }

}
