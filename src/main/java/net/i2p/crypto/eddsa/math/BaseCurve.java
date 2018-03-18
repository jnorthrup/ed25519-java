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

import net.i2p.crypto.eddsa.math.GroupElement.*;

import java.util.EnumMap;
import java.util.concurrent.Callable;
import java.util.function.Function;

import static net.i2p.crypto.eddsa.math.GroupElement.*;

/**
 * A twisted Edwards curve.
 * Points on the curve satisfy $-x^2 + y^2 = 1 + d x^2y^2$
 *
 * @author str4d
 */
@SuppressWarnings("ThisEscapedInObjectConstruction")
public class BaseCurve implements Curve {

    final EnumMap<Representation, Callable<GroupElement>> source;
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
        source = new EnumMap<Representation, Callable<GroupElement>>(Representation.class) {
            {
                put(Representation.P2, () -> p2(c, zero, one, one));
                put(Representation.P3, () -> p3(c, zero, one, one, zero, false));
                put(Representation.P3PrecomputedDouble, () -> p3(c, zero, one, one, zero, true));
                put(Representation.PRECOMP, () -> precomp(c, one, one, zero));
            }
        };
    }


    @Override
    public GroupElement createPoint(byte[] P, boolean precompute) {
        GroupElement ge = new GroupElement(this, P, precompute);
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
        return facade.computeIfAbsent(Representation, new Function<Representation, GroupElement>() {
            @Override
            public GroupElement apply(Representation representation) {
                try {
                    return source.get(Representation).call();
                } catch (Exception e) {
                    throw new Error(e);
                }
            }
        });
    }
}
