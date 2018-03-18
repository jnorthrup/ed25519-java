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
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.Future;

import static net.i2p.crypto.eddsa.math.GroupElement.*;

/**
 * A twisted Edwards curve.
 * Points on the curve satisfy $-x^2 + y^2 = 1 + d x^2y^2$
 *
 * @author str4d
 */
@SuppressWarnings("ThisEscapedInObjectConstruction")
public class BaseCurve implements Curve {

    private final EdDSAFiniteField edDSAFiniteField;
    private final FieldElement d;
    private final FieldElement d2;
    private final FieldElement I;

    EnumMap<Representation, Future<GroupElement>> facade  ;
    public BaseCurve(final EdDSAFiniteField edDSAFiniteField, final byte[] d, final FieldElement I) {
        this.edDSAFiniteField = edDSAFiniteField;
        this.d = edDSAFiniteField.fromByteArray(d);
        this.d2 = this.getD().add(this.getD());
        this.I = I;
        final FieldElement zero = edDSAFiniteField.ZERO;
        final FieldElement one = edDSAFiniteField.ONE;
        ForkJoinPool forkJoinPool = ForkJoinPool.commonPool();
        Curve c = this;

        facade = new EnumMap<Representation, Future<GroupElement>>(Representation.class) {
            {
                put(Representation.P2,       forkJoinPool.submit(() -> p2(c, zero, one, one)));
                put(Representation.P3,       forkJoinPool.submit(() -> p3(c, zero, one, one, zero, false)));
                put(Representation.P3PrecomputedDouble,forkJoinPool.submit( () -> p3(c, zero, one, one, zero, true)));
                put(Representation.PRECOMP, forkJoinPool.submit( () ->precomp(c, one, one, zero)));
            }
        };
    };


    @Override
    public GroupElement getZero(final Representation repr) {
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

    @Override
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
        if (!(o instanceof Curve))
            return false;
        final Curve c = (Curve) o;
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
    public GroupElement getZeroP2() {
        try {
            return   facade .get( Representation.P2 ).get();
        } catch (InterruptedException e) {
            e.printStackTrace();
        } catch (ExecutionException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public GroupElement getZeroP3() { ; try {
            return   facade .get( Representation.P3 ).get();
        } catch (InterruptedException e) {
            e.printStackTrace();
        } catch (ExecutionException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public GroupElement getZeroP3PrecomputedDouble() {
        ; try {
            return   facade .get( Representation.P3PrecomputedDouble ).get();
        } catch (InterruptedException e) {
            e.printStackTrace();
        } catch (ExecutionException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public GroupElement getZeroPrecomp() {    ; try {
        return   facade .get( Representation.PRECOMP ).get();
    } catch (InterruptedException e) {
        e.printStackTrace();
    } catch (ExecutionException e) {
        e.printStackTrace();
    }
        return null;
    }
}
