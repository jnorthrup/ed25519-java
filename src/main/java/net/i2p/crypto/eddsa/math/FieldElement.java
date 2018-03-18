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
import java.util.Objects;

/**
 * Note: concrete subclasses must implement hashCode() and equals()
 */
public abstract class FieldElement  {

    protected final EdDSAFiniteField f;

    protected FieldElement(final EdDSAFiniteField f) {
        assert null != f : "field cannot be null";
        this.f = f;
    }

    /**
     * Encode a FieldElement in its $(b-1)$-bit encoding.
     * @return the $(b-1)$-bit encoding of this FieldElement.
     */
    public byte[] toByteArray() {
        return f.getEncoding().encode(this);
    }

    public abstract boolean isNonZero();

    public boolean isNegative() {
        return f.getEncoding().isNegative(this);
    }

    public abstract FieldElement add(FieldElement val);

    public FieldElement addOne() {
        return add(f.ONE);
    }

    public abstract FieldElement subtract(FieldElement val);

    public FieldElement subtractOne() {
        return subtract(f.ONE);
    }

    public abstract FieldElement negate();

    public FieldElement divide(final FieldElement val) {
        return multiply(val.invert());
    }

    public abstract FieldElement multiply(FieldElement val);

    public abstract FieldElement square();

    public abstract FieldElement squareAndDouble();

    public abstract FieldElement invert();

    public abstract FieldElement pow22523();

    public abstract FieldElement cmov(FieldElement val, final int b);

    // Note: concrete subclasses must implement hashCode() and equals()
}
