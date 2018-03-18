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
 * Note: concrete subclasses must implement hashCode() and equals()
 */
public abstract class BaseFieldElement implements FieldElement {

    private final EdDSAFiniteField edDSAFiniteField;

    protected BaseFieldElement(final EdDSAFiniteField edDSAFiniteField) {
        assert null != edDSAFiniteField : "field cannot be null";
        this.edDSAFiniteField = edDSAFiniteField;
    }

    /**
     * Encode a FieldElement in its $(b-1)$-bit encoding.
     * @return the $(b-1)$-bit encoding of this FieldElement.
     */
    @Override
    public byte[] toByteArray() {
        return getEdDSAFiniteField().getEncoding().encode(this);
    }

    @Override
    public boolean isNegative() {
        return getEdDSAFiniteField().getEncoding().isNegative(this);
    }

    @Override
    public FieldElement addOne() {
        return add(getEdDSAFiniteField().ONE);
    }

    @Override
    public FieldElement subtractOne() {
        return subtract(getEdDSAFiniteField().ONE);
    }

    @Override
    public FieldElement divide(final FieldElement fieldElement) {
        return multiply(fieldElement).invert() ;
    }

    @Override
    public EdDSAFiniteField getEdDSAFiniteField() {
        return edDSAFiniteField;
    }

    // Note: concrete subclasses must implement hashCode() and equals()
}
