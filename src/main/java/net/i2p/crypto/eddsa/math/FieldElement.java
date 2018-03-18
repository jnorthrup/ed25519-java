package net.i2p.crypto.eddsa.math;

public interface FieldElement {
    /**
     * Encode a FieldElement in its $(b-1)$-bit encoding.
     * @return the $(b-1)$-bit encoding of this FieldElement.
     */
    byte[] toByteArray();

    boolean isNonZero();

    boolean isNegative();

    FieldElement add(FieldElement val);

    FieldElement addOne();

    FieldElement subtract(FieldElement val);

    FieldElement subtractOne();

    FieldElement negate();

    FieldElement divide(FieldElement val);

    FieldElement multiply(FieldElement val);

    FieldElement square();

    FieldElement squareAndDouble();

    FieldElement invert();

    FieldElement pow22523();

    FieldElement cmov(FieldElement fieldElement, int b);
}
