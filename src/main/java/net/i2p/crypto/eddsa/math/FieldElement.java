package net.i2p.crypto.eddsa.math;

public interface FieldElement {
    abstract byte[] toByteArray();

    boolean isNonZero();

    abstract boolean isNegative();

    FieldElement add(FieldElement element);

    abstract FieldElement addOne();

    FieldElement subtract(FieldElement fieldElement);

    abstract FieldElement subtractOne();

    FieldElement negate();

    abstract FieldElement divide(FieldElement fieldElement);

    FieldElement multiply(FieldElement fieldElement);

    FieldElement square();

    FieldElement squareAndDouble();

    FieldElement invert();

    FieldElement pow22523();

    FieldElement cmov(FieldElement fieldElement, int b);

    EdDSAFiniteField getEdDSAFiniteField();
}
