package net.i2p.crypto.eddsa.math;

public interface Curve {
    GroupElement get(Representation repr);

    GroupElement createPoint(byte[] P, boolean precompute);

    @Override
    int hashCode();

    @Override
    boolean equals(Object o);

    EdDSAFiniteField getEdDSAFiniteField();

    FieldElement getD();

    FieldElement getD2();

    FieldElement getI();

    GroupElement getZeroP2();

    GroupElement getZeroP3();

    GroupElement getZeroP3PrecomputedDouble();

    GroupElement getZeroPrecomp();
}
