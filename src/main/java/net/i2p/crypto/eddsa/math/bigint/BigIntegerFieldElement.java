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
package net.i2p.crypto.eddsa.math.bigint;

import java.io.Serializable;
import java.math.BigInteger;

import net.i2p.crypto.eddsa.math.EdDSAFiniteField;
import net.i2p.crypto.eddsa.math.FieldElement;

/**
 * A particular element of the field \Z/(2^255-19).
 * @author str4d
 *
 */
public class BigIntegerFieldElement extends FieldElement  {

    /**
     * Variable is package private for encoding.
     */
    final BigInteger bi;

    public BigIntegerFieldElement(final EdDSAFiniteField f, final BigInteger bi) {
        super(f);
        this.bi = bi;
    }

    public boolean isNonZero() {
        return !bi.equals(BigInteger.ZERO);
    }

    public FieldElement add(final FieldElement val) {
        return new BigIntegerFieldElement(f, bi.add(((BigIntegerFieldElement)val).bi)).mod(f.getQ());
    }

    @Override
    public FieldElement addOne() {
        return new BigIntegerFieldElement(f, bi.add(BigInteger.ONE)).mod(f.getQ());
    }

    public FieldElement subtract(final FieldElement val) {
        return new BigIntegerFieldElement(f, bi.subtract(((BigIntegerFieldElement)val).bi)).mod(f.getQ());
    }

    @Override
    public FieldElement subtractOne() {
        return new BigIntegerFieldElement(f, bi.subtract(BigInteger.ONE)).mod(f.getQ());
    }

    public FieldElement negate() {
        return f.getQ().subtract(this);
    }

    @Override
    public FieldElement divide(final FieldElement val) {
        return divide(((BigIntegerFieldElement)val).bi);
    }

    public FieldElement divide(final BigInteger val) {
        return new BigIntegerFieldElement(f, bi.divide(val)).mod(f.getQ());
    }

    public FieldElement multiply(final FieldElement val) {
        return new BigIntegerFieldElement(f, bi.multiply(((BigIntegerFieldElement)val).bi)).mod(f.getQ());
    }

    public FieldElement square() {
        return multiply(this);
    }

    public FieldElement squareAndDouble() {
        final FieldElement sq = square();
        return sq.add(sq);
    }

    public FieldElement invert() {
        // Euler's theorem
        //return modPow(edDSAFiniteField.getQm2(), edDSAFiniteField.getQ());
        return new BigIntegerFieldElement(f, bi.modInverse(((BigIntegerFieldElement)f.getQ()).bi));
    }

    public FieldElement mod(final FieldElement m) {
        return new BigIntegerFieldElement(f, bi.mod(((BigIntegerFieldElement)m).bi));
    }

    public FieldElement modPow(final FieldElement e, final FieldElement m) {
        return new BigIntegerFieldElement(f, bi.modPow(((BigIntegerFieldElement)e).bi, ((BigIntegerFieldElement)m).bi));
    }

    public FieldElement pow(final FieldElement e){
        return modPow(e, f.getQ());
    }

    public FieldElement pow22523(){
        return pow(f.getQm5d8());
    }

    @Override
    public FieldElement cmov(final FieldElement val, final int b) {
        // Not constant-time, but it doesn't really matter because none of the underlying BigInteger operations
        // are either, so there's not much point in trying hard here ...
        return 0 == b ? this : val;
    }

    @Override
    public int hashCode() {
        return bi.hashCode();
    }

    @Override
    public boolean equals(final Object obj) {
        if (!(obj instanceof BigIntegerFieldElement))
            return false;
        final BigIntegerFieldElement fe = (BigIntegerFieldElement) obj;
        return bi.equals(fe.bi);
    }

    @Override
    public String toString() {
        return "[BigIntegerFieldElement val="+bi+"]";
    }
}
