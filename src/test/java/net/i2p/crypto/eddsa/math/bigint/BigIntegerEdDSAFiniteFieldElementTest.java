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

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import net.i2p.crypto.eddsa.Utils;
import net.i2p.crypto.eddsa.math.EdDSAFiniteField;
import net.i2p.crypto.eddsa.math.FieldElement;
import net.i2p.crypto.eddsa.math.MathUtils;
import net.i2p.crypto.eddsa.math.AbstractEdDSAFiniteFieldElementTest;
import org.junit.Test;

/**
 * @author str4d
 *
 */
public class BigIntegerEdDSAFiniteFieldElementTest extends AbstractEdDSAFiniteFieldElementTest {
    static final byte[] BYTES_ZERO = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000");
    static final byte[] BYTES_ONE = Utils.hexToBytes("0100000000000000000000000000000000000000000000000000000000000000");
    static final byte[] BYTES_TEN = Utils.hexToBytes("0a00000000000000000000000000000000000000000000000000000000000000");

    static final EdDSAFiniteField ED_25519_ED_DSA_FINITE_FIELD = new EdDSAFiniteField(
            256, // b
            Utils.hexToBytes("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // q
            new BigIntegerLittleEndianEncoding().getEmptyEncoding());

    static final FieldElement ZERO = new BigIntegerFieldElement(ED_25519_ED_DSA_FINITE_FIELD, BigInteger.ZERO);
    static final FieldElement ONE = new BigIntegerFieldElement(ED_25519_ED_DSA_FINITE_FIELD, BigInteger.ONE);
    static final FieldElement TWO = new BigIntegerFieldElement(ED_25519_ED_DSA_FINITE_FIELD, BigInteger.valueOf(2L));

    protected FieldElement getRandomFieldElement() {
        BigInteger r;
        final Random rnd = new SecureRandom( );
        do {
            r = new BigInteger(255, rnd);
        } while (0 <= r.compareTo(getQ()));
        return new BigIntegerFieldElement(ED_25519_ED_DSA_FINITE_FIELD, r);
    }

    protected BigInteger toBigInteger(final FieldElement f) {
        return ((BigIntegerFieldElement)f).bi;
    }

    protected BigInteger getQ() {
        return MathUtils.getQ();
    }

    protected EdDSAFiniteField getEdDSAFiniteField() {
        return ED_25519_ED_DSA_FINITE_FIELD;
    }

    /**
     * Test method for {@link BigIntegerFieldElement#BigIntegerFieldElement(EdDSAFiniteField, BigInteger)}.
     */
    @Test
    public void testFieldElementBigInteger() {
        assertThat(new BigIntegerFieldElement(ED_25519_ED_DSA_FINITE_FIELD, BigInteger.ZERO).bi, is(BigInteger.ZERO));
        assertThat(new BigIntegerFieldElement(ED_25519_ED_DSA_FINITE_FIELD, BigInteger.ONE).bi, is(BigInteger.ONE));
        assertThat(new BigIntegerFieldElement(ED_25519_ED_DSA_FINITE_FIELD, BigInteger.valueOf(2L)).bi, is(BigInteger.valueOf(2L)));
    }

    /**
     * Test method for {@link FieldElement#toByteArray()}.
     */
    @Test
    public void testToByteArray() {
        final byte[] zero = ZERO.toByteArray();
        assertThat(Integer.valueOf(zero.length), is(equalTo(Integer.valueOf(BYTES_ZERO.length))));
        assertThat(zero, is(equalTo(BYTES_ZERO)));

        final byte[] one = ONE.toByteArray();
        assertThat(Integer.valueOf(one.length), is(equalTo(Integer.valueOf(BYTES_ONE.length))));
        assertThat(one, is(equalTo(BYTES_ONE)));

        final byte[] ten = new BigIntegerFieldElement(ED_25519_ED_DSA_FINITE_FIELD, BigInteger.TEN).toByteArray();
        assertThat(Integer.valueOf(ten.length), is(equalTo(Integer.valueOf(BYTES_TEN.length))));
        assertThat(ten, is(equalTo(BYTES_TEN)));
    }

    // region isNonZero

    protected FieldElement getZeroFieldElement() {
        return ZERO;
    }

    protected FieldElement getNonZeroFieldElement() {
        return TWO;
    }

    // endregion

    /**
     * Test method for {@link FieldElement#equals(java.lang.Object)}.
     */
    @Test
    public void testEqualsObject() {
        assertThat(new BigIntegerFieldElement(ED_25519_ED_DSA_FINITE_FIELD, BigInteger.ZERO), is(equalTo(ZERO)));
        assertThat(new BigIntegerFieldElement(ED_25519_ED_DSA_FINITE_FIELD, BigInteger.valueOf(1000L)), is(equalTo(new BigIntegerFieldElement(ED_25519_ED_DSA_FINITE_FIELD, BigInteger.valueOf(1000L)))));
        assertThat(ONE, is(not(equalTo(TWO))));
    }

}
