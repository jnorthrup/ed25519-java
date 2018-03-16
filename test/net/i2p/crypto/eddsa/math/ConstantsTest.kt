/**
 * EdDSA-Java by str4d
 *
 * To the extent possible under law, the person who associated CC0 with
 * EdDSA-Java has waived all copyright and related or neighboring rights
 * to EdDSA-Java.
 *
 * You should have received a copy of the CC0 legalcode along with this
 * work. If not, see <https:></https:>//creativecommons.org/publicdomain/zero/1.0/>.
 *
 */
package net.i2p.crypto.eddsa.math

import org.hamcrest.Matchers.equalTo
import org.hamcrest.Matchers.greaterThanOrEqualTo
import org.hamcrest.Matchers.`is`
import org.junit.Assert.assertThat
import org.junit.Assert.fail

import java.security.MessageDigest
import java.security.NoSuchAlgorithmException

import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable

import org.junit.Test

/**
 * Based on the tests in checkparams.py from the Python Ed25519 implementation.
 * @author str4d
 */
class ConstantsTest {

    @Test
    fun testb() {
        val b = curve.field.getb()
        assertThat(b, `is`(greaterThanOrEqualTo(10)))
        try {
            val h = MessageDigest.getInstance(ed25519.hashAlgorithm)
            assertThat(8 * h.digestLength, `is`(equalTo(2 * b)))
        } catch (e: NoSuchAlgorithmException) {
            fail(e.message)
        }

    }

    /*@Test
    public void testq() {
        FieldElement q = curve.getField().getQ();
        assertThat(TWO.modPow(q.subtractOne(), q), is(equalTo(ONE)));
        assertThat(q.mod(curve.getField().FOUR), is(equalTo(ONE)));
    }

    @Test
    public void testl() {
        int b = curve.getField().getb();
        BigInteger l = ed25519.getL();
        assertThat(TWO.modPow(l.subtract(BigInteger.ONE), l), is(equalTo(ONE)));
        assertThat(l, is(greaterThanOrEqualTo(BigInteger.valueOf(2).pow(b-4))));
        assertThat(l, is(lessThanOrEqualTo(BigInteger.valueOf(2).pow(b-3))));
    }

    @Test
    public void testd() {
        FieldElement q = curve.getField().getQ();
        FieldElement qm1 = q.subtractOne();
        assertThat(curve.getD().modPow(qm1.divide(curve.getField().TWO), q), is(equalTo(qm1)));
    }

    @Test
    public void testI() {
        FieldElement q = curve.getField().getQ();
        assertThat(curve.getI().modPow(curve.getField().TWO, q), is(equalTo(q.subtractOne())));
    }*/

    @Test
    fun testB() {
        val B = ed25519.b
        assertThat(B.isOnCurve(curve), `is`(true))
        //assertThat(B.scalarMultiply(new BigIntegerLittleEndianEncoding().encode(ed25519.getL(), curve.getField().getb()/8)), is(equalTo(P3_ZERO)));
    }

    companion object {
        private val ed25519 = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)
        private val curve = ed25519.curve

        private val ZERO = curve.field.ZERO
        private val ONE = curve.field.ONE
        internal val TWO = curve.field.TWO

        internal val P3_ZERO = GroupElement.p3(curve, ZERO, ONE, ONE, ZERO)
    }
}
