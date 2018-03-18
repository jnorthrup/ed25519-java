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
package net.i2p.crypto.eddsa.math.bigint

import org.hamcrest.Matchers.*
import org.junit.Assert.*

import java.math.BigInteger
import java.security.SecureRandom
import java.util.Random

import net.i2p.crypto.eddsa.Utils
import net.i2p.crypto.eddsa.math.*
import org.junit.Test

/**
 * @author str4d
 */
class BigIntegerEdDSAFiniteFieldElementTest : AbstractEdDSAFiniteFieldElementTest() {

    protected override val randomFieldElement: FieldElement
        get() {
            var r: BigInteger
            val rnd = SecureRandom()
            do {
                r = BigInteger(255, rnd)
            } while (0 <= r.compareTo(q))
            return BigIntegerFieldElement(ED_25519_ED_DSA_FINITE_FIELD, r)
        }

    protected override val q: BigInteger
        get() = MathUtils.q

    protected override val edDSAFiniteField: EdDSAFiniteField
        get() = ED_25519_ED_DSA_FINITE_FIELD

    // region isNonZero

    protected override val zeroFieldElement: FieldElement
        get() = ZERO

    protected override val nonZeroFieldElement: FieldElement
        get() = TWO

    override fun toBigInteger(f: FieldElement): BigInteger {
        return (f as BigIntegerFieldElement).bi
    }

    /**
     * Test method for [BigIntegerFieldElement.BigIntegerFieldElement].
     */
    @Test
    fun testFieldElementBigInteger() {
        assertThat(BigIntegerFieldElement(ED_25519_ED_DSA_FINITE_FIELD, BigInteger.ZERO).bi, `is`(BigInteger.ZERO))
        assertThat(BigIntegerFieldElement(ED_25519_ED_DSA_FINITE_FIELD, BigInteger.ONE).bi, `is`(BigInteger.ONE))
        assertThat(BigIntegerFieldElement(ED_25519_ED_DSA_FINITE_FIELD, BigInteger.valueOf(2L)).bi, `is`(BigInteger.valueOf(2L)))
    }

    /**
     * Test method for [BaseFieldElement.toByteArray].
     */
    @Test
    fun testToByteArray() {
        val zero = ZERO.toByteArray()
        assertThat(Integer.valueOf(zero.size), `is`(equalTo(Integer.valueOf(BYTES_ZERO.size))))
        assertThat(zero, `is`(equalTo(BYTES_ZERO)))

        val one = ONE.toByteArray()
        assertThat(Integer.valueOf(one.size), `is`(equalTo(Integer.valueOf(BYTES_ONE.size))))
        assertThat(one, `is`(equalTo(BYTES_ONE)))

        val ten = BigIntegerFieldElement(ED_25519_ED_DSA_FINITE_FIELD, BigInteger.TEN).toByteArray()
        assertThat(Integer.valueOf(ten.size), `is`(equalTo(Integer.valueOf(BYTES_TEN.size))))
        assertThat(ten, `is`(equalTo(BYTES_TEN)))
    }

    // endregion

    /**
     * Test method for [BaseFieldElement.equals].
     */
    @Test
    fun testEqualsObject() {
        assertThat(BigIntegerFieldElement(ED_25519_ED_DSA_FINITE_FIELD, BigInteger.ZERO), `is`(equalTo<FieldElement>(ZERO)))
        assertThat(BigIntegerFieldElement(ED_25519_ED_DSA_FINITE_FIELD, BigInteger.valueOf(1000L)), `is`(equalTo(BigIntegerFieldElement(ED_25519_ED_DSA_FINITE_FIELD, BigInteger.valueOf(1000L)))))
        assertThat<FieldElement>(ONE, `is`(not(equalTo<FieldElement>(TWO))))
    }

    companion object {
        private val BYTES_ZERO = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000")
        private val BYTES_ONE = Utils.hexToBytes("0100000000000000000000000000000000000000000000000000000000000000")
        private val BYTES_TEN = Utils.hexToBytes("0a00000000000000000000000000000000000000000000000000000000000000")

        private val ED_25519_ED_DSA_FINITE_FIELD = EdDSAFiniteField(
                256, // b
                Utils.hexToBytes("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // q
                BigIntegerLittleEndianEncoding().emptyEncoding)

        private val ZERO = BigIntegerFieldElement(ED_25519_ED_DSA_FINITE_FIELD, BigInteger.ZERO)
        private val ONE = BigIntegerFieldElement(ED_25519_ED_DSA_FINITE_FIELD, BigInteger.ONE)
        private val TWO = BigIntegerFieldElement(ED_25519_ED_DSA_FINITE_FIELD, BigInteger.valueOf(2L))
    }

}
