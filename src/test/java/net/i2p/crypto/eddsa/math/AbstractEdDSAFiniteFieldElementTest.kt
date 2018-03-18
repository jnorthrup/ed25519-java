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

import org.hamcrest.core.*
import org.junit.*

import java.math.BigInteger

/**
 * Tests rely on the BigInteger class.
 */
abstract class AbstractEdDSAFiniteFieldElementTest {

    protected abstract val randomFieldElement: FieldElement
    protected abstract val q: BigInteger
    protected abstract val edDSAFiniteField: EdDSAFiniteField

    // region isNonZero

    protected abstract val zeroFieldElement: FieldElement
    protected abstract val nonZeroFieldElement: FieldElement
    protected abstract fun toBigInteger(f: FieldElement): BigInteger

    @Test
    fun isNonZeroReturnsFalseIfFieldElementIsZero() {
        // Act:
        val f = zeroFieldElement

        // Assert:
        Assert.assertThat(java.lang.Boolean.valueOf(f.isNonZero), IsEqual.equalTo(java.lang.Boolean.FALSE))
    }

    @Test
    fun isNonZeroReturnsTrueIfFieldElementIsNonZero() {
        // Act:
        val f = nonZeroFieldElement

        // Assert:
        Assert.assertThat(java.lang.Boolean.valueOf(f.isNonZero), IsEqual.equalTo(java.lang.Boolean.TRUE))
    }

    // endregion

    // region mod q arithmetic

    @Test
    fun addReturnsCorrectResult() {
        var i = 0
        while (1000 > i) {
            // Arrange:
            val f1 = randomFieldElement
            val f2 = randomFieldElement
            val b1 = toBigInteger(f1)
            val b2 = toBigInteger(f2)

            // Act:
            val f3 = f1.add(f2)
            val b3 = toBigInteger(f3).mod(q)

            // Assert:
            Assert.assertThat(b3, IsEqual.equalTo(b1.add(b2).mod(q)))
            i++
        }
    }

    @Test
    fun subtractReturnsCorrectResult() {
        var i = 0
        while (1000 > i) {
            // Arrange:
            val f1 = randomFieldElement
            val f2 = randomFieldElement
            val b1 = toBigInteger(f1)
            val b2 = toBigInteger(f2)

            // Act:
            val f3 = f1.subtract(f2)
            val b3 = toBigInteger(f3).mod(q)

            // Assert:
            Assert.assertThat(b3, IsEqual.equalTo(b1.subtract(b2).mod(q)))
            i++
        }
    }

    @Test
    fun negateReturnsCorrectResult() {
        var i = 0
        while (1000 > i) {
            // Arrange:
            val f1 = randomFieldElement
            val b1 = toBigInteger(f1)

            // Act:
            val f2 = f1.negate()
            val b2 = toBigInteger(f2).mod(q)

            // Assert:
            Assert.assertThat(b2, IsEqual.equalTo(b1.negate().mod(q)))
            i++
        }
    }

    @Test
    fun multiplyReturnsCorrectResult() {
        var i = 0
        while (1000 > i) {
            // Arrange:
            val f1 = randomFieldElement
            val f2 = randomFieldElement
            val b1 = toBigInteger(f1)
            val b2 = toBigInteger(f2)

            // Act:
            val f3 = f1.multiply(f2)
            val b3 = toBigInteger(f3).mod(q)

            // Assert:
            Assert.assertThat(b3, IsEqual.equalTo(b1.multiply(b2).mod(q)))
            i++
        }
    }

    @Test
    fun squareReturnsCorrectResult() {
        var i = 0
        while (1000 > i) {
            // Arrange:
            val f1 = randomFieldElement
            val b1 = toBigInteger(f1)

            // Act:
            val f2 = f1.square()
            val b2 = toBigInteger(f2).mod(q)

            // Assert:
            Assert.assertThat(b2, IsEqual.equalTo(b1.multiply(b1).mod(q)))
            i++
        }
    }

    @Test
    fun squareAndDoubleReturnsCorrectResult() {
        var i = 0
        while (1000 > i) {
            // Arrange:
            val f1 = randomFieldElement
            val b1 = toBigInteger(f1)

            // Act:
            val f2 = f1.squareAndDouble()
            val b2 = toBigInteger(f2).mod(q)

            // Assert:
            Assert.assertThat(b2, IsEqual.equalTo(b1.multiply(b1).multiply(BigInteger("2")).mod(q)))
            i++
        }
    }

    @Test
    fun invertReturnsCorrectResult() {
        var i = 0
        while (1000 > i) {
            // Arrange:
            val f1 = randomFieldElement
            val b1 = toBigInteger(f1)

            // Act:
            val f2 = f1.invert()
            val b2 = toBigInteger(f2).mod(q)

            // Assert:
            Assert.assertThat(b2, IsEqual.equalTo(b1.modInverse(q)))
            i++
        }
    }

    @Test
    fun pow22523ReturnsCorrectResult() {
        var i = 0
        while (1000 > i) {
            // Arrange:
            val f1 = randomFieldElement
            val b1 = toBigInteger(f1)

            // Act:
            val f2 = f1.pow22523()
            val b2 = toBigInteger(f2).mod(q)

            // Assert:
            Assert.assertThat(b2, IsEqual.equalTo(b1.modPow(BigInteger.ONE.shiftLeft(252).subtract(BigInteger("3")), q)))
            i++
        }
    }

    // endregion

    // region cmov

    @Test
    fun cmovReturnsCorrectResult() {
        val zero = zeroFieldElement
        val nz = nonZeroFieldElement
        val f = randomFieldElement

        Assert.assertThat(zero.cmov(nz, 0), IsEqual.equalTo(zero))
        Assert.assertThat(zero.cmov(nz, 1), IsEqual.equalTo(nz))

        Assert.assertThat(f.cmov(nz, 0), IsEqual.equalTo(f))
        Assert.assertThat(f.cmov(nz, 1), IsEqual.equalTo(nz))
    }

    // endregion

    // region hashCode / equals

    @Test
    fun equalsOnlyReturnsTrueForEquivalentObjects() {
        // Arrange:
        val f1 = randomFieldElement
        val f2 = edDSAFiniteField.encoding.decode(f1.toByteArray())
        val f3 = randomFieldElement
        val f4 = randomFieldElement

        // Assert:
        Assert.assertThat(f1, IsEqual.equalTo(f2))
        Assert.assertThat(f1, IsNot.not(IsEqual.equalTo(f3)))
        Assert.assertThat(f1, IsNot.not(IsEqual.equalTo(f4)))
        Assert.assertThat(f3, IsNot.not(IsEqual.equalTo(f4)))
    }

    @Test
    fun hashCodesAreEqualForEquivalentObjects() {
        // Arrange:
        val f1 = randomFieldElement
        val f2 = edDSAFiniteField.encoding.decode(f1.toByteArray())
        val f3 = randomFieldElement
        val f4 = randomFieldElement

        // Assert:
        Assert.assertThat(Integer.valueOf(f1.hashCode()), IsEqual.equalTo(Integer.valueOf(f2.hashCode())))
        Assert.assertThat(Integer.valueOf(f1.hashCode()), IsNot.not(IsEqual.equalTo(Integer.valueOf(f3.hashCode()))))
        Assert.assertThat(Integer.valueOf(f1.hashCode()), IsNot.not(IsEqual.equalTo(Integer.valueOf(f4.hashCode()))))
        Assert.assertThat(Integer.valueOf(f3.hashCode()), IsNot.not(IsEqual.equalTo(Integer.valueOf(f4.hashCode()))))
    }

    // endregion
}
