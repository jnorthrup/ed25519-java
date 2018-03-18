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
package net.i2p.crypto.eddsa.math.ed25519

import net.i2p.crypto.eddsa.math.*
import org.hamcrest.core.IsEqual
import org.junit.*

import java.math.BigInteger
import java.security.SecureRandom

/**
 * Tests rely on the BigInteger class.
 */
class Ed25519LittleEndianEncodingTest {

    @Test
    fun encodeReturnsCorrectByteArrayForSimpleFieldElements() {
        // Arrange:
        val t1 = IntArray(10)
        val t2 = IntArray(10)
        t2[0] = 1
        val fieldElement1 = Ed25519FieldElement(MathUtils.edDSAFiniteField, t1)
        val fieldElement2 = Ed25519FieldElement(MathUtils.edDSAFiniteField, t2)

        // Act:
        val bytes1 = MathUtils.edDSAFiniteField.encoding.encode(fieldElement1)
        val bytes2 = MathUtils.edDSAFiniteField.encoding.encode(fieldElement2)

        // Assert:
        Assert.assertThat(bytes1, IsEqual.equalTo(MathUtils.toByteArray(BigInteger.ZERO)))
        Assert.assertThat(bytes2, IsEqual.equalTo(MathUtils.toByteArray(BigInteger.ONE)))
    }

    @Test
    fun encodeReturnsCorrectByteArray() {
        var i = 0
        while (10000 > i) {
            // Arrange:
            val t = IntArray(10)
            var j = 0
            while (10 > j) {
                t[j] = random.nextInt(1 shl 28) - (1 shl 27)
                j++
            }
            val fieldElement1 = Ed25519FieldElement(MathUtils.edDSAFiniteField, t)
            val b = toBigInteger(t)

            // Act:
            val bytes = MathUtils.edDSAFiniteField.encoding.encode(fieldElement1)

            // Assert:
            Assert.assertThat(bytes, IsEqual.equalTo(MathUtils.toByteArray(b.mod(MathUtils.q))))
            i++
        }
    }

    @Test
    fun decodeReturnsCorrectFieldElementForSimpleByteArrays() {
        // Arrange:
        val bytes1 = ByteArray(32)
        val bytes2 = ByteArray(32)
        bytes2[0] = 1.toByte()

        // Act:
        val f1 = MathUtils.edDSAFiniteField.encoding.decode(bytes1) as Ed25519FieldElement
        val f2 = MathUtils.edDSAFiniteField.encoding.decode(bytes2) as Ed25519FieldElement
        val b1 = toBigInteger(f1.t)
        val b2 = toBigInteger(f2.t)

        // Assert:
        Assert.assertThat(b1, IsEqual.equalTo(BigInteger.ZERO))
        Assert.assertThat(b2, IsEqual.equalTo(BigInteger.ONE))
    }

    @Test
    fun decodeReturnsCorrectFieldElement() {
        var i = 0
        while (10000 > i) {
            // Arrange:
            val bytes = ByteArray(32)
            random.nextBytes(bytes)
            bytes[31] = (bytes[31]as Int  and 0x7f).toByte()
            val b1 = MathUtils.toBigInteger(bytes)

            // Act:
            val f = MathUtils.edDSAFiniteField.encoding.decode(bytes) as Ed25519FieldElement
            val b2 = toBigInteger(f.t).mod(MathUtils.q)

            // Assert:
            Assert.assertThat(b2, IsEqual.equalTo(b1))
            i++
        }
    }

    @Test
    fun isNegativeReturnsCorrectResult() {
        var i = 0
        while (10000 > i) {
            // Arrange:
            val t = IntArray(10)
            var j = 0
            while (10 > j) {
                t[j] = random.nextInt(1 shl 28) - (1 shl 27)
                j++
            }
            val isNegative = toBigInteger(t).mod(MathUtils.q).mod(BigInteger("2")) == BigInteger.ONE
            val f = Ed25519FieldElement(MathUtils.edDSAFiniteField, t)

            // Assert:
            Assert.assertThat(java.lang.Boolean.valueOf(MathUtils.edDSAFiniteField.encoding.isNegative(f)), IsEqual.equalTo(java.lang.Boolean.valueOf(isNegative)))
            i++
        }
    }

    companion object {

        private val random = SecureRandom()

        /**
         * Converts a 2^25.5 bit representation to a BigInteger.
         *
         *
         * Value: 2^exponents[0] * t[0] + 2^exponents[1] * t[1] + ... + 2^exponents[9] * t[9]
         *
         * @param t The 2^25.5 bit representation.
         * @return The BigInteger.
         */
        private fun toBigInteger(t: IntArray): BigInteger {
            var b = BigInteger.ZERO
            var i = 0
            while (10 > i) {
                b = b.add(BigInteger.ONE.multiply(BigInteger.valueOf(t[i].toLong())).shiftLeft(MathUtils.exponents[i]))
                i++
            }

            return b
        }
    }
}
