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

import net.i2p.crypto.eddsa.Utils
import net.i2p.crypto.eddsa.math.*
import org.hamcrest.core.IsEqual
import org.junit.*

import java.math.BigInteger

import org.hamcrest.Matchers.equalTo
import org.hamcrest.Matchers.`is`
import org.junit.Assert.assertThat

/**
 * @author str4d
 * Additional tests by the NEM project team.
 */
class Ed25519ScalarOpsTest {

    /**
     * Test method for [net.i2p.crypto.eddsa.math.bigint.BigIntegerScalarOps.reduce].
     */
    @Test
    fun testReduce() {
        // Example from test case 1
        val r = Utils.hexToBytes("b6b19cd8e0426f5983fa112d89a143aa97dab8bc5deb8d5b6253c928b65272f4044098c2a990039cde5b6a4818df0bfb6e40dc5dee54248032962323e701352d")
        assertThat(scalarOps.reduce(r), `is`(equalTo(Utils.hexToBytes("f38907308c893deaf244787db4af53682249107418afc2edc58f75ac58a07404"))))
    }

    @Test
    fun reduceReturnsExpectedResult() {
        var i = 0
        while (1000 > i) {
            // Arrange:
            val bytes = getRandomByteArray(64)

            // Act:
            val reduced1 = scalarOps.reduce(bytes)
            val reduced2 = reduceModGroupOrder(bytes)

            // Assert:
            Assert.assertThat(Integer.valueOf(MathUtils.toBigInteger(reduced1).compareTo(groupOrder)), IsEqual.equalTo(Integer.valueOf(-1)))
            Assert.assertThat(Integer.valueOf(MathUtils.toBigInteger(reduced1).compareTo(BigInteger("-1"))), IsEqual.equalTo(Integer.valueOf(1)))
            Assert.assertThat(reduced1, IsEqual.equalTo(reduced2))
            i++
        }
    }

    /**
     * Test method for [net.i2p.crypto.eddsa.math.bigint.BigIntegerScalarOps.multiplyAndAdd].
     */
    @Test
    fun testMultiplyAndAdd() {
        // Example from test case 1
        val h = Utils.hexToBytes("86eabc8e4c96193d290504e7c600df6cf8d8256131ec2c138a3e7e162e525404")
        val a = Utils.hexToBytes("307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f")
        val r = Utils.hexToBytes("f38907308c893deaf244787db4af53682249107418afc2edc58f75ac58a07404")
        val S = Utils.hexToBytes("5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
        assertThat(scalarOps.multiplyAndAdd(h, a, r), `is`(equalTo(S)))
    }

    @Test
    fun multiplyAndAddReturnsExpectedResult() {
        var i = 0
        while (1000 > i) {
            // Arrange:
            val bytes1 = getRandomByteArray(32)
            val bytes2 = getRandomByteArray(32)
            val bytes3 = getRandomByteArray(32)

            // Act:
            val result1 = scalarOps.multiplyAndAdd(bytes1, bytes2, bytes3)
            val result2 = multiplyAndAddModGroupOrder(bytes1, bytes2, bytes3)

            // Assert:
            Assert.assertThat(Integer.valueOf(MathUtils.toBigInteger(result1).compareTo(groupOrder)), IsEqual.equalTo(Integer.valueOf(-1)))
            Assert.assertThat(Integer.valueOf(MathUtils.toBigInteger(result1).compareTo(BigInteger("-1"))), IsEqual.equalTo(Integer.valueOf(1)))
            Assert.assertThat(result1, IsEqual.equalTo(result2))
            i++
        }
    }

    companion object {

        private val scalarOps = Ed25519ScalarOps()

        private fun getRandomByteArray(length: Int): ByteArray {
            val bytes = ByteArray(length)
            MathUtils.random.nextBytes(bytes)
            return bytes
        }

        /**
         * Calculates (a * b + c) mod group order and returns the result.
         *
         *
         * a, b and c are given in 2^8 bit representation.
         *
         * @param a The first integer.
         * @param b The second integer.
         * @param c The third integer.
         * @return The mod group order reduced result.
         */
        private fun multiplyAndAddModGroupOrder(a: ByteArray, b: ByteArray, c: ByteArray): ByteArray {
            val result = MathUtils.toBigInteger(a).multiply(MathUtils.toBigInteger(b)).add(MathUtils.toBigInteger(c)).mod(MathUtils.groupOrder)
            return MathUtils.toByteArray(result)
        }

        /**
         * Reduces an integer in 2^8 bit representation modulo the group order and returns the result.
         *
         * @param bytes The integer in 2^8 bit representation.
         * @return The mod group order reduced integer.
         */
        private fun reduceModGroupOrder(bytes: ByteArray): ByteArray {
            val b = MathUtils.toBigInteger(bytes).mod(MathUtils.groupOrder)
            return MathUtils.toByteArray(b)
        }

        /**
         * Gets group order = 2^252 + 27742317777372353535851937790883648493 as BigInteger.
         */
        private val groupOrder: BigInteger
            get() = MathUtils.groupOrder
    }
}
