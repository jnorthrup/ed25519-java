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

import net.i2p.crypto.eddsa.Utils
import net.i2p.crypto.eddsa.math.EdDSAFiniteField
import net.i2p.crypto.eddsa.math.ScalarOps
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable

import org.junit.Test

/**
 * @author str4d
 */
class BigIntegerScalarOpsTest {

    /**
     * Test method for [net.i2p.crypto.eddsa.math.bigint.BigIntegerScalarOps.reduce].
     */
    @Test
    fun testReduce() {
        val sc = BigIntegerScalarOps(ED_25519_ED_DSA_FINITE_FIELD,
                BigInteger("5"))
        assertThat(sc.reduce(byteArrayOf(7.toByte())),
                `is`(equalTo(Utils.hexToBytes("0200000000000000000000000000000000000000000000000000000000000000"))))

        val sc2 = BigIntegerScalarOps(ED_25519_ED_DSA_FINITE_FIELD,
                BigInteger("7237005577332262213973186563042994240857116359379907606001950938285454250989"))
        // Example from test case 1
        val r = Utils.hexToBytes("b6b19cd8e0426f5983fa112d89a143aa97dab8bc5deb8d5b6253c928b65272f4044098c2a990039cde5b6a4818df0bfb6e40dc5dee54248032962323e701352d")
        assertThat(sc2.reduce(r), `is`(equalTo(Utils.hexToBytes("f38907308c893deaf244787db4af53682249107418afc2edc58f75ac58a07404"))))
    }

    /**
     * Test method for [net.i2p.crypto.eddsa.math.bigint.BigIntegerScalarOps.multiplyAndAdd].
     */
    @Test
    fun testMultiplyAndAdd() {
        val sc = BigIntegerScalarOps(ED_25519_ED_DSA_FINITE_FIELD,
                BigInteger("5"))
        assertThat(sc.multiplyAndAdd(byteArrayOf(7.toByte()), byteArrayOf(2.toByte()), byteArrayOf(5.toByte())),
                `is`(equalTo(Utils.hexToBytes("0400000000000000000000000000000000000000000000000000000000000000"))))

        val sc2 = BigIntegerScalarOps(ED_25519_ED_DSA_FINITE_FIELD,
                BigInteger("7237005577332262213973186563042994240857116359379907606001950938285454250989"))
        // Example from test case 1
        val h = Utils.hexToBytes("86eabc8e4c96193d290504e7c600df6cf8d8256131ec2c138a3e7e162e525404")
        val a = Utils.hexToBytes("307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f")
        val r = Utils.hexToBytes("f38907308c893deaf244787db4af53682249107418afc2edc58f75ac58a07404")
        val S = Utils.hexToBytes("5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
        assertThat(sc2.multiplyAndAdd(h, a, r), `is`(equalTo(S)))
    }

    companion object {

        private val ed25519 = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)
        private val ED_25519_ED_DSA_FINITE_FIELD = ed25519.curve.edDSAFiniteField
    }

}
