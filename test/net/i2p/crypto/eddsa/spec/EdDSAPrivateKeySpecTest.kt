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
package net.i2p.crypto.eddsa.spec

import org.hamcrest.Matchers.*
import org.junit.Assert.*
import net.i2p.crypto.eddsa.Utils

import org.junit.Rule
import org.junit.Test
import org.junit.rules.ExpectedException

/**
 * @author str4d
 */
class EdDSAPrivateKeySpecTest {

    @Rule
    val exception = ExpectedException.none()

    /**
     * Test method for [net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec.EdDSAPrivateKeySpec].
     */
    @Test
    fun testEdDSAPrivateKeySpecFromSeed() {
        val key = EdDSAPrivateKeySpec(ZERO_SEED, ed25519)
        assertThat(key.seed, `is`(equalTo(ZERO_SEED)))
        assertThat(key.h, `is`(equalTo(ZERO_H)))
        assertThat(key.aPrime!!.toByteArray(), `is`(equalTo(ZERO_PK)))
    }

    @Test
    fun incorrectSeedLengthThrows() {
        exception.expect(IllegalArgumentException::class.java)
        exception.expectMessage("seed length is wrong")
        val key = EdDSAPrivateKeySpec(ByteArray(2), ed25519)
    }

    /**
     * Test method for [net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec.EdDSAPrivateKeySpec].
     */
    @Test
    fun testEdDSAPrivateKeySpecFromH() {
        val key = EdDSAPrivateKeySpec(ed25519, ZERO_H)
        assertThat(key.seed, `is`(nullValue()))
        assertThat(key.h, `is`(equalTo(ZERO_H)))
        assertThat(key.aPrime!!.toByteArray(), `is`(equalTo(ZERO_PK)))
    }

    @Test
    fun incorrectHashLengthThrows() {
        exception.expect(IllegalArgumentException::class.java)
        exception.expectMessage("hash length is wrong")
        val key = EdDSAPrivateKeySpec(ed25519, ByteArray(2))
    }

    companion object {
        private val ZERO_SEED = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000")
        private val ZERO_H = Utils.hexToBytes("5046adc1dba838867b2bbbfdd0c3423e58b57970b5267a90f57960924a87f1960a6a85eaa642dac835424b5d7c8d637c00408c7a73da672b7f498521420b6dd3")
        private val ZERO_PK = Utils.hexToBytes("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29")

        private val ed25519 = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)
    }
}
