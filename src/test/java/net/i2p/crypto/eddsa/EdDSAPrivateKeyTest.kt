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
package net.i2p.crypto.eddsa

import org.hamcrest.Matchers.*
import org.junit.Assert.*

import java.security.spec.PKCS8EncodedKeySpec

import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec

import org.junit.Test

/**
 * @author str4d
 */
class EdDSAPrivateKeyTest {

    @Test
    @Throws(Exception::class)
    fun testDecodeAndEncode() {
        // Decode
        val encoded = PKCS8EncodedKeySpec(TEST_PRIVKEY)
        val keyIn = EdDSAPrivateKey(encoded)

        // Encode
        val decoded = EdDSAPrivateKeySpec(
                keyIn.seed!!,
                keyIn.hashOfTheSeed,
                keyIn.privateKey,
                keyIn.groupElement,
                keyIn.edDSAParameterSpec)
        val keyOut = EdDSAPrivateKey(decoded)

        // Check
        assertThat(keyOut.encoded, `is`(equalTo(TEST_PRIVKEY)))
    }

    @Test
    @Throws(Exception::class)
    fun testDecodeWithNullAndEncode() {
        // Decode
        val encoded = PKCS8EncodedKeySpec(TEST_PRIVKEY_NULL_PARAMS)
        val keyIn = EdDSAPrivateKey(encoded)

        // Encode
        val decoded = EdDSAPrivateKeySpec(
                keyIn.seed!!,
                keyIn.hashOfTheSeed,
                keyIn.privateKey,
                keyIn.groupElement,
                keyIn.edDSAParameterSpec)
        val keyOut = EdDSAPrivateKey(decoded)

        // Check
        assertThat(keyOut.encoded, `is`(equalTo(TEST_PRIVKEY)))
    }

    @Test
    @Throws(Exception::class)
    fun testReEncodeOldEncoding() {
        // Decode
        val encoded = PKCS8EncodedKeySpec(TEST_PRIVKEY_OLD)
        val keyIn = EdDSAPrivateKey(encoded)

        // Encode
        val decoded = EdDSAPrivateKeySpec(
                keyIn.seed!!,
                keyIn.hashOfTheSeed,
                keyIn.privateKey,
                keyIn.groupElement,
                keyIn.edDSAParameterSpec)
        val keyOut = EdDSAPrivateKey(decoded)

        // Check
        assertThat(keyOut.encoded, `is`(equalTo(TEST_PRIVKEY)))
    }

    companion object {
        /**
         * The example private key MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
         * from https://tools.ietf.org/html/draft-ietf-curdle-pkix-04#section-10.3
         */
        private val TEST_PRIVKEY = Utils.hexToBytes("302e020100300506032b657004220420d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842")

        private val TEST_PRIVKEY_NULL_PARAMS = Utils.hexToBytes("3030020100300706032b6570050004220420d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842")
        private val TEST_PRIVKEY_OLD = Utils.hexToBytes("302f020100300806032b65640a01010420d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842")
    }
}
