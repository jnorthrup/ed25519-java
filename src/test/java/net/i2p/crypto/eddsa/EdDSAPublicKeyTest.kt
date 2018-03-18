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

import java.security.spec.X509EncodedKeySpec

import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec

import org.junit.Test

/**
 * @author str4d
 */
class EdDSAPublicKeyTest {

    @Test
    @Throws(Exception::class)
    fun testDecodeAndEncode() {
        // Decode
        val encoded = X509EncodedKeySpec(TEST_PUBKEY)
        val keyIn = EdDSAPublicKey(encoded)

        // Encode
        val decoded = EdDSAPublicKeySpec(
                keyIn.a,
                keyIn.edDSAParameterSpec)
        val keyOut = EdDSAPublicKey(decoded)

        // Check
        assertThat(keyOut.encoded, `is`(equalTo(TEST_PUBKEY)))
    }

    @Test
    @Throws(Exception::class)
    fun testDecodeWithNullAndEncode() {
        // Decode
        val encoded = X509EncodedKeySpec(TEST_PUBKEY_NULL_PARAMS)
        val keyIn = EdDSAPublicKey(encoded)

        // Encode
        val decoded = EdDSAPublicKeySpec(
                keyIn.a,
                keyIn.edDSAParameterSpec)
        val keyOut = EdDSAPublicKey(decoded)

        // Check
        assertThat(keyOut.encoded, `is`(equalTo(TEST_PUBKEY)))
    }

    @Test
    @Throws(Exception::class)
    fun testReEncodeOldEncoding() {
        // Decode
        val encoded = X509EncodedKeySpec(TEST_PUBKEY_OLD)
        val keyIn = EdDSAPublicKey(encoded)

        // Encode
        val decoded = EdDSAPublicKeySpec(
                keyIn.a,
                keyIn.edDSAParameterSpec)
        val keyOut = EdDSAPublicKey(decoded)

        // Check
        assertThat(keyOut.encoded, `is`(equalTo(TEST_PUBKEY)))
    }

    companion object {
        /**
         * The example public key MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=
         * from https://tools.ietf.org/html/draft-ietf-curdle-pkix-04#section-10.1
         */
        private val TEST_PUBKEY = Utils.hexToBytes("302a300506032b657003210019bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1")

        private val TEST_PUBKEY_NULL_PARAMS = Utils.hexToBytes("302c300706032b6570050003210019bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1")
        private val TEST_PUBKEY_OLD = Utils.hexToBytes("302d300806032b65640a010103210019bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1")
    }
}
