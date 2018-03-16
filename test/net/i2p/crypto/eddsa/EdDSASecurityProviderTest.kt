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

import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.NoSuchProviderException
import java.security.Security
import java.security.Signature

import net.i2p.crypto.eddsa.EdDSASecurityProvider

import org.junit.Rule
import org.junit.Test
import org.junit.rules.ExpectedException

/**
 * @author str4d
 */
class EdDSASecurityProviderTest {

    @Rule
    val exception = ExpectedException.none()

    @Test
    @Throws(Exception::class)
    fun canGetInstancesWhenProviderIsPresent() {
        Security.addProvider(EdDSASecurityProvider())

        val keyGen = KeyPairGenerator.getInstance("EdDSA", "EdDSA")
        val keyFac = KeyFactory.getInstance("EdDSA", "EdDSA")
        val sgr = Signature.getInstance("NONEwithEdDSA", "EdDSA")

        Security.removeProvider("EdDSA")
    }

    @Test
    @Throws(Exception::class)
    fun cannotGetInstancesWhenProviderIsNotPresent() {
        exception.expect(NoSuchProviderException::class.java)
        val keyGen = KeyPairGenerator.getInstance("EdDSA", "EdDSA")
    }
}
