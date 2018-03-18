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

import java.security.AccessController
import java.security.PrivilegedAction
import java.security.Provider
import java.security.Security

/**
 * A security [Provider] that can be registered via [Security.addProvider]
 *
 * @author str4d
 */
internal class EdDSASecurityProvider : Provider(PROVIDER_NAME, 0.2, "str4d $PROVIDER_NAME security provider wrapper") {
    init {

        AccessController.doPrivileged(PrivilegedAction<Any> {
            setup()
            null
        })
    }/* should match POM major.minor version */

    private fun setup() {
        // See https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/HowToImplAProvider.html
        put("KeyFactory." + EdDSAKey.KEY_ALGORITHM, "net.i2p.crypto.eddsa.KeyFactory")
        put("KeyPairGenerator." + EdDSAKey.KEY_ALGORITHM, "net.i2p.crypto.eddsa.KeyPairGenerator")
        put("Signature." + EdDSAEngine.SIGNATURE_ALGORITHM, "net.i2p.crypto.eddsa.EdDSAEngine")

        // OID Mappings
        // See section "Mapping from OID to name".
        // The Key* -> OID mappings correspond to the default algorithm in KeyPairGenerator.
        //
        // From draft-ieft-curdle-pkix-04:
        //   id-Ed25519   OBJECT IDENTIFIER ::= { 1 3 101 112 }
        put("Alg.Alias.KeyFactory.1.3.101.112", EdDSAKey.KEY_ALGORITHM)
        put("Alg.Alias.KeyFactory.OID.1.3.101.112", EdDSAKey.KEY_ALGORITHM)
        put("Alg.Alias.KeyPairGenerator.1.3.101.112", EdDSAKey.KEY_ALGORITHM)
        put("Alg.Alias.KeyPairGenerator.OID.1.3.101.112", EdDSAKey.KEY_ALGORITHM)
        put("Alg.Alias.Signature.1.3.101.112", EdDSAEngine.SIGNATURE_ALGORITHM)
        put("Alg.Alias.Signature.OID.1.3.101.112", EdDSAEngine.SIGNATURE_ALGORITHM)
    }

    companion object {

        private val PROVIDER_NAME = "EdDSA"
    }
}
