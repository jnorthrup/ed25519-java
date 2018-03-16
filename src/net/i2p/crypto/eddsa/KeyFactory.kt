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

import java.security.InvalidKeyException
import java.security.Key
import java.security.KeyFactorySpi
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.KeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec

/**
 * @author str4d
 */
class KeyFactory : KeyFactorySpi() {

    @Throws(InvalidKeySpecException::class)
    override fun engineGeneratePrivate(keySpec: KeySpec): PrivateKey {
        if (keySpec is EdDSAPrivateKeySpec) {
            return EdDSAPrivateKey(keySpec)
        }
        if (keySpec is PKCS8EncodedKeySpec) {
            return EdDSAPrivateKey(keySpec)
        }
        throw InvalidKeySpecException("key spec not recognised: " + keySpec.javaClass)
    }

    @Throws(InvalidKeySpecException::class)
    override fun engineGeneratePublic(keySpec: KeySpec): PublicKey {
        if (keySpec is EdDSAPublicKeySpec) {
            return EdDSAPublicKey(keySpec)
        }
        if (keySpec is X509EncodedKeySpec) {
            return EdDSAPublicKey(keySpec)
        }
        throw InvalidKeySpecException("key spec not recognised: " + keySpec.javaClass)
    }

    @Throws(InvalidKeySpecException::class)
    override fun <T : KeySpec> engineGetKeySpec(key: Key, keySpec: Class<T>): T {
        if (keySpec.isAssignableFrom(EdDSAPublicKeySpec::class.java) && key is EdDSAPublicKey) {
            if (null != key.params) {
                return EdDSAPublicKeySpec(key.a, key.params) as T
            }
        } else if (keySpec.isAssignableFrom(EdDSAPrivateKeySpec::class.java) && key is EdDSAPrivateKey) {
            if (null != key.params) {
                return EdDSAPrivateKeySpec(key.seed, key.h, key.byteArr, key.aPrime, key.params) as T
            }
        }
        throw InvalidKeySpecException("not implemented yet $key $keySpec")
    }

    @Throws(InvalidKeyException::class)
    override fun engineTranslateKey(key: Key): Key {
        throw InvalidKeyException("No other EdDSA key providers known")
    }
}
