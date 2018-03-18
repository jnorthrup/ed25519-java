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

import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec
import java.security.InvalidKeyException
import java.security.Key
import java.security.KeyFactorySpi
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.KeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Objects

import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec

/**
 * @author str4d
 */
class KeyFactory : KeyFactorySpi() {

    @Throws(InvalidKeySpecException::class)
    override fun engineGeneratePrivate(keySpec: KeySpec): PrivateKey {
        val ret: EdDSAPrivateKey
        if (keySpec is EdDSAPrivateKeySpec)
            ret = EdDSAPrivateKey(keySpec)
        else {
            assert(keySpec is PKCS8EncodedKeySpec) { "key spec not recognised: " + keySpec.javaClass }
            ret = EdDSAPrivateKey(keySpec as PKCS8EncodedKeySpec)
        }
        return ret
    }

    override fun engineGeneratePublic(keySpec: KeySpec): PublicKey {
        assert(keySpec is EdDSAPublicKeySpec) { "key spec not recognised: " + keySpec.javaClass }
        return EdDSAPublicKey(keySpec as EdDSAPublicKeySpec)
    }

    override fun <T : KeySpec> engineGetKeySpec(key: Key, keySpec: Class<T>): T {
        val ret: T
        if (!keySpec.isAssignableFrom(EdDSAPublicKeySpec::class.java) || key !is EdDSAPublicKey) {
            assert(keySpec.isAssignableFrom(EdDSAPrivateKeySpec::class.java) && key is EdDSAPrivateKey) { "not implemented yet $key $keySpec" }
            val k = key as EdDSAPrivateKey
            ret = EdDSAPrivateKeySpec(k.seed!!, k.hashOfTheSeed, k.privateKey, k.groupElement, k.edDSAParameterSpec) as T
        } else {
            Objects.requireNonNull<EdDSAParameterSpec>(key.edDSAParameterSpec)
            ret = EdDSAPublicKeySpec(key.a, key.edDSAParameterSpec) as T
        }
        return ret
    }

    @Throws(InvalidKeyException::class)
    override fun engineTranslateKey(key: Key): Key {
        throw InvalidKeyException("No other EdDSA key providers known")
    }
}
