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

import java.security.InvalidAlgorithmParameterException
import java.security.InvalidParameterException
import java.security.KeyPair
import java.security.KeyPairGeneratorSpi
import java.security.SecureRandom
import java.security.spec.AlgorithmParameterSpec
import java.util.Hashtable
import java.util.Objects

import net.i2p.crypto.eddsa.spec.EdDSAGenParameterSpec
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec

/**
 * Default keysize is 256 (Ed25519)
 */
class KeyPairGenerator : KeyPairGeneratorSpi() {
    lateinit var edParams: EdDSAParameterSpec
    var random: SecureRandom? = null
    var initialized: Boolean = false

    override fun initialize(keysize: Int, random: SecureRandom) {
        val edParams = edParameters[Integer.valueOf(keysize)!!]
        Objects.requireNonNull<AlgorithmParameterSpec>(edParams)
        try {
            initialize(edParams, random)
        } catch (e: InvalidAlgorithmParameterException) {
            throw InvalidParameterException("key type not configurable.")
        }

    }

    @Throws(InvalidAlgorithmParameterException::class)
    override fun initialize(params: AlgorithmParameterSpec?, random: SecureRandom?) {
        if (params is EdDSAParameterSpec) {
            edParams = params
        } else if (params is EdDSAGenParameterSpec) {
            edParams = createNamedCurveSpec(params.name)
        } else
            throw InvalidAlgorithmParameterException("parameter object not a EdDSAParameterSpec")

        this.random = random
        initialized = true
    }

    override fun generateKeyPair(): KeyPair {
        if (!initialized)
            initialize(DEFAULT_KEYSIZE, SecureRandom())

        val seed = ByteArray(edParams.curve.edDSAFiniteField.b / 8)
        random!!.nextBytes(seed)

        val privKey = EdDSAPrivateKeySpec(seed, edParams)
        val pubKey = EdDSAPublicKeySpec(privKey.groupElement, edParams)

        return KeyPair(EdDSAPublicKey(pubKey), EdDSAPrivateKey(privKey))
    }

    /**
     * Create an EdDSANamedCurveSpec from the provided curve name. The current
     * implementation fetches the pre-created curve spec from a table.
     * @param curveName the EdDSA named curve.
     * @return the specification for the named curve.
     * @throws InvalidAlgorithmParameterException if the named curve is unknown.
     */
    protected fun createNamedCurveSpec(curveName: String): EdDSANamedCurveSpec {
        val spec = EdDSANamedCurveTable.getByName(curveName)
        Objects.requireNonNull(spec)
        return spec
    }

    companion object {
        val DEFAULT_KEYSIZE = 256

        val edParameters: Hashtable<Int, AlgorithmParameterSpec>

        init {
            edParameters = Hashtable()

            edParameters[Integer.valueOf(256)!!] = EdDSAGenParameterSpec(EdDSANamedCurveTable.ED_25519)
        }
    }
}
