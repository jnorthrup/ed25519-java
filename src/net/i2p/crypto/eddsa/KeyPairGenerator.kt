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

import net.i2p.crypto.eddsa.spec.*

import java.security.*
import java.security.spec.AlgorithmParameterSpec
import java.util.LinkedHashMap

/**
 * Default keysize is 256 (Ed25519)
 */
class KeyPairGenerator : KeyPairGeneratorSpi() {
    private var edParams: EdDSAParameterSpec? = null
    private var random: SecureRandom? = null
    private var initialized: Boolean = false

    override fun initialize(keysize: Int, random: SecureRandom) {
        val edParams = edParameters[Integer.valueOf(keysize)] ?: throw InvalidParameterException("unknown key type.")
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

        val seed = ByteArray(edParams!!.curve.field.getb() / 8)
        random!!.nextBytes(seed)

        val privKey = EdDSAPrivateKeySpec(seed, edParams!!)
        val pubKey = EdDSAPublicKeySpec(privKey.aPrime!!, edParams)

        return KeyPair(EdDSAPublicKey(pubKey), EdDSAPrivateKey(privKey))
    }

    companion object {
        private val DEFAULT_KEYSIZE = 256

        private val edParameters: MutableMap<Int, AlgorithmParameterSpec>

        init {
            edParameters = LinkedHashMap()

            edParameters[Integer.valueOf(256)] = EdDSAGenParameterSpec(EdDSANamedCurveTable.ED_25519)
        }

        /**
         * Create an EdDSANamedCurveSpec from the provided curve name. The current
         * implementation fetches the pre-created curve spec from a table.
         * @param curveName the EdDSA named curve.
         * @return the specification for the named curve.
         * @throws InvalidAlgorithmParameterException if the named curve is unknown.
         */
        @Throws(InvalidAlgorithmParameterException::class)
        private fun createNamedCurveSpec(curveName: String): EdDSANamedCurveSpec {
            return EdDSANamedCurveTable.getByName(curveName)
                    ?: throw InvalidAlgorithmParameterException("unknown curve name: $curveName")
        }
    }
}
