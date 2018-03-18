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

import java.security.PrivateKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Arrays
import java.util.Objects

import net.i2p.crypto.eddsa.math.GroupElement
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec

/**
 * An EdDSA private key.
 *
 *
 * Warning: Private key encoding is based on the current curdle WG draft,
 * and is subject to change. See getEncoded().
 *
 *
 * For compatibility with older releases, decoding supports both the old and new
 * draft specifications. See decode().
 *
 *
 * Ref: https://tools.ietf.org/html/draft-ietf-curdle-pkix-04
 *
 *
 * Old Ref: https://tools.ietf.org/html/draft-josefsson-pkix-eddsa-04
 *
 * @author str4d
 */
class EdDSAPrivateKey(spec: EdDSAPrivateKeySpec) : EdDSAKey, PrivateKey {

    val seed: ByteArray?
    val hashOfTheSeed: ByteArray
    val privateKey: ByteArray
    val groupElement: GroupElement
    private val aByte: ByteArray
    override val edDSAParameterSpec: EdDSAParameterSpec

    init {
        seed = spec.seed
        hashOfTheSeed = spec.hashOfTheSeed
        privateKey = spec.privateKey
        groupElement = spec.groupElement
        aByte = groupElement.toByteArray()
        edDSAParameterSpec = spec.params
    }

    @Throws(InvalidKeySpecException::class)
    constructor(spec: PKCS8EncodedKeySpec) : this(EdDSAPrivateKeySpec(decode(spec.encoded),
            EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519))) {
    }

    override fun getAlgorithm(): String {
        return EdDSAKey.KEY_ALGORITHM
    }

    override fun getFormat(): String {
        return "PKCS#8"
    }

    /**
     * Returns the public key in its canonical encoding.
     *
     *
     * This implements the following specs:
     *  *
     * General encoding: https://tools.ietf.org/html/draft-ietf-curdle-pkix-04
     *  *
     * Key encoding: https://tools.ietf.org/html/rfc8032
     *
     *
     *
     * This encodes the seed. It will return null if constructed from
     * a spec which was directly constructed from H, in which case seed is null.
     *
     *
     * For keys in older formats, decoding and then re-encoding is sufficient to
     * migrate them to the canonical encoding.
     *
     * Relevant spec quotes:
     * <pre>
     * OneAsymmetricKey ::= SEQUENCE {
     * version Version,
     * privateKeyAlgorithm PrivateKeyAlgorithmIdentifier,
     * privateKey PrivateKey,
     * attributes [0] Attributes OPTIONAL,
     * ...,
     * [[2: publicKey [1] PublicKey OPTIONAL ]],
     * ...
     * }
     *
     * Version ::= INTEGER
     * PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
     * PrivateKey ::= OCTET STRING
     * PublicKey ::= OCTET STRING
     * Attributes ::= SET OF Attribute
    </pre> *
     *
     * <pre>
     * ... when encoding a OneAsymmetricKey object, the private key is wrapped
     * in a CurvePrivateKey object and wrapped by the OCTET STRING of the
     * 'privateKey' field.
     *
     * CurvePrivateKey ::= OCTET STRING
    </pre> *
     *
     * <pre>
     * AlgorithmIdentifier  ::=  SEQUENCE  {
     * algorithm   OBJECT IDENTIFIER,
     * parameters  ANY DEFINED BY algorithm OPTIONAL
     * }
     *
     * For all of the OIDs, the parameters MUST be absent.
    </pre> *
     *
     * <pre>
     * id-Ed25519   OBJECT IDENTIFIER ::= { 1 3 101 112 }
    </pre> *
     *
     * @return 48 bytes for Ed25519, null for other curves
     */
    override fun getEncoded(): ByteArray? {
        if (edDSAParameterSpec != EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519))
            return null
        if (null == seed)
            return null
        val totlen = 16 + seed.size
        val encoded = ByteArray(totlen)
        var idx = 0
        // sequence
        encoded[idx++] = 0x30.toByte()
        encoded[idx++] = (totlen - 2).toByte()
        // version
        encoded[idx++] = 0x02.toByte()
        encoded[idx++] = 1.toByte()
        // v1 - no public key included
        encoded[idx++] = 0.toByte()
        // Algorithm Identifier
        // sequence
        encoded[idx++] = 0x30.toByte()
        encoded[idx++] = 5.toByte()
        // OID
        // https://msdn.microsoft.com/en-us/library/windows/desktop/bb540809%28v=vs.85%29.aspx
        encoded[idx++] = 0x06.toByte()
        encoded[idx++] = 3.toByte()
        encoded[idx++] = (1 * 40 + 3).toByte()
        encoded[idx++] = 101.toByte()
        encoded[idx++] = OID_ED25519.toByte()
        // params - absent
        // PrivateKey
        encoded[idx++] = 0x04.toByte()  // octet string
        encoded[idx++] = (2 + seed.size).toByte()
        // CurvePrivateKey
        encoded[idx++] = 0x04.toByte()  // octet string
        encoded[idx++] = seed.size.toByte()
        // the key
        System.arraycopy(seed, 0, encoded, idx, seed.size)
        return encoded
    }

    /**
     * @return the public key
     */
    fun getaByte(): ByteArray {
        return aByte.clone()
    }

    override fun hashCode(): Int {
        return Arrays.hashCode(seed)
    }

    override fun equals(o: Any?): Boolean {
        return o === this || o is EdDSAPrivateKey && Arrays.equals(seed, o.seed) && edDSAParameterSpec == o.edDSAParameterSpec
    }

    companion object {

        // OID 1.3.101.xxx
        private val OID_OLD = 100
        private val OID_ED25519 = 112
        private val OID_BYTE = 11
        private val IDLEN_BYTE = 6

        /**
         * Extracts the private key bytes from the provided encoding.
         *
         *
         * This will decode data conforming to the current spec at
         * https://tools.ietf.org/html/draft-ietf-curdle-pkix-04
         * or as inferred from the old spec at
         * https://tools.ietf.org/html/draft-josefsson-pkix-eddsa-04.
         *
         *
         * Contrary to draft-ietf-curdle-pkix-04, it WILL accept a parameter value
         * of NULL, as it is required for interoperability with the default Java
         * keystore. Other implementations MUST NOT copy this behaviour from here
         * unless they also need to read keys from the default Java keystore.
         *
         *
         * This is really dumb for now. It does not use a general-purpose ASN.1 decoder.
         * See also getEncoded().
         *
         * @return 32 bytes for Ed25519, throws for other curves
         */
        @Throws(InvalidKeySpecException::class)
        private fun decode(d: ByteArray): ByteArray {
            try {
                //
                // Setup and OID check
                //
                var totlen = 48
                var idlen = 5
                val doid = d[OID_BYTE].toInt()
                when (doid) {
                    OID_OLD -> {
                        totlen = 49
                        idlen = 8
                    }
                    OID_ED25519 ->
                        // Detect parameter value of NULL
                        if (7 == d[IDLEN_BYTE].toInt()) {
                            totlen = 50
                            idlen = 7
                        }
                    else -> throw InvalidKeySpecException("unsupported key spec")
                }

                //
                // Pre-decoding check
                //
                if (d.size == totlen) {

                    //
                    // Decoding
                    //
                    var idx = 0
                    if (0x30 == d[idx++].toInt() &&
                            d[idx++].toInt() == totlen - 2 &&
                            0x02 == d[idx++].toInt() &&
                            1 == d[idx++].toInt() &&
                            0 == d[idx++].toInt() &&
                            0x30 == d[idx++].toInt() &&
                            d[idx++].toInt() == idlen &&
                            0x06 == d[idx++].toInt() &&
                            3 == d[idx++].toInt() &&
                            1 * 40 + 3 == d[idx++].toInt() &&
                            101 == d[idx++].toInt()) {
                        idx++ // OID, checked above
                        // parameters only with old OID
                        if (OID_OLD == doid) {
                            assert(0x0a == d[idx++].toInt() &&
                                    1 == d[idx++].toInt() &&
                                    1 == d[idx++].toInt()) { "unsupported key spec" }
                        } else {
                            // Handle parameter value of NULL
                            //
                            // Quote https://tools.ietf.org/html/draft-ietf-curdle-pkix-04 :
                            //   For all of the OIDs, the parameters MUST be absent.
                            //   Regardless of the defect in the original 1997 syntax,
                            //   implementations MUST NOT accept a parameters value of NULL.
                            //
                            // But Java's default keystore puts it in (when decoding as
                            // PKCS8 and then re-encoding to pass on), so we must accept it.
                            if (7 == idlen) {
                                assert(0x05 == d[idx++].toInt() && 0 == d[idx++].toInt()) { "unsupported key spec" }
                            }
                            // PrivateKey wrapping the CurvePrivateKey
                            assert(0x04 == d[idx++].toInt() && 34 == d[idx++].toInt()) { "unsupported key spec" }
                        }
                        if (0x04 == d[idx++].toInt() && 32 == d[idx++].toInt()) {
                            val rv = ByteArray(32)
                            System.arraycopy(d, idx, rv, 0, 32)
                            return rv
                        }
                        throw InvalidKeySpecException("unsupported key spec")
                    }
                    throw InvalidKeySpecException("unsupported key spec")
                }
                throw InvalidKeySpecException("invalid key spec length")
            } catch (ioobe: IndexOutOfBoundsException) {
                throw InvalidKeySpecException(ioobe)
            }

        }
    }
}
