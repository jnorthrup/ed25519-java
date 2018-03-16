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

import java.security.PublicKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.X509EncodedKeySpec
import java.util.Arrays

import net.i2p.crypto.eddsa.math.GroupElement
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec

/**
 * An EdDSA public key.
 *
 *
 * Warning: Public key encoding is is based on the current curdle WG draft,
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
class EdDSAPublicKey(spec: EdDSAPublicKeySpec) : EdDSAKey, PublicKey {
    val a: GroupElement
    val negativeA: GroupElement
    private val Abyte: ByteArray
    override val params: EdDSAParameterSpec

    val abyte: ByteArray
        get() = Abyte.clone().clone()

    init {
        a = spec.a
        negativeA = spec.negativeA
        Abyte = a.toByteArray()
        params = spec.params
    }

    @Throws(InvalidKeySpecException::class)
    constructor(spec: X509EncodedKeySpec) : this(EdDSAPublicKeySpec(decode(spec.encoded),
            EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519))) {
    }

    override fun getAlgorithm(): String {
        return EdDSAKey.KEY_ALGORITHM
    }

    override fun getFormat(): String {
        return "X.509"
    }

    /**
     * Returns the public key in its canonical encoding.
     *
     *
     * This implements the following specs:
     *  *
     * General encoding: https://tools.ietf.org/html/draft-ietf-curdle-pkix-04
     *
     * Key encoding: https://tools.ietf.org/html/rfc8032
     *
     *
     *
     * For keys in older formats, decoding and then re-encoding is sufficient to
     * migrate them to the canonical encoding.
     *
     * Relevant spec quotes:
     * <pre>
     * In the X.509 certificate, the subjectPublicKeyInfo field has the
     * SubjectPublicKeyInfo type, which has the following ASN.1 syntax:
     *
     * SubjectPublicKeyInfo  ::=  SEQUENCE  {
     * algorithm         AlgorithmIdentifier,
     * subjectPublicKey  BIT STRING
     * }
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
     * @return 44 bytes for Ed25519, null for other curves
     */
    override fun getEncoded(): ByteArray? {
        if (params == EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)) {
            val totlen = 12 + Abyte.size
            val rv = ByteArray(totlen)
            // sequence
            rv[0] = 0x30.toByte()
            rv[1] = ((totlen - 2).toByte().toInt() and 0xff).toByte()
            // Algorithm Identifier
            // sequence
            rv[2] = 0x30.toByte()
            rv[3] = 5.toByte()
            // OID
            // https://msdn.microsoft.com/en-us/library/windows/desktop/bb540809%28v=vs.85%29.aspx
            rv[4] = 0x06.toByte()
            rv[5] = 3.toByte()
            rv[6] = (1 * 40 + 3).toByte()
            rv[7] = 101.toByte()
            rv[8] = OID_ED25519.toByte()
            // params - absent
            // the key
            rv[9] = 0x03.toByte() // bit string
            rv[10] = ((1 + Abyte.size).toByte().toInt() and 0xff).toByte()
            rv[11] = 0.toByte() // number of trailing unused bits
            System.arraycopy(Abyte, 0, rv, 12, Abyte.size)
            return rv
        }
        return null
    }

    override fun hashCode(): Int {
        return Arrays.hashCode(Abyte)
    }

    override fun equals(o: Any?): Boolean {
        if (o === this)
            return true
        if (o !is EdDSAPublicKey)
            return false
        val pk = o as EdDSAPublicKey?
        return Arrays.equals(Abyte, pk!!.abyte) && params == pk.params
    }

    companion object {
        private val serialVersionUID = 9837459837498475L

        // OID 1.3.101.xxx
        private val OID_OLD = 100
        private val OID_ED25519 = 112
        private val OID_BYTE = 8
        private val IDLEN_BYTE = 3

        /**
         * Extracts the public key bytes from the provided encoding.
         *
         *
         * This will decode data conforming to the current spec at
         * https://tools.ietf.org/html/draft-ietf-curdle-pkix-04
         * or the old spec at
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
         *
         * @return 32 bytes for Ed25519, throws for other curves
         */
        @Throws(InvalidKeySpecException::class)
        private fun decode(d: ByteArray): ByteArray {
            try {
                //
                // Setup and OID check
                //
                var totlen = 44
                var idlen = 5
                val doid = d[OID_BYTE].toInt()
                if (OID_OLD == doid) {
                    totlen = 47
                    idlen = 8
                } else if (OID_ED25519 == doid) {
                    // Detect parameter value of NULL
                    if (7 == d[IDLEN_BYTE].toInt()) {
                        totlen = 46
                        idlen = 7
                    }
                } else {
                    throw InvalidKeySpecException("unsupported key spec")
                }

                //
                // Pre-decoding check
                //
                if (d.size != totlen) {
                    throw InvalidKeySpecException("invalid key spec length")
                }

                //
                // Decoding
                //
                var idx = 0
                if (0x30 != d[idx++].toInt() ||
                        d[idx++].toInt() != totlen - 2 ||
                        0x30 != d[idx++].toInt() ||
                        d[idx++].toInt() != idlen ||
                        0x06 != d[idx++].toInt() ||
                        3 != d[idx++].toInt() ||
                        1 * 40 + 3 != d[idx++].toInt() ||
                        101 != d[idx++].toInt()) {
                    throw InvalidKeySpecException("unsupported key spec")
                }
                idx++ // OID, checked above
                // parameters only with old OID
                if (OID_OLD == doid) {
                    if (0x0a != d[idx++].toInt() ||
                            1 != d[idx++].toInt() ||
                            1 != d[idx++].toInt()) {
                        throw InvalidKeySpecException("unsupported key spec")
                    }
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
                        if (0x05 != d[idx++].toInt() || 0 != d[idx++].toInt()) {
                            throw InvalidKeySpecException("unsupported key spec")
                        }
                    }
                }
                if (0x03 != d[idx++].toInt() ||
                        33 != d[idx++].toInt() ||
                        0 != d[idx++].toInt()) {
                    throw InvalidKeySpecException("unsupported key spec")
                }
                val rv = ByteArray(32)
                System.arraycopy(d, idx, rv, 0, 32)
                return rv
            } catch (ioobe: IndexOutOfBoundsException) {
                throw InvalidKeySpecException(ioobe)
            }

        }
    }
}
