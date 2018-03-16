/**
 * EdDSA-Java by str4d
 * <p>
 * To the extent possible under law, the person who associated CC0 with
 * EdDSA-Java has waived all copyright and related or neighboring rights
 * to EdDSA-Java.
 * <p>
 * You should have received a copy of the CC0 legalcode along with this
 * work. If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
 */
package net.i2p.crypto.eddsa;

import net.i2p.crypto.eddsa.math.GroupElement;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;

import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * An EdDSA private key.
 * <p>
 * Warning: Private key encoding is based on the current curdle WG draft,
 * and is subject to change. See getEncoded().
 * </p><p>
 * For compatibility with older releases, decoding supports both the old and new
 * draft specifications. See decode().
 * </p><p>
 * Ref: https://tools.ietf.org/html/draft-ietf-curdle-pkix-04
 * </p><p>
 * Old Ref: https://tools.ietf.org/html/draft-josefsson-pkix-eddsa-04
 * </p>
 *
 * @author str4d
 */
public final class EdDSAPrivateKey implements EdDSAKey, PrivateKey {
    private static final Map<Integer, byte[]> stubs = new LinkedHashMap<>();
    private static final long serialVersionUID = 23495873459878957L;
    // OID 1.3.101.xxx
    private static final int OID_OLD = 100;
    private static final int OID_ED25519 = 112;
    private static final int OID_BYTE = 11;
    private static final int IDLEN_BYTE = 6;
    private final byte[] seed;
    private final byte[] h;
    private final byte[] a;
    private final GroupElement A;
    private final byte[] Abyte;
    private final EdDSAParameterSpec edDsaSpec;

    public EdDSAPrivateKey(final EdDSAPrivateKeySpec spec) {
        seed = spec.getSeed();
        h = spec.getH();
        a = spec.geta();
        A = spec.getA();
        Abyte = A.toByteArray();
        edDsaSpec = spec.getParams();
    }

    public EdDSAPrivateKey(final PKCS8EncodedKeySpec spec) throws InvalidKeySpecException {
        this(new EdDSAPrivateKeySpec(decode(spec.getEncoded()),
                EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)));
    }

    /**
     * Extracts the private key bytes from the provided encoding.
     * <p>
     * This will decode data conforming to the current spec at
     * https://tools.ietf.org/html/draft-ietf-curdle-pkix-04
     * or as inferred from the old spec at
     * https://tools.ietf.org/html/draft-josefsson-pkix-eddsa-04.
     * </p><p>
     * Contrary to draft-ietf-curdle-pkix-04, it WILL accept a parameter value
     * of NULL, as it is required for interoperability with the default Java
     * keystore. Other implementations MUST NOT copy this behaviour from here
     * unless they also need to read keys from the default Java keystore.
     * </p><p>
     * This is really dumb for now. It does not use a general-purpose ASN.1 decoder.
     * See also getEncoded().
     *
     * @return 32 bytes for Ed25519, throws for other curves
     */
    private static byte[] decode(final byte[] d) throws InvalidKeySpecException {
        try {
            //
            // Setup and OID check
            //
            int totlen = 48;
            int idlen = 5;
            final int doid = d[OID_BYTE];
            if (OID_OLD == doid) {
                totlen = 49;
                idlen = 8;
            } else if (OID_ED25519 == doid) {
                // Detect parameter value of NULL
                if (7 == d[IDLEN_BYTE]) {
                    totlen = 50;
                    idlen = 7;
                }
            } else {
                throw new InvalidKeySpecException("unsupported key spec");
            }

            //
            // Pre-decoding check
            //
            if (d.length != totlen) {
                throw new InvalidKeySpecException("invalid key spec length");
            }

            //
            // Decoding
            //
            int idx = 0;
            //noinspection DuplicateBooleanBranch
            if (0x30 != d[idx++] ||
                    d[idx++] != (totlen - 2) ||
                    0x02 != d[idx++] ||
                    1 != d[idx++] ||
                    0 != d[idx++] ||
                    0x30 != d[idx++] ||
                    d[idx++] != idlen ||
                    0x06 != d[idx++] ||
                    3 != d[idx++] ||
                    (1 * 40) + 3 != d[idx++] ||
                    101 != d[idx++]) {
                throw new InvalidKeySpecException("unsupported key spec");
            }
            idx++; // OID, checked above
            // parameters only with old OID
            if (OID_OLD == doid) {
                //noinspection DuplicateBooleanBranch
                if (0x0a != d[idx++] ||
                        1 != d[idx++] ||
                        1 != d[idx++]) {
                    throw new InvalidKeySpecException("unsupported key spec");
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
                    if (0x05 != d[idx++] ||
                            0 != d[idx++]) {
                        throw new InvalidKeySpecException("unsupported key spec");
                    }
                }
                // PrivateKey wrapping the CurvePrivateKey
                if (0x04 != d[idx++] ||
                        34 != d[idx++]) {
                    throw new InvalidKeySpecException("unsupported key spec");
                }
            }
            if (0x04 != d[idx++] ||
                    32 != d[idx++]) {
                throw new InvalidKeySpecException("unsupported key spec");
            }
            final byte[] rv = new byte[32];
            System.arraycopy(d, idx, rv, 0, 32);
            return rv;
        } catch (final IndexOutOfBoundsException ioobe) {
            throw new InvalidKeySpecException(ioobe);
        }
    }

    @Override
    public final String getAlgorithm() {
        return KEY_ALGORITHM;
    }

    @Override
    public final String getFormat() {
        return "PKCS#8";
    }

    /**
     * Returns the public key in its canonical encoding.
     * <p>
     * This implements the following specs:
     * <ul><li>
     * General encoding: https://tools.ietf.org/html/draft-ietf-curdle-pkix-04
     * <li>
     * Key encoding: https://tools.ietf.org/html/rfc8032
     * </ul>
     * <p>
     * This encodes the seed. It will return null if constructed from
     * a spec which was directly constructed from H, in which case seed is null.
     * </p><p>
     * For keys in older formats, decoding and then re-encoding is sufficient to
     * migrate them to the canonical encoding.
     * </p>
     * Relevant spec quotes:
     * <pre>
     *  OneAsymmetricKey ::= SEQUENCE {
     *    version Version,
     *    privateKeyAlgorithm PrivateKeyAlgorithmIdentifier,
     *    privateKey PrivateKey,
     *    attributes [0] Attributes OPTIONAL,
     *    ...,
     *    [[2: publicKey [1] PublicKey OPTIONAL ]],
     *    ...
     *  }
     *
     *  Version ::= INTEGER
     *  PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
     *  PrivateKey ::= OCTET STRING
     *  PublicKey ::= OCTET STRING
     *  Attributes ::= SET OF Attribute
     * </pre>
     * <p>
     * <pre>
     *  ... when encoding a OneAsymmetricKey object, the private key is wrapped
     *  in a CurvePrivateKey object and wrapped by the OCTET STRING of the
     *  'privateKey' field.
     *
     *  CurvePrivateKey ::= OCTET STRING
     * </pre>
     * <p>
     * <pre>
     *  AlgorithmIdentifier  ::=  SEQUENCE  {
     *    algorithm   OBJECT IDENTIFIER,
     *    parameters  ANY DEFINED BY algorithm OPTIONAL
     *  }
     *
     *  For all of the OIDs, the parameters MUST be absent.
     * </pre>
     * <p>
     * <pre>
     *  id-Ed25519   OBJECT IDENTIFIER ::= { 1 3 101 112 }
     * </pre>
     *
     * @return 48 bytes for Ed25519, null for other curves
     */
    @Override
    public final byte[] getEncoded() {
        if (edDsaSpec.equals(EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)) && null != seed) {
            final int totlen = 16 + seed.length;
            final byte[] rv = new byte[totlen];
            final byte[] stub = stubs.computeIfAbsent(seed.length, integer -> new byte[]{(byte) 0x30,
                    (byte) ((int) (byte) (totlen - 2) & 0xff),
                    // version
                    (byte) 0x02,
                    (byte) 1,
                    // v1 - no public key included
                    (byte) 0,
                    // Algorithm Identifier
                    // sequence
                    (byte) 0x30,
                    (byte) 5,
                    // OID
                    // https://msdn.microsoft.com/en-us/library/windows/desktop/bb540809%28v=vs.85%29.aspx
                    (byte) 0x06,
                    (byte) 3,
                    (byte) ((1 * 40) + 3),
                    (byte) 101,
                    (byte) OID_ED25519,
                    // params - absent
                    // PrivateKey
                    (byte) 0x04,  // octet strin,
                    (byte) ((int) (byte) (2 + seed.length) &0xff),
                    // CurvePrivateKey
                    (byte) 0x04,  // octet strin,
                    (byte) ((int) (byte) seed.length &0xff)});
            // sequence

            // the key
            System.arraycopy(stub, 0, rv, 0, stub.length);
            System.arraycopy(seed, 0, rv, 16, seed.length);
            return rv;
        }
        return null;
    }

    @Override
    public final EdDSAParameterSpec getParams() {
        return edDsaSpec;
    }

    /**
     * @return will be null if constructed from a spec which was
     * directly constructed from H
     */
    public final byte[] getSeed() {
        return seed.clone();
    }

    /**
     * @return the hash of the seed
     */
    public final byte[] getH() {
        return h.clone();
    }

    /**
     * @return the private key
     */
    public final byte[] geta() {
        return a.clone();
    }

    /**
     * @return the public key
     */
    public final GroupElement getA() {
        return A;
    }

    /**
     * @return the public key
     */
    public final byte[] getAbyte() {
        return Abyte.clone();
    }

    @Override
    public final int hashCode() {
        return Arrays.hashCode(seed);
    }

    @Override
    public final boolean equals(final Object o) {
        if (o != this) {
            if (o instanceof EdDSAPrivateKey) {
                final EdDSAPrivateKey pk = (EdDSAPrivateKey) o;
                return Arrays.equals(seed, pk.getSeed()) && edDsaSpec.equals(pk.getParams());
            }
            return false;
        }
        return true;
    }
}
