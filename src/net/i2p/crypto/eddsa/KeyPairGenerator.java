/**
 * EdDSA-Java by str4d
 *
 * To the extent possible under law, the person who associated CC0 with
 * EdDSA-Java has waived all copyright and related or neighboring rights
 * to EdDSA-Java.
 *
 * You should have received a copy of the CC0 legalcode along with this
 * work. If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
 *
 */
package net.i2p.crypto.eddsa;

import net.i2p.crypto.eddsa.spec.*;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 *  Default keysize is 256 (Ed25519)
 */
@SuppressWarnings("WeakerAccess")
public final class KeyPairGenerator extends KeyPairGeneratorSpi {
    private static final int DEFAULT_KEYSIZE = 256;
    private EdDSAParameterSpec edParams;
    private SecureRandom random;
    private boolean initialized;

    private static final Map<Integer, AlgorithmParameterSpec> edParameters;

    static {
        edParameters = new LinkedHashMap<>();

        edParameters.put(Integer.valueOf(256), new EdDSAGenParameterSpec(EdDSANamedCurveTable.ED_25519));
    }

    public void initialize(final int keysize, final SecureRandom random) {
        final AlgorithmParameterSpec edParams = edParameters.get(Integer.valueOf(keysize));
        if (null == edParams)
            throw new InvalidParameterException("unknown key type.");
        try {
            initialize(edParams, random);
        } catch (final InvalidAlgorithmParameterException e) {
            throw new InvalidParameterException("key type not configurable.");
        }
    }

    @Override
    public void initialize(final AlgorithmParameterSpec params, final SecureRandom random) throws InvalidAlgorithmParameterException {
        if (params instanceof EdDSAParameterSpec) {
            edParams = (EdDSAParameterSpec) params;
        } else if (params instanceof EdDSAGenParameterSpec) {
            edParams = createNamedCurveSpec(((EdDSAGenParameterSpec) params).getName());
        } else
            throw new InvalidAlgorithmParameterException("parameter object not a EdDSAParameterSpec");

        this.random = random;
        initialized = true;
    }

    public KeyPair generateKeyPair() {
        if (!initialized)
            initialize(DEFAULT_KEYSIZE, new SecureRandom());

        final byte[] seed = new byte[edParams.getCurve().getField().getb()/8];
        random.nextBytes(seed);

        final EdDSAPrivateKeySpec privKey = new EdDSAPrivateKeySpec(seed, edParams);
        final EdDSAPublicKeySpec pubKey = new EdDSAPublicKeySpec(privKey.getAPrime(), edParams);

        return new KeyPair(new EdDSAPublicKey(pubKey), new EdDSAPrivateKey(privKey));
    }

    /**
     * Create an EdDSANamedCurveSpec from the provided curve name. The current
     * implementation fetches the pre-created curve spec from a table.
     * @param curveName the EdDSA named curve.
     * @return the specification for the named curve.
     * @throws InvalidAlgorithmParameterException if the named curve is unknown.
     */
    private static EdDSANamedCurveSpec createNamedCurveSpec(final String curveName) throws InvalidAlgorithmParameterException {
        final EdDSANamedCurveSpec spec = EdDSANamedCurveTable.getByName(curveName);
        if (null == spec) {
            throw new InvalidAlgorithmParameterException("unknown curve name: " + curveName);
        }
        return spec;
    }
}
