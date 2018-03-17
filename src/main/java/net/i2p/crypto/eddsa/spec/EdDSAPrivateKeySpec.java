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
package net.i2p.crypto.eddsa.spec;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import net.i2p.crypto.eddsa.math.GroupElement;

/**
 * @author str4d
 *
 */
public class EdDSAPrivateKeySpec implements KeySpec {
    public final byte[] seed;
    public final byte[] hasOfTheSeed;
    public final byte[] privateKey;
    public final GroupElement groupElement;
    public final EdDSAParameterSpec spec;

    /**
     *  @param seed the private key
     *  @param spec the parameter specification for this key
     *  @throws IllegalArgumentException if seed length is wrong or hash algorithm is unsupported
     */
    public EdDSAPrivateKeySpec(byte[] seed, EdDSAParameterSpec spec) {
        if (seed.length != spec.curve.getField().getb()/8)
            throw new IllegalArgumentException("seed length is wrong");

        this.spec = spec;
        this.seed = seed;

        try {
            MessageDigest hash = MessageDigest.getInstance(spec.hashAlgo);
            int b = spec.curve.getField().getb();

            // H(k)
            hasOfTheSeed = hash.digest(seed);

            /*a = BigInteger.valueOf(2).pow(b-2);
            for (int i=3;i<(b-2);i++) {
                a = a.add(BigInteger.valueOf(2).pow(i).multiply(BigInteger.valueOf(Utils.bit(h,i))));
            }*/
            // Saves ~0.4ms per key when running signing tests.
            // TODO: are these bitflips the same for any hash function?
            hasOfTheSeed[0] &= 248;
            hasOfTheSeed[(b/8)-1] &= 63;
            hasOfTheSeed[(b/8)-1] |= 64;
            privateKey = Arrays.copyOfRange(hasOfTheSeed, 0, b/8);

            groupElement = spec.groupElement.scalarMultiply(privateKey);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Unsupported hash algorithm");
        }
    }

    /**
     *  Initialize directly from the hash.
     *  getSeed() will return null if this constructor is used.
     *
     *  @param spec the parameter specification for this key
     *  @param hasOfTheSeed the private key
     *  @throws IllegalArgumentException if hash length is wrong
     *  @since 0.1.1
     */
    public EdDSAPrivateKeySpec(EdDSAParameterSpec spec, byte[] hasOfTheSeed) {
        if (hasOfTheSeed.length != spec.curve.getField().getb()/4)
            throw new IllegalArgumentException("hash length is wrong");

	this.seed = null;
	this.hasOfTheSeed = hasOfTheSeed;
	this.spec = spec;
        int b = spec.curve.getField().getb();

        hasOfTheSeed[0] &= 248;
        hasOfTheSeed[(b/8)-1] &= 63;
        hasOfTheSeed[(b/8)-1] |= 64;
        privateKey = Arrays.copyOfRange(hasOfTheSeed, 0, b/8);

        groupElement = spec.groupElement.scalarMultiply(privateKey);
    }

    public EdDSAPrivateKeySpec(byte[] seed, byte[] hasOfTheSeed, byte[] privateKey, GroupElement groupElement, EdDSAParameterSpec spec) {
        this.seed = seed;
        this.hasOfTheSeed = hasOfTheSeed;
        this.privateKey = privateKey;
        this.groupElement = groupElement;
        this.spec = spec;
    }

    public EdDSAParameterSpec getParams() {
        return spec;
    }
}
