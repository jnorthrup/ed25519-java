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
import java.security.spec.AlgorithmParameterSpec;

import net.i2p.crypto.eddsa.math.Curve;
import net.i2p.crypto.eddsa.math.GroupElement;
import net.i2p.crypto.eddsa.math.ScalarOps;

import java.io.Serializable;
import java.util.Objects;

/**
 * Parameter specification for an EdDSA algorithm.
 * @author str4d
 *
 */
public class EdDSAParameterSpec implements AlgorithmParameterSpec  {

    public final Curve curve;
    public final String hashAlgo;
    public final ScalarOps scalarOps;
    public final GroupElement groupElement;

    /**
     * @param curve the curve
     * @param hashAlgo the JCA string for the hash algorithm
     * @param scalarOps the parameter L represented as ScalarOps
     * @param groupElement the parameter B
     * @throws IllegalArgumentException if hash algorithm is unsupported or length is wrong
     */
    public EdDSAParameterSpec(Curve curve, String hashAlgo,
                              ScalarOps scalarOps, GroupElement groupElement) {
        try {
            MessageDigest hash = MessageDigest.getInstance(hashAlgo);
            // EdDSA hash function must produce 2b-bit output
            if (curve.getField().getb()/4 != hash.getDigestLength())
                throw new IllegalArgumentException("Hash output is not 2b-bit");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Unsupported hash algorithm");
        }

        this.curve = curve;
        this.hashAlgo = hashAlgo;
        this.scalarOps = scalarOps;
        this.groupElement = groupElement;
    }

    @Override
    public int hashCode() {
        return hashAlgo.hashCode() ^
               curve.hashCode() ^
               groupElement.hashCode();
    }

    @Override
    public boolean equals(Object o) {
        return o == this || o instanceof EdDSAParameterSpec && Objects.equals(hashAlgo, ((EdDSAParameterSpec) o).hashAlgo) && curve.equals(((EdDSAParameterSpec) o).curve) && groupElement.equals(((EdDSAParameterSpec) o).groupElement);
    }
}
