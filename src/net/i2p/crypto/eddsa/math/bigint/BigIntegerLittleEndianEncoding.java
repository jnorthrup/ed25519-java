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
package net.i2p.crypto.eddsa.math.bigint;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.stream.IntStream;

import net.i2p.crypto.eddsa.math.Encoding;
import net.i2p.crypto.eddsa.math.Field;
import net.i2p.crypto.eddsa.math.FieldElement;

public final class BigIntegerLittleEndianEncoding extends Encoding   {
    private static final long serialVersionUID = 3984579843759837L;
    /**
     * Mask where only the first b-1 bits are set.
     */
    private BigInteger mask;

    @Override
    public final synchronized void setField(final Field f) {
        super.setField(f);
        mask = BigInteger.ONE.shiftLeft(f.getb()-1).subtract(BigInteger.ONE);
    }

    public byte[] encode(final FieldElement x) {
        return encode(((BigIntegerFieldElement)x).bi.and(mask));
    }

    /**
     *  Convert $x$ to little endian.
     *  Constant time.
     *
     *  @param x the BigInteger value to encode
     *  @return array of length $b/8$
     *  @throws IllegalStateException if field not set
     */
    public final byte[] encode(final BigInteger x) {
        if (f != null) {
            final byte[] in = x.toByteArray();
            final byte[] out = new byte[f.getb() / 8];
            int bound = in.length;
            for (int i1 = 0; i1 < bound; i1++) {
                out[i1] = in[in.length - 1 - i1];
            }
            int bound1 = out.length;
            for (int i = in.length; i < bound1; i++) {
                out[i] = (byte) 0;
            }
            return out;
        } else {
            throw new IllegalStateException("field not set");
        }
    }

    /**
     *  Decode a FieldElement from its $(b-1)$-bit encoding.
     *  The highest bit is masked out.
     *
     *  @param in the $(b-1)$-bit encoding of a FieldElement.
     *  @return the FieldElement represented by 'val'.
     *  @throws IllegalStateException if field not set
     *  @throws IllegalArgumentException if encoding is invalid
     */
    public FieldElement decode(final byte[] in) {
        if (f != null) {
            if (in.length == f.getb() / 8)
                return new BigIntegerFieldElement(f, toBigInteger(in).and(mask));
            throw new IllegalArgumentException("Not a valid encoding");
        }
        throw new IllegalStateException("field not set");
    }

    /**
     *  Convert in to big endian
     *
     *  @param in the $(b-1)$-bit encoding of a FieldElement.
     *  @return the decoded value as a BigInteger
     */
    public final BigInteger toBigInteger(final byte[] in) {
        final byte[] out = new byte[in.length];
        int bound = in.length;
        for (int i = 0; i < bound; i++) {
            out[i] = in[in.length - 1 - i];
        }
        return new BigInteger(1, out);
    }

    /**
     * From the Ed25519 paper:<br>
     * $x$ is negative if the $(b-1)$-bit encoding of $x$ is lexicographically larger
     * than the $(b-1)$-bit encoding of $-x$. If $q$ is an odd prime and the encoding
     * is the little-endian representation of $\{0, 1,\dots, q-1\}$ then the negative
     * elements of $F_q$ are $\{1, 3, 5,\dots, q-2\}$.
     * @return true if negative
     */
    public boolean isNegative(final FieldElement x) {
        return ((BigIntegerFieldElement)x).bi.testBit(0);
    }
}
