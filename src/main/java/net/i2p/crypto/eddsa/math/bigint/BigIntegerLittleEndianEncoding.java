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

import java.math.BigInteger;
import java.util.Objects;
import java.util.stream.IntStream;

import net.i2p.crypto.eddsa.math.EmptyEncoding;
import net.i2p.crypto.eddsa.math.EdDSAFiniteField;
import net.i2p.crypto.eddsa.math.FieldElement;

public class BigIntegerLittleEndianEncoding {

    private final MyEmptyEncoding emptyEncoding = new MyEmptyEncoding();
    /**
     * Mask where only the first b-1 bits are set.
     */
    public BigInteger mask;

    /**
     *  Convert $x$ to little endian.
     *  Constant time.
     *
     *  @param x the BigInteger value to encode
     *  @return array of length $b/8$
     *  @throws IllegalStateException if field not set
     */
    public byte[] convertBigIntegerToLittleEndian(final BigInteger x) {
        Objects.requireNonNull(getEdDSAFiniteField(),"field not set");
        final byte[] in = x.toByteArray();
        final byte[] out = new byte[getEdDSAFiniteField().getb()/8];
        int bound = in.length;
        for (int i1 = 0; i1 < bound; i1++) {
            out[i1] = in[in.length - 1 - i1];
        }
        int bound1 = out.length;
        for (int i = in.length; i < bound1; i++) {
            out[i] = 0;
        }
        return out;
    }

    /**
     *  Convert in to big endian
     *
     *  @param in the $(b-1)$-bit encoding of a FieldElement.
     *  @return the decoded value as a BigInteger
     */
    public BigInteger toBigInteger(final byte[] in) {
        final byte[] out = new byte[in.length];
        for (int i = 0; i < in.length; i++) {
            out[i] = in[in.length-1-i];
        }
        return new BigInteger(1, out);
    }

    public EmptyEncoding getEmptyEncoding() {
        return emptyEncoding;
    }

    public void setEdDSAFiniteField(final EdDSAFiniteField f) {
        emptyEncoding.setEdDSAFiniteField(f);
    }

    public EdDSAFiniteField getEdDSAFiniteField() {
        return emptyEncoding.getEdDSAFiniteField();
    }

    private class MyEmptyEncoding extends EmptyEncoding {
        @Override
        public synchronized void setEdDSAFiniteField(final EdDSAFiniteField f) {
            super.setEdDSAFiniteField(f);
            mask = BigInteger.ONE.shiftLeft(f.getb()-1).subtract(BigInteger.ONE);
        }

        public byte[] encode(final FieldElement x) {
            return convertBigIntegerToLittleEndian(((BigIntegerFieldElement)x).bi.and(mask));
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
            Objects.requireNonNull(getEdDSAFiniteField(),"field not set");
            assert in.length == getEdDSAFiniteField().getb() / 8 : "Not a valid encoding";
            return new BigIntegerFieldElement(getEdDSAFiniteField(), toBigInteger(in).and(mask));
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
}
