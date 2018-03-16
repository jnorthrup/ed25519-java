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

import net.i2p.crypto.eddsa.math.Field;
import net.i2p.crypto.eddsa.math.ScalarOps;

public final class BigIntegerScalarOps implements ScalarOps {
    private final BigInteger l;
    private final BigIntegerLittleEndianEncoding enc;

    public BigIntegerScalarOps(final Field f, final BigInteger l) {
        this.l = l;
        enc = new BigIntegerLittleEndianEncoding();
        enc.setField(f);
    }

    public byte[] reduce(final byte[] s) {
        return enc.encode(BigIntegerLittleEndianEncoding.toBigInteger(s).mod(l));
    }

    public byte[] multiplyAndAdd(final byte[] a, final byte[] b, final byte[] c) {
        return enc.encode(BigIntegerLittleEndianEncoding.toBigInteger(a).multiply(BigIntegerLittleEndianEncoding.toBigInteger(b)).add(BigIntegerLittleEndianEncoding.toBigInteger(c)).mod(l));
    }

}
