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
package net.i2p.crypto.eddsa.math.bigint

import java.math.BigInteger

import net.i2p.crypto.eddsa.math.EdDSAFiniteField
import net.i2p.crypto.eddsa.math.ScalarOps

class BigIntegerScalarOps(f: EdDSAFiniteField, private val l: BigInteger) : ScalarOps {
    private val enc: BigIntegerLittleEndianEncoding

    init {
        enc = BigIntegerLittleEndianEncoding()
        enc.edDSAFiniteField = f
    }

    override fun reduce(s: ByteArray): ByteArray {
        return enc.convertBigIntegerToLittleEndian(enc.toBigInteger(s).mod(l))
    }

    override fun multiplyAndAdd(a: ByteArray, b: ByteArray, c: ByteArray): ByteArray {
        return enc.convertBigIntegerToLittleEndian(enc.toBigInteger(a).multiply(enc.toBigInteger(b)).add(enc.toBigInteger(c)).mod(l))
    }

}
