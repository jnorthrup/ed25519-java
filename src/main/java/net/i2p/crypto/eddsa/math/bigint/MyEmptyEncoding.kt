package net.i2p.crypto.eddsa.math.bigint

import net.i2p.crypto.eddsa.math.EdDSAFiniteField
import net.i2p.crypto.eddsa.math.EmptyEncoding
import net.i2p.crypto.eddsa.math.FieldElement

import java.math.BigInteger
import java.util.Objects

internal class MyEmptyEncoding(private val bigIntegerLittleEndianEncoding: BigIntegerLittleEndianEncoding) : EmptyEncoding() {

    override var edDSAFiniteField: EdDSAFiniteField?
        get() = super.edDSAFiniteField!!
        @Synchronized set(f) {
            super.edDSAFiniteField = f
            bigIntegerLittleEndianEncoding.mask = BigInteger.ONE.shiftLeft(f!!.b!! - 1).subtract(BigInteger.ONE)
        }

    override fun encode(x: FieldElement): ByteArray {
        return bigIntegerLittleEndianEncoding.convertBigIntegerToLittleEndian((x as BigIntegerFieldElement).bi.and(bigIntegerLittleEndianEncoding.mask!!))
    }

    /**
     * Decode a FieldElement from its $(b-1)$-bit encoding.
     * The highest bit is masked out.
     *
     * @param in the $(b-1)$-bit encoding of a FieldElement.
     * @return the FieldElement represented by 'val'.
     * @throws IllegalStateException if field not set
     * @throws IllegalArgumentException if encoding is invalid
     */
    override fun decode(`in`: ByteArray): FieldElement {
        Objects.requireNonNull(edDSAFiniteField, "field not set")
        assert(`in`.size == edDSAFiniteField!!.b / 8) { "Not a valid encoding" }
        return BigIntegerFieldElement(this!!.edDSAFiniteField!!, bigIntegerLittleEndianEncoding.toBigInteger(`in`).and(bigIntegerLittleEndianEncoding.mask!!))
    }

    /**
     * From the Ed25519 paper:<br></br>
     * $x$ is negative if the $(b-1)$-bit encoding of $x$ is lexicographically larger
     * than the $(b-1)$-bit encoding of $-x$. If $q$ is an odd prime and the encoding
     * is the little-endian representation of $\{0, 1,\dots, q-1\}$ then the negative
     * elements of $F_q$ are $\{1, 3, 5,\dots, q-2\}$.
     * @return true if negative
     */
    override fun isNegative(x: FieldElement): Boolean {
        return (x as BigIntegerFieldElement).bi.testBit(0)
    }
}
