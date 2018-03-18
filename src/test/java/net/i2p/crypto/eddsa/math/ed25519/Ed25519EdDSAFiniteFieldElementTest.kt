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
package net.i2p.crypto.eddsa.math.ed25519

import net.i2p.crypto.eddsa.math.*
import org.hamcrest.core.*
import org.junit.*

import java.math.BigInteger

/**
 * Tests rely on the BigInteger class.
 */
class Ed25519EdDSAFiniteFieldElementTest : AbstractEdDSAFiniteFieldElementTest() {

    protected override val randomFieldElement: FieldElement
        get() = MathUtils.randomFieldElement

    protected override val q: BigInteger
        get() = MathUtils.q

    protected override val edDSAFiniteField: EdDSAFiniteField
        get() = MathUtils.edDSAFiniteField

    // endregion

    // region isNonZero

    protected override val zeroFieldElement: FieldElement
        get() = Ed25519FieldElement(MathUtils.edDSAFiniteField, IntArray(10))

    protected override val nonZeroFieldElement: FieldElement
        get() {
            val t = IntArray(10)
            t[0] = 5
            return Ed25519FieldElement(MathUtils.edDSAFiniteField, t)
        }

    override fun toBigInteger(f: FieldElement): BigInteger {
        return MathUtils.toBigInteger(f)
    }

    // region constructor

    @Test
    fun canConstructFieldElementFromArrayWithCorrectLength() {
        // Assert:
        Ed25519FieldElement(MathUtils.edDSAFiniteField, IntArray(10))
    }

    @Test(expected = AssertionError::class)
    fun cannotConstructFieldElementFromArrayWithIncorrectLength() {
        // Assert:
        Ed25519FieldElement(MathUtils.edDSAFiniteField, IntArray(9))
    }

    @Test(expected = AssertionError::class)
    fun cannotConstructFieldElementWithoutField() {
        // Assert:
        Ed25519FieldElement(null, IntArray(9))
    }

    // endregion

    // region toString

    @Test
    fun toStringReturnsCorrectRepresentation() {
        // Arrange:
        val bytes = ByteArray(32)
        var i = 0
        while (32 > i) {
            bytes[i] = (i + 1).toByte()
            i++
        }
        val f = MathUtils.edDSAFiniteField.encoding.decode(bytes)

        // Act:
        val fAsString = f.toString()
        val builder = StringBuilder()
        builder.append("[Ed25519FieldElement val=")
        for (b in bytes) {
            builder.append(String.format("%02x", java.lang.Byte.valueOf(b)))
        }
        builder.append("]")

        // Assert:
        Assert.assertThat(fAsString, IsEqual.equalTo(builder.toString()))
    }

    // endregion
}
