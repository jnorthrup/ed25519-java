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
class Ed25519FiniteFieldElementTest : AbstractFiniteFieldElementTest() {

    protected override val randomFieldElement: FieldElement
        get() = MathUtils.randomFieldElement

    protected override val q: BigInteger
        get() = MathUtils.q

    protected override val field: FiniteField
        get() = MathUtils.field

    // endregion

    // region isNonZero

    protected override val zeroFieldElement: FieldElement
        get() = Ed25519FieldElement(MathUtils.field, IntArray(10))

    protected override val nonZeroFieldElement: FieldElement
        get() {
            val t = IntArray(10)
            t[0] = 5
            return Ed25519FieldElement(MathUtils.field, t)
        }

    override fun toBigInteger(f: FieldElement): BigInteger {
        return MathUtils.toBigInteger(f)
    }

    // region constructor

    @Test
    fun canConstructFieldElementFromArrayWithCorrectLength() {
        // Assert:
        Ed25519FieldElement(MathUtils.field, IntArray(10))
    }

    @Test(expected = IllegalArgumentException::class)
    fun cannotConstructFieldElementFromArrayWithIncorrectLength() {
        // Assert:
        Ed25519FieldElement(MathUtils.field, IntArray(9))
    }

    @Test(expected = IllegalArgumentException::class)
    fun cannotConstructFieldElementWithoutField() {
        // Assert:
        Ed25519FieldElement(null, IntArray(9))
    }

    // endregion

    // region toString

    @Test
    fun toStringReturnsCorrectRepresentation() {
        // Arrange:
        val f = MathUtils.field.encoding.decode(BYTES)

        // Act:
        val fAsString = f.toString()
        val builder = StringBuilder()
        builder.append("[Ed25519FieldElement val=")
        for (b in BYTES) {
            builder.append(String.format("%02x", b))
        }
        builder.append("]")

        // Assert:
        Assert.assertThat(fAsString, IsEqual.equalTo(builder.toString()))
    }

    companion object {

        private val BYTES = byteArrayOf((0 + 1).toByte(), (1 + 1).toByte(), (2 + 1).toByte(), (3 + 1).toByte(), (4 + 1).toByte(), (5 + 1).toByte(), (6 + 1).toByte(), (7 + 1).toByte(), (8 + 1).toByte(), (9 + 1).toByte(), (10 + 1).toByte(), (11 + 1).toByte(), (12 + 1).toByte(), (13 + 1).toByte(), (14 + 1).toByte(), (15 + 1).toByte(), (16 + 1).toByte(), (17 + 1).toByte(), (18 + 1).toByte(), (19 + 1).toByte(), (20 + 1).toByte(), (21 + 1).toByte(), (22 + 1).toByte(), (23 + 1).toByte(), (24 + 1).toByte(), (25 + 1).toByte(), (26 + 1).toByte(), (27 + 1).toByte(), (28 + 1).toByte(), (29 + 1).toByte(), (30 + 1).toByte(), (31 + 1).toByte())
    }

    // endregion
}
