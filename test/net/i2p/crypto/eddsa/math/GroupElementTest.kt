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
package net.i2p.crypto.eddsa.math

import net.i2p.crypto.eddsa.*
import net.i2p.crypto.eddsa.math.GroupElement.Representation
import net.i2p.crypto.eddsa.spec.*
import org.hamcrest.core.*
import org.junit.*
import org.junit.rules.ExpectedException

import java.math.BigInteger
import java.util.Arrays

import org.hamcrest.Matchers.*
import org.junit.Assert.assertThat
import kotlin.experimental.or

/**
 * @author str4d
 * Additional tests by NEM project team.
 */public
class GroupElementTest {

//    @Rule
//   public  var exception = ExpectedException.none()

    /**
     * Test method for [GroupElement.p2].
     */
    @Test
    fun testP2() {
        val t = GroupElement.p2(curve, ZERO, ONE, ONE)
        assertThat(t.curve, `is`(equalTo(curve)))
        assertThat<Representation>(t.repr, `is`<Representation>(Representation.P2))
        assertThat(t.X, `is`(ZERO))
        assertThat(t.Y, `is`(ONE))
        assertThat(t.Z, `is`(ONE))
        assertThat(t.T, `is`<FieldElement>(null as FieldElement?))
    }

    /**
     * Test method for [GroupElement.p3].
     */
    @Test
    fun testP3() {
        val t = GroupElement.p3(curve, ZERO, ONE, ONE, ZERO)
        assertThat(t.curve, `is`(equalTo(curve)))
        assertThat<Representation>(t.repr, `is`<Representation>(Representation.P3))
        assertThat(t.X, `is`(ZERO))
        assertThat(t.Y, `is`(ONE))
        assertThat(t.Z, `is`(ONE))
        assertThat(t.T, `is`(ZERO))
    }

    /**
     * Test method for [GroupElement.p1p1].
     */
    @Test
    fun testP1p1() {
        val t = GroupElement.p1p1(curve, ZERO, ONE, ONE, ONE)
        assertThat(t.curve, `is`(equalTo(curve)))
        assertThat<Representation>(t.repr, `is`<Representation>(Representation.P1P1))
        assertThat(t.X, `is`(ZERO))
        assertThat(t.Y, `is`(ONE))
        assertThat(t.Z, `is`(ONE))
        assertThat(t.T, `is`(ONE))
    }

    /**
     * Test method for [GroupElement.precomp].
     */
    @Test
    fun testPrecomp() {
        val t = GroupElement.precomp(curve, ONE, ONE, ZERO)
        assertThat(t.curve, `is`(equalTo(curve)))
        assertThat<Representation>(t.repr, `is`<Representation>(Representation.PRECOMP))
        assertThat(t.X, `is`(ONE))
        assertThat(t.Y, `is`(ONE))
        assertThat(t.Z, `is`(ZERO))
        assertThat(t.T, `is`<FieldElement>(null as FieldElement?))
    }

    /**
     * Test method for [GroupElement.cached].
     */
    @Test
    fun testCached() {
        val t = GroupElement.cached(curve, ONE, ONE, ONE, ZERO)
        assertThat(t.curve, `is`(equalTo(curve)))
        assertThat<Representation>(t.repr, `is`<Representation>(Representation.CACHED))
        assertThat(t.X, `is`(ONE))
        assertThat(t.Y, `is`(ONE))
        assertThat(t.Z, `is`(ONE))
        assertThat(t.T, `is`(ZERO))
    }

    /**
     * Test method for [GroupElement.GroupElement].
     */
    @Test
    fun testGroupElementCurveRepresentationFieldElementFieldElementFieldElementFieldElement() {
        val t = GroupElement(curve, Representation.P3, ZERO, ONE, ONE, ZERO)
        assertThat(t.curve, `is`(equalTo(curve)))
        assertThat<Representation>(t.repr, `is`<Representation>(Representation.P3))
        assertThat(t.X, `is`(ZERO))
        assertThat(t.Y, `is`(ONE))
        assertThat(t.Z, `is`(ONE))
        assertThat(t.T, `is`(ZERO))
    }

    /**
     * Tests [GroupElement.GroupElement] and
     * [GroupElement.toByteArray] against valid public keys.
     */
    @Test
    fun testToAndFromByteArray() {
        var t: GroupElement
        for (testCase in Ed25519TestVectors.testCases) {
            t = GroupElement(curve, testCase.pk)
            assertThat("Test case " + testCase.caseNum + " failed",
                    t.toByteArray(), `is`(equalTo(testCase.pk)))
        }
    }

    /**
     * Test method for [GroupElement.GroupElement].
     */
    @Test
    fun testGroupElementByteArray() {
        val t = GroupElement(curve, BYTES_PKR)
        val s = GroupElement.p3(curve, PKR[0], PKR[1], ONE, PKR[0].multiply(PKR[1]))
        assertThat(t, `is`(equalTo(s)))
    }

    @Test
    fun constructorUsingByteArrayReturnsExpectedResult() {
        for (i in 0..99) {
            // Arrange:
            val g = MathUtils.getRandomGroupElement()
            val bytes = g.toByteArray()

            // Act:
            val h1 = GroupElement(curve, bytes)
            val h2 = MathUtils.toGroupElement(bytes)

            // Assert:
            Assert.assertThat(h1, IsEqual.equalTo(h2))
        }
    }

    /**
     * Test method for [GroupElement.toByteArray].
     *
     *
     * TODO 20141001 BR: why test with points which are not on the curve?
     */
    @Test
    fun testToByteArray() {
        val zerozero = GroupElement.p2(curve, ZERO, ZERO, ONE).toByteArray()
        assertThat(zerozero.size, `is`(equalTo(BYTES_ZEROZERO.size)))
        assertThat(zerozero, `is`(equalTo(BYTES_ZEROZERO)))

        val oneone = GroupElement.p2(curve, ONE, ONE, ONE).toByteArray()
        assertThat(oneone.size, `is`(equalTo(BYTES_ONEONE.size)))
        assertThat(oneone, `is`(equalTo(BYTES_ONEONE)))

        val tenzero = GroupElement.p2(curve, TEN, ZERO, ONE).toByteArray()
        assertThat(tenzero.size, `is`(equalTo(BYTES_TENZERO.size)))
        assertThat(tenzero, `is`(equalTo(BYTES_TENZERO)))

        val oneten = GroupElement.p2(curve, ONE, TEN, ONE).toByteArray()
        assertThat(oneten.size, `is`(equalTo(BYTES_ONETEN.size)))
        assertThat(oneten, `is`(equalTo(BYTES_ONETEN)))

        val pkr = GroupElement.p2(curve, PKR[0], PKR[1], ONE).toByteArray()
        assertThat(pkr.size, `is`(equalTo(BYTES_PKR.size)))
        assertThat(pkr, `is`(equalTo(BYTES_PKR)))
    }

    @Test
    fun toByteArrayReturnsExpectedResult() {
        for (i in 0..99) {
            // Arrange:
            val g = MathUtils.getRandomGroupElement()

            // Act:
            val gBytes = g.toByteArray()
            val bytes = MathUtils.toByteArray(MathUtils.toBigInteger(g.y))
            if (MathUtils.toBigInteger(g.x).mod(BigInteger("2")) == BigInteger.ONE) bytes.set(31, bytes[31].or(0x80.toByte()))

            // Assert:
            Assert.assertThat(Arrays.equals(gBytes, bytes), IsEqual.equalTo(true))
        }
    }

    // region toX where X is the representation

    /**
     * Test method for [GroupElement.toP2].
     */
    @Test
    fun testToP2() {
        val p3zero = curve.getZero(Representation.P3)
        var t = p3zero!!.toP2()
        assertThat<Representation>(t.repr, `is`<Representation>(Representation.P2))
        assertThat(t.X, `is`(p3zero.X))
        assertThat(t.Y, `is`(p3zero.Y))
        assertThat(t.Z, `is`(p3zero.Z))
        assertThat(t.T, `is`<FieldElement>(null as FieldElement?))

        val B = ed25519.b
        t = B.toP2()
        assertThat<Representation>(t.repr, `is`<Representation>(Representation.P2))
        assertThat(t.X, `is`(B.X))
        assertThat(t.Y, `is`(B.Y))
        assertThat(t.Z, `is`(B.Z))
        assertThat(t.T, `is`<FieldElement>(null as FieldElement?))
    }

    @Test(expected = IllegalArgumentException::class)
    fun toP2ThrowsIfGroupElementHasPrecompRepresentation() {
        // Arrange:
        val g = MathUtils.toRepresentation(MathUtils.getRandomGroupElement(), Representation.PRECOMP)

        // Assert:
        g.toP2()
    }

    @Test(expected = IllegalArgumentException::class)
    fun toP2ThrowsIfGroupElementHasCachedRepresentation() {
        // Arrange:
        val g = MathUtils.toRepresentation(MathUtils.getRandomGroupElement(), Representation.CACHED)

        // Assert:
        g.toP2()
    }

    @Test
    fun toP2ReturnsExpectedResultIfGroupElementHasP2Representation() {
        for (i in 0..9) {
            // Arrange:
            val g = MathUtils.toRepresentation(MathUtils.getRandomGroupElement(), Representation.P2)

            // Act:
            val h = g.toP2()

            // Assert:
            Assert.assertThat(h, IsEqual.equalTo(g))
            Assert.assertThat<Representation>(h.representation, IsEqual.equalTo<Representation>(Representation.P2))
            Assert.assertThat(h.x, IsEqual.equalTo(g.x))
            Assert.assertThat(h.y, IsEqual.equalTo(g.y))
            Assert.assertThat(h.z, IsEqual.equalTo(g.z))
            Assert.assertThat(h.t, IsEqual.equalTo<FieldElement>(null))
        }
    }

    @Test
    fun toP2ReturnsExpectedResultIfGroupElementHasP3Representation() {
        for (i in 0..9) {
            // Arrange:
            val g = MathUtils.getRandomGroupElement()

            // Act:
            val h1 = g.toP2()
            val h2 = MathUtils.toRepresentation(g, Representation.P2)

            // Assert:
            Assert.assertThat(h1, IsEqual.equalTo(h2))
            Assert.assertThat<Representation>(h1.representation, IsEqual.equalTo<Representation>(Representation.P2))
            Assert.assertThat(h1.x, IsEqual.equalTo(g.x))
            Assert.assertThat(h1.y, IsEqual.equalTo(g.y))
            Assert.assertThat(h1.z, IsEqual.equalTo(g.z))
            Assert.assertThat(h1.t, IsEqual.equalTo<FieldElement>(null))
        }
    }

    @Test
    fun toP2ReturnsExpectedResultIfGroupElementHasP1P1Representation() {
        for (i in 0..9) {
            // Arrange:
            val g = MathUtils.toRepresentation(MathUtils.getRandomGroupElement(), Representation.P1P1)

            // Act:
            val h1 = g.toP2()
            val h2 = MathUtils.toRepresentation(g, Representation.P2)

            // Assert:
            Assert.assertThat(h1, IsEqual.equalTo(h2))
            Assert.assertThat<Representation>(h1.representation, IsEqual.equalTo<Representation>(Representation.P2))
            Assert.assertThat(h1.x, IsEqual.equalTo(g.x.multiply(g.t)))
            Assert.assertThat(h1.y, IsEqual.equalTo(g.y.multiply(g.z)))
            Assert.assertThat(h1.z, IsEqual.equalTo(g.z.multiply(g.t)))
            Assert.assertThat(h1.t, IsEqual.equalTo<FieldElement>(null))
        }
    }

    @Test(expected = IllegalArgumentException::class)
    fun toP3ThrowsIfGroupElementHasP2Representation() {
        // Arrange:
        val g = MathUtils.toRepresentation(MathUtils.getRandomGroupElement(), Representation.P2)

        // Assert:
        g.toP3()
    }

    @Test(expected = IllegalArgumentException::class)
    fun toP3ThrowsIfGroupElementHasPrecompRepresentation() {
        // Arrange:
        val g = MathUtils.toRepresentation(MathUtils.getRandomGroupElement(), Representation.PRECOMP)

        // Assert:
        g.toP3()
    }

    @Test(expected = IllegalArgumentException::class)
    fun toP3ThrowsIfGroupElementHasCachedRepresentation() {
        // Arrange:
        val g = MathUtils.toRepresentation(MathUtils.getRandomGroupElement(), Representation.CACHED)

        // Assert:
        g.toP3()
    }

    @Test
    fun toP3ReturnsExpectedResultIfGroupElementHasP1P1Representation() {
        for (i in 0..9) {
            // Arrange:
            val g = MathUtils.toRepresentation(MathUtils.getRandomGroupElement(), Representation.P1P1)

            // Act:
            val h1 = g.toP3()
            val h2 = MathUtils.toRepresentation(g, Representation.P3)

            // Assert:
            Assert.assertThat(h1, IsEqual.equalTo(h2))
            Assert.assertThat<Representation>(h1.representation, IsEqual.equalTo<Representation>(Representation.P3))
            Assert.assertThat(h1.x, IsEqual.equalTo(g.x.multiply(g.t)))
            Assert.assertThat(h1.y, IsEqual.equalTo(g.y.multiply(g.z)))
            Assert.assertThat(h1.z, IsEqual.equalTo(g.z.multiply(g.t)))
            Assert.assertThat(h1.t, IsEqual.equalTo(g.x.multiply(g.y)))
        }
    }

    @Test
    fun toP3ReturnsExpectedResultIfGroupElementHasP3Representation() {
        for (i in 0..9) {
            // Arrange:
            val g = MathUtils.getRandomGroupElement()

            // Act:
            val h = g.toP3()

            // Assert:
            Assert.assertThat(h, IsEqual.equalTo(g))
            Assert.assertThat<Representation>(h.representation, IsEqual.equalTo<Representation>(Representation.P3))
            Assert.assertThat(h, IsEqual.equalTo(g))
            Assert.assertThat(h.x, IsEqual.equalTo(g.x))
            Assert.assertThat(h.y, IsEqual.equalTo(g.y))
            Assert.assertThat(h.z, IsEqual.equalTo(g.z))
            Assert.assertThat(h.t, IsEqual.equalTo(g.t))
        }
    }

    @Test(expected = IllegalArgumentException::class)
    fun toCachedThrowsIfGroupElementHasP2Representation() {
        // Arrange:
        val g = MathUtils.toRepresentation(MathUtils.getRandomGroupElement(), Representation.P2)

        // Assert:
        g.toCached()
    }

    @Test(expected = IllegalArgumentException::class)
    fun toCachedThrowsIfGroupElementHasPrecompRepresentation() {
        // Arrange:
        val g = MathUtils.toRepresentation(MathUtils.getRandomGroupElement(), Representation.PRECOMP)

        // Assert:
        g.toCached()
    }

    @Test(expected = IllegalArgumentException::class)
    fun toCachedThrowsIfGroupElementHasP1P1Representation() {
        // Arrange:
        val g = MathUtils.toRepresentation(MathUtils.getRandomGroupElement(), Representation.P1P1)

        // Assert:
        g.toCached()
    }

    @Test
    fun toCachedReturnsExpectedResultIfGroupElementHasCachedRepresentation() {
        for (i in 0..9) {
            // Arrange:
            val g = MathUtils.toRepresentation(MathUtils.getRandomGroupElement(), Representation.CACHED)

            // Act:
            val h = g.toCached()

            // Assert:
            Assert.assertThat(h, IsEqual.equalTo(g))
            Assert.assertThat<Representation>(h.representation, IsEqual.equalTo<Representation>(Representation.CACHED))
            Assert.assertThat(h, IsEqual.equalTo(g))
            Assert.assertThat(h.x, IsEqual.equalTo(g.x))
            Assert.assertThat(h.y, IsEqual.equalTo(g.y))
            Assert.assertThat(h.z, IsEqual.equalTo(g.z))
            Assert.assertThat(h.t, IsEqual.equalTo(g.t))
        }
    }

    @Test
    fun toCachedReturnsExpectedResultIfGroupElementHasP3Representation() {
        for (i in 0..9) {
            // Arrange:
            val g = MathUtils.getRandomGroupElement()

            // Act:
            val h1 = g.toCached()
            val h2 = MathUtils.toRepresentation(g, Representation.CACHED)

            // Assert:
            Assert.assertThat(h1, IsEqual.equalTo(h2))
            Assert.assertThat<Representation>(h1.representation, IsEqual.equalTo<Representation>(Representation.CACHED))
            Assert.assertThat(h1, IsEqual.equalTo(g))
            Assert.assertThat(h1.x, IsEqual.equalTo(g.y.add(g.x)))
            Assert.assertThat(h1.y, IsEqual.equalTo(g.y.subtract(g.x)))
            Assert.assertThat(h1.z, IsEqual.equalTo(g.z))
            Assert.assertThat(h1.t, IsEqual.equalTo(g.t.multiply(curve.d2)))
        }
    }

    // endregion

    /**
     * Test method for [GroupElement.precompute].
     */
    @Test
    fun testPrecompute() {
        val B = ed25519.b
        val testPrecmp = PrecomputationTestVectors.testPrecmp
        val precmp = B.precmp
        assertThat(precmp, `is`(equalTo(testPrecmp)))
        val testDblPrecmp = PrecomputationTestVectors.testDblPrecmp
        assertThat(B.dblPrecmp, `is`(equalTo(testDblPrecmp)))
    }

    @Test
    fun precomputedTableContainsExpectedGroupElements() {
        // Arrange:
        var g = ed25519.b

        // Act + Assert:
        for (i in 0..31) {
            var h = g
            for (j in 0..7) {
                Assert.assertThat(MathUtils.toRepresentation(h, Representation.PRECOMP), IsEqual.equalTo(ed25519.b.precmp[i][j]))
                h = MathUtils.addGroupElements(h, g)
            }
            for (k in 0..7) {
                g = MathUtils.addGroupElements(g, g)
            }
        }
    }

    @Test
    fun dblPrecomputedTableContainsExpectedGroupElements() {
        // Arrange:
        var g = ed25519.b
        val h = MathUtils.addGroupElements(g, g)

        // Act + Assert:
        for (i in 0..7) {
            Assert.assertThat(MathUtils.toRepresentation(g, Representation.PRECOMP), IsEqual.equalTo(ed25519.b.dblPrecmp[i]))
            g = MathUtils.addGroupElements(g, h)
        }
    }

    /**
     * Test method for [GroupElement.dbl].
     */
    @Test
    fun testDbl() {
        val B = ed25519.b
        // 2 * B = B + B
        assertThat(B.dbl(), `is`(equalTo(B.add(B.toCached()))))
    }

    @Test
    fun dblReturnsExpectedResult() {
        for (i in 0..999) {
            // Arrange:
            val g = MathUtils.getRandomGroupElement()

            // Act:
            val h1 = g.dbl()
            val h2 = MathUtils.doubleGroupElement(g)

            // Assert:
            Assert.assertThat(h2, IsEqual.equalTo(h1))
        }
    }

    @Test
    fun addingNeutralGroupElementDoesNotChangeGroupElement() {
        val neutral = GroupElement.p3(curve, curve.field.ZERO, curve.field.ONE, curve.field.ONE, curve.field.ZERO)
        for (i in 0..999) {
            // Arrange:
            val g = MathUtils.getRandomGroupElement()

            // Act:
            val h1 = g.add(neutral.toCached())
            val h2 = neutral.add(g.toCached())

            // Assert:
            Assert.assertThat(g, IsEqual.equalTo(h1))
            Assert.assertThat(g, IsEqual.equalTo(h2))
        }
    }

    @Test
    fun addReturnsExpectedResult() {
        for (i in 0..999) {
            // Arrange:
            val g1 = MathUtils.getRandomGroupElement()
            val g2 = MathUtils.getRandomGroupElement()

            // Act:
            val h1 = g1.add(g2.toCached())
            val h2 = MathUtils.addGroupElements(g1, g2)

            // Assert:
            Assert.assertThat(h2, IsEqual.equalTo(h1))
        }
    }

    @Test
    fun subReturnsExpectedResult() {
        for (i in 0..999) {
            // Arrange:
            val g1 = MathUtils.getRandomGroupElement()
            val g2 = MathUtils.getRandomGroupElement()

            // Act:
            val h1 = g1.sub(g2.toCached())
            val h2 = MathUtils.addGroupElements(g1, MathUtils.negateGroupElement(g2))

            // Assert:
            Assert.assertThat(h2, IsEqual.equalTo(h1))
        }
    }

    // region hashCode / equals
    /**
     * Test method for [GroupElement.equals].
     */
    @Test
    fun testEqualsObject() {
        assertThat(GroupElement.p2(curve, ZERO, ONE, ONE),
                `is`(equalTo(P2_ZERO)))
    }

    @Test
    fun equalsOnlyReturnsTrueForEquivalentObjects() {
        // Arrange:
        val g1 = MathUtils.getRandomGroupElement()
        val g2 = MathUtils.toRepresentation(g1, Representation.P2)
        val g3 = MathUtils.toRepresentation(g1, Representation.CACHED)
        val g4 = MathUtils.toRepresentation(g1, Representation.P1P1)
        val g5 = MathUtils.getRandomGroupElement()

        // Assert
        Assert.assertThat(g2, IsEqual.equalTo(g1))
        Assert.assertThat(g3, IsEqual.equalTo(g1))
        Assert.assertThat(g1, IsEqual.equalTo(g4))
        Assert.assertThat(g1, IsNot.not(IsEqual.equalTo(g5)))
        Assert.assertThat(g2, IsNot.not(IsEqual.equalTo(g5)))
        Assert.assertThat(g3, IsNot.not(IsEqual.equalTo(g5)))
        Assert.assertThat(g5, IsNot.not(IsEqual.equalTo(g4)))
    }

    @Test
    fun hashCodesAreEqualForEquivalentObjects() {
        // Arrange:
        val g1 = MathUtils.getRandomGroupElement()
        val g2 = MathUtils.toRepresentation(g1, Representation.P2)
        val g3 = MathUtils.toRepresentation(g1, Representation.P1P1)
        val g4 = MathUtils.getRandomGroupElement()

        // Assert
        Assert.assertThat(g2.hashCode(), IsEqual.equalTo(g1.hashCode()))
        Assert.assertThat(g3.hashCode(), IsEqual.equalTo(g1.hashCode()))
        Assert.assertThat(g1.hashCode(), IsNot.not(IsEqual.equalTo(g4.hashCode())))
        Assert.assertThat(g2.hashCode(), IsNot.not(IsEqual.equalTo(g4.hashCode())))
        Assert.assertThat(g3.hashCode(), IsNot.not(IsEqual.equalTo(g4.hashCode())))
    }

    /**
     * Test method for [GroupElement.toRadix16].
     */
    @Test
    fun testToRadix16() {
        assertThat(GroupElement.toRadix16(BYTES_ZERO), `is`(RADIX16_ZERO))
        assertThat(GroupElement.toRadix16(BYTES_ONE), `is`(RADIX16_ONE))
        assertThat(GroupElement.toRadix16(BYTES_42), `is`(RADIX16_42))

        val from1234567890 = GroupElement.toRadix16(BYTES_1234567890)
        var total = 0
        for (i in from1234567890.indices) {
            assertThat(from1234567890[i], `is`(greaterThanOrEqualTo((-8).toByte())))
            assertThat(from1234567890[i], `is`(lessThanOrEqualTo(8.toByte())))
            total += (from1234567890[i] * Math.pow(16.0, i.toDouble())).toInt()
        }
        assertThat(total, `is`(1234567890))

        val pkrR16 = GroupElement.toRadix16(BYTES_PKR)
        for (i in pkrR16.indices) {
            assertThat(pkrR16[i], `is`(greaterThanOrEqualTo((-8).toByte())))
            assertThat(pkrR16[i], `is`(lessThanOrEqualTo(8.toByte())))
        }
    }

    /**
     * Test method for [GroupElement.cmov].
     */
    @Test
    fun testCmov() {
        val a = curve.getZero(Representation.PRECOMP)
        val b = GroupElement.precomp(curve, TWO, ZERO, TEN)
        assertThat(a!!.cmov(b, 0), `is`(equalTo(a)))
        assertThat(a.cmov(b, 1), `is`(equalTo(b)))
    }

    /**
     * Test method for [GroupElement.select].
     */
    @Test
    fun testSelect() {
        val B = ed25519.b
        for (i in 0..31) {
            // 16^i 0 B
            assertThat(i.toString() + ",0", B.select(i, 0),
                    `is`(equalTo(GroupElement.precomp(curve, ONE, ONE, ZERO))))
            for (j in 1..7) {
                // 16^i r_i B
                var t = B.select(i, j)
                assertThat(i.toString() + "," + j,
                        t, `is`(equalTo(B.precmp[i][j - 1])))
                // -16^i r_i B
                t = B.select(i, -j)
                val neg = GroupElement.precomp(curve,
                        B.precmp[i][j - 1].Y,
                        B.precmp[i][j - 1].X,
                        B.precmp[i][j - 1].Z.negate())
                assertThat(i.toString() + "," + -j,
                        t, `is`(equalTo(neg)))
            }
        }
    }

    // region scalar multiplication
    /**
     * Test method for [GroupElement.scalarMultiply].
     * Test values generated with Python Ed25519 implementation.
     */
    @Test
    fun testScalarMultiplyByteArray() {
        // Little-endian
        val zero = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000")
        val one = Utils.hexToBytes("0100000000000000000000000000000000000000000000000000000000000000")
        val two = Utils.hexToBytes("0200000000000000000000000000000000000000000000000000000000000000")
        val a = Utils.hexToBytes("d072f8dd9c07fa7bc8d22a4b325d26301ee9202f6db89aa7c3731529e37e437c")
        val A = GroupElement(curve, Utils.hexToBytes("d4cf8595571830644bd14af416954d09ab7159751ad9e0f7a6cbd92379e71a66"))

        assertThat("scalarMultiply(0) failed",
                ed25519.b.scalarMultiply(zero), `is`(equalTo(curve.getZero(Representation.P3))))
        assertThat("scalarMultiply(1) failed",
                ed25519.b.scalarMultiply(one), `is`(equalTo(ed25519.b)))
        assertThat("scalarMultiply(2) failed",
                ed25519.b.scalarMultiply(two), `is`(equalTo(ed25519.b.dbl())))

        assertThat("scalarMultiply(a) failed",
                ed25519.b.scalarMultiply(a), `is`(equalTo(A)))
    }

    @Test
    fun scalarMultiplyBasePointWithZeroReturnsNeutralElement() {
        // Arrange:
        val basePoint = ed25519.b

        // Act:
        val g = basePoint.scalarMultiply(curve.field.ZERO.toByteArray())

        // Assert:
        Assert.assertThat(curve.getZero(Representation.P3), IsEqual.equalTo(g))
    }

    @Test
    fun scalarMultiplyBasePointWithOneReturnsBasePoint() {
        // Arrange:
        val basePoint = ed25519.b

        // Act:
        val g = basePoint.scalarMultiply(curve.field.ONE.toByteArray())

        // Assert:
        Assert.assertThat(basePoint, IsEqual.equalTo(g))
    }

    // This test is slow (~6s) due to math utils using an inferior algorithm to calculate the result.
    @Test
    fun scalarMultiplyBasePointReturnsExpectedResult() {
        for (i in 0..9) {
            // Arrange:
            val basePoint = ed25519.b
            val f = MathUtils.getRandomFieldElement()

            // Act:
            val g = basePoint.scalarMultiply(f.toByteArray())
            val h = MathUtils.scalarMultiplyGroupElement(basePoint, f)

            // Assert:
            Assert.assertThat(g, IsEqual.equalTo(h))
        }
    }

    @Test
    fun testDoubleScalarMultiplyVariableTime() {
        // Little-endian
        val zero = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000")
        val one = Utils.hexToBytes("0100000000000000000000000000000000000000000000000000000000000000")
        val two = Utils.hexToBytes("0200000000000000000000000000000000000000000000000000000000000000")
        val a = Utils.hexToBytes("d072f8dd9c07fa7bc8d22a4b325d26301ee9202f6db89aa7c3731529e37e437c")
        val A = GroupElement(curve, Utils.hexToBytes("d4cf8595571830644bd14af416954d09ab7159751ad9e0f7a6cbd92379e71a66"))
        val B = ed25519.b
        val geZero = curve.getZero(Representation.P3)
        geZero!!.precompute(false)

        // 0 * GE(0) + 0 * GE(0) = GE(0)
        assertThat(geZero.doubleScalarMultiplyVariableTime(geZero, zero, zero),
                `is`(equalTo(geZero)))
        // 0 * GE(0) + 0 * B = GE(0)
        assertThat(B.doubleScalarMultiplyVariableTime(geZero, zero, zero),
                `is`(equalTo(geZero)))
        // 1 * GE(0) + 0 * B = GE(0)
        assertThat(B.doubleScalarMultiplyVariableTime(geZero, one, zero),
                `is`(equalTo(geZero)))
        // 1 * GE(0) + 1 * B = B
        assertThat(B.doubleScalarMultiplyVariableTime(geZero, one, one),
                `is`(equalTo(B)))
        // 1 * B + 1 * B = 2 * B
        assertThat(B.doubleScalarMultiplyVariableTime(B, one, one),
                `is`(equalTo(B.dbl())))
        // 1 * B + 2 * B = 3 * B
        assertThat(B.doubleScalarMultiplyVariableTime(B, one, two),
                `is`(equalTo(B.dbl().toP3().add(B.toCached()))))
        // 2 * B + 2 * B = 4 * B
        assertThat(B.doubleScalarMultiplyVariableTime(B, two, two),
                `is`(equalTo(B.dbl().toP3().dbl())))

        // 0 * B + a * B = A
        assertThat(B.doubleScalarMultiplyVariableTime(B, zero, a),
                `is`(equalTo(A)))
        // a * B + 0 * B = A
        assertThat(B.doubleScalarMultiplyVariableTime(B, a, zero),
                `is`(equalTo(A)))
        // a * B + a * B = 2 * A
        assertThat(B.doubleScalarMultiplyVariableTime(B, a, a),
                `is`(equalTo(A.dbl())))
    }

    // This test is slow (~6s) due to math utils using an inferior algorithm to calculate the result.
    @Test
    fun doubleScalarMultiplyVariableTimeReturnsExpectedResult() {
        for (i in 0..9) {
            // Arrange:
            val basePoint = ed25519.b
            val g = MathUtils.getRandomGroupElement()
            g.precompute(false)
            val f1 = MathUtils.getRandomFieldElement()
            val f2 = MathUtils.getRandomFieldElement()

            // Act:
            val h1 = basePoint.doubleScalarMultiplyVariableTime(g, f2.toByteArray(), f1.toByteArray())
            val h2 = MathUtils.doubleScalarMultiplyGroupElements(basePoint, f1, g, f2)

            // Assert:
            Assert.assertThat(h1, IsEqual.equalTo(h2))
        }
    }

    // endregion

    /**
     * Test method for [GroupElement.isOnCurve].
     */
    @Test
    fun testIsOnCurve() {
        assertThat(P2_ZERO.isOnCurve(curve),
                `is`(true))
        assertThat(GroupElement.p2(curve, ZERO, ZERO, ONE).isOnCurve(curve),
                `is`(false))
        assertThat(GroupElement.p2(curve, ONE, ONE, ONE).isOnCurve(curve),
                `is`(false))
        assertThat(GroupElement.p2(curve, TEN, ZERO, ONE).isOnCurve(curve),
                `is`(false))
        assertThat(GroupElement.p2(curve, ONE, TEN, ONE).isOnCurve(curve),
                `is`(false))
        assertThat(GroupElement.p2(curve, PKR[0], PKR[1], ONE).isOnCurve(curve),
                `is`(true))
    }

    @Test
    fun isOnCurveReturnsTrueForPointsOnTheCurve() {
        for (i in 0..99) {
            // Arrange:
            val g = MathUtils.getRandomGroupElement()

            // Assert:
            Assert.assertThat(g.isOnCurve, IsEqual.equalTo(true))
        }
    }

    @Test
    fun isOnCurveReturnsFalseForPointsNotOnTheCurve() {
        for (i in 0..99) {
            // Arrange:
            val g = MathUtils.getRandomGroupElement()
            val h = GroupElement.p2(curve, g.x, g.y, g.z.multiply(curve.field.TWO))

            // Assert (can only fail for 5*Z^2=1):
            Assert.assertThat(h.isOnCurve, IsEqual.equalTo(false))
        }
    }

    companion object {
        internal val BYTES_ZEROZERO = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000")
        internal val BYTES_ONEONE = Utils.hexToBytes("0100000000000000000000000000000000000000000000000000000000000080")
        internal val BYTES_TENZERO = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000")
        internal val BYTES_ONETEN = Utils.hexToBytes("0a00000000000000000000000000000000000000000000000000000000000080")

        internal val ed25519 = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)
        internal val curve = ed25519.curve

        internal val ZERO = curve.field.ZERO
        internal val ONE = curve.field.ONE
        internal val TWO = curve.field.TWO
        internal val TEN = curve.field.fromByteArray(Utils.hexToBytes("0a00000000000000000000000000000000000000000000000000000000000000"))

        internal val P2_ZERO = GroupElement.p2(curve, ZERO, ONE, ONE)

        internal val PKR = arrayOf(curve.field.fromByteArray(Utils.hexToBytes("5849722e338aced7b50c7f0e9328f9a10c847b08e40af5c5b0577b0fd8984f15")), curve.field.fromByteArray(Utils.hexToBytes("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29")))
        internal val BYTES_PKR = Utils.hexToBytes("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29")

        // endregion

        internal val BYTES_ZERO = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000")
        internal val BYTES_ONE = Utils.hexToBytes("0100000000000000000000000000000000000000000000000000000000000000")
        internal val BYTES_42 = Utils.hexToBytes("2A00000000000000000000000000000000000000000000000000000000000000")
        internal val BYTES_1234567890 = Utils.hexToBytes("D202964900000000000000000000000000000000000000000000000000000000")

        internal val RADIX16_ZERO = Utils.hexToBytes("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
        internal val RADIX16_ONE = Utils.hexToBytes("01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
        internal val RADIX16_42 = Utils.hexToBytes("FA030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
    }
}
