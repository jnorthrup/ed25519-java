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
import net.i2p.crypto.eddsa.spec.*
import org.hamcrest.core.*
import org.junit.*
import org.junit.rules.ExpectedException

import java.math.BigInteger
import java.util.Arrays

import org.hamcrest.Matchers.*
import org.junit.Assert.assertThat

/**
 * @author str4d
 * Additional tests by NEM project team.
 */
class GroupElementTest {

    @Rule public  var exception = ExpectedException.none()

    /**
     * Test method for [BaseGroupElement.p2].
     */
    @Test
    fun testP2() {
        val t = P2GroupElement(curve, ZERO, ONE, ONE)
        assertThat(t.curve, `is`(equalTo(curve)))
        assertThat(t.repr, `is`(Representation.P2))
        assertThat(t.x, `is`(ZERO))
        assertThat(t.y, `is`(ONE))
        assertThat(t.z, `is`(ONE))
        assertThat(t.t, `is`<FieldElement>(null as FieldElement?))
    }

    /**
     * Test method for [BaseGroupElement.p3].
     */
    @Test
    fun testP3() {
        /**
         * Creates a new group element in P3 representation.
         *
         * @param curve The curve.
         * @param X The $X$ coordinate.
         * @param Y The $Y$ coordinate.
         * @param Z The $Z$ coordinate.
         * @param T The $T$ coordinate.
         * @param precomputeDoubleOnly If true, populate dblPrecmp, else set to null.
         * @return The group element in P3 representation.
         */
        val t = if (false) P3PreGroupElement(curve, ZERO, ONE, ONE, ZERO) else P3GroupElement(curve, ZERO, ONE, ONE, ZERO)
        assertThat(t.curve, `is`(equalTo(curve)))
        assertThat(t.repr, `is`(Representation.P3))
        assertThat(t.x, `is`(ZERO))
        assertThat(t.y, `is`(ONE))
        assertThat(t.z, `is`(ONE))
        assertThat(t.t, `is`(ZERO))
    }

    /**
     * Test method for [BaseGroupElement.p1p1].
     */
    @Test
    fun testP1p1() {

        /**
         * Creates a new group element in P1P1 representation.
         *
         * @param curve The curve.
         * @param X The $X$ coordinate.
         * @param Y The $Y$ coordinate.
         * @param Z The $Z$ coordinate.
         * @param T The $T$ coordinate.
         * @return The group element in P1P1 representation.
         */
        val t = P1pGroupElement(curve, ZERO, ONE, ONE, ONE)
        assertThat(t.curve, `is`(equalTo(curve)))
        assertThat(t.repr, `is`(Representation.P1P1))
        assertThat(t.x, `is`(ZERO))
        assertThat(t.y, `is`(ONE))
        assertThat(t.z, `is`(ONE))
        assertThat(t.t, `is`(ONE))
    }

    /**
     * Test method for [BaseGroupElement.precomp].
     */
    @Test
    fun testPrecomp() {
        val t = PrecompGroupElement(curve, ONE, ONE, ZERO)
        assertThat(t.curve, `is`(equalTo(curve)))
        assertThat(t.repr, `is`(Representation.PRECOMP))
        assertThat(t.x, `is`(ONE))
        assertThat(t.y, `is`(ONE))
        assertThat(t.z, `is`(ZERO))
        assertThat(t.t, `is`<FieldElement>(null as FieldElement?))
    }

    /**
     * Test method for [BaseGroupElement.cached].
     */
    @Test
    fun testCached() {
        val t = CachedGroupElement(curve, ONE, ONE, ONE, ZERO)
        assertThat(t.curve, `is`(equalTo(curve)))
        assertThat(t.repr, `is`(Representation.CACHED))
        assertThat(t.x, `is`(ONE))
        assertThat(t.y, `is`(ONE))
        assertThat(t.z, `is`(ONE))
        assertThat(t.t, `is`(ZERO))
    }

    /**
     * Test method for [BaseGroupElement.GroupElement].
     */
    @Test
    fun testGroupElementCurveRepresentationFieldElementFieldElementFieldElementFieldElement() {
        val t = P3GroupElement(curve, ZERO, ONE, ONE, ZERO)
        assertThat(t.curve, `is`(equalTo(curve)))
        assertThat(t.repr, `is`(Representation.P3))
        assertThat(t.x, `is`(ZERO))
        assertThat(t.y, `is`(ONE))
        assertThat(t.z, `is`(ONE))
        assertThat(t.t, `is`(ZERO))
    }

    /**
     * Tests [BaseGroupElement.GroupElement] and
     * [BaseGroupElement.toByteArray] against valid public keys.
     */
    @Test
    fun testToAndFromByteArray() {
        var t: GroupElement
        val iterator = Ed25519TestVectors.testCases.iterator()
        while (iterator.hasNext()) {
            val testCase = iterator.next()
            t = P3GroupElement(curve, testCase.pk)
            assertThat("Test case " + testCase.caseNum + " failed",
                    t.toByteArray(), `is`(equalTo(testCase.pk)))
        }
    }

    /**
     * Test method for [BaseGroupElement.GroupElement].
     */
    @Test
    fun testGroupElementByteArray() {
        val t = P3GroupElement(curve, BYTES_PKR)
        val t1 = PKR[0].multiply(PKR[1])
        /**
         * Creates a new group element in P3 representation.
         *
         * @param curve The curve.
         * @param X The $X$ coordinate.
         * @param Y The $Y$ coordinate.
         * @param Z The $Z$ coordinate.
         * @param T The $T$ coordinate.
         * @param precomputeDoubleOnly If true, populate dblPrecmp, else set to null.
         * @return The group element in P3 representation.
         */
        val s = if (false) P3PreGroupElement(curve, PKR[0], PKR[1], ONE, t1) else P3GroupElement(curve, PKR[0], PKR[1], ONE, t1)
        assertThat<GroupElement>(t, `is`(equalTo<GroupElement>(s)))
    }

    @Test
    fun constructorUsingByteArrayReturnsExpectedResult() {
        var i = 0
        while (100 > i) {
            // Arrange:
            val g = MathUtils.randomGroupElement
            val bytes = g.toByteArray()

            // Act:
            val h1 = P3GroupElement(curve, bytes)
            val h2 = toGroupElement(bytes)

            // Assert:
            assertThat<GroupElement>(h1, IsEqual.equalTo(h2))
            i++
        }
    }

    /**
     * Test method for [BaseGroupElement.toByteArray].
     *
     *
     * TODO 20141001 BR: why test with points which are not on the curve?
     */
    @Test
    fun testToByteArray() {
        val zerozero = P2GroupElement(curve, ZERO, ZERO, ONE).toByteArray()
        assertThat(Integer.valueOf(zerozero.size), `is`(equalTo(Integer.valueOf(BYTES_ZEROZERO.size))))
        assertThat(zerozero, `is`(equalTo(BYTES_ZEROZERO)))

        val oneone = P2GroupElement(curve, ONE, ONE, ONE).toByteArray()
        assertThat(Integer.valueOf(oneone.size), `is`(equalTo(Integer.valueOf(BYTES_ONEONE.size))))
        assertThat(oneone, `is`(equalTo(BYTES_ONEONE)))

        val tenzero = P2GroupElement(curve, TEN, ZERO, ONE).toByteArray()
        assertThat(Integer.valueOf(tenzero.size), `is`(equalTo(Integer.valueOf(BYTES_TENZERO.size))))
        assertThat(tenzero, `is`(equalTo(BYTES_TENZERO)))

        val oneten = P2GroupElement(curve, ONE, TEN, ONE).toByteArray()
        assertThat(Integer.valueOf(oneten.size), `is`(equalTo(Integer.valueOf(BYTES_ONETEN.size))))
        assertThat(oneten, `is`(equalTo(BYTES_ONETEN)))

        val pkr = P2GroupElement(curve, PKR[0], PKR[1], ONE).toByteArray()
        assertThat(Integer.valueOf(pkr.size), `is`(equalTo(Integer.valueOf(BYTES_PKR.size))))
        assertThat(pkr, `is`(equalTo(BYTES_PKR)))
    }

    @Test
    fun toByteArrayReturnsExpectedResult() {
        var i = 0
        while (100 > i) {
            // Arrange:
            val g = MathUtils.randomGroupElement

            // Act:
            val gBytes = g.toByteArray()
            val bytes = MathUtils.toByteArray(MathUtils.toBigInteger(g.y))
            if (MathUtils.toBigInteger(g.x).mod(BigInteger("2")) == BigInteger.ONE) {
                bytes[31] = (bytes[31] as Int or 0x80).toByte()
            }

            // Assert:
            assertThat(java.lang.Boolean.valueOf(Arrays.equals(gBytes, bytes)), IsEqual.equalTo(java.lang.Boolean.TRUE))
            i++
        }
    }

    // region toX where X is the representation

    /**
     * Test method for [BaseGroupElement.toP2].
     */
    @Test
    fun testToP2() {
        val p3zero = curve.get(Representation.P3)
        val t = Representation.P2.toRep(p3zero)
        assertThat(t.repr, `is`(Representation.P2))
        assertThat(t.x, `is`(p3zero.x))
        assertThat(t.y, `is`(p3zero.y))
        assertThat(t.z, `is`(p3zero.z))
        assertThat(t.t, `is`<FieldElement>(null as FieldElement?))

        val B = ed25519.groupElement
        val t2 = Representation.P2.toRep(B)
        assertThat(t2.repr, `is`(Representation.P2))
        assertThat(t2.x, `is`(B.x))
        assertThat(t2.y, `is`(B.y))
        assertThat(t2.z, `is`(B.z))
        assertThat(t2.t, `is`<FieldElement>(null as FieldElement?))
    }

    @Test(expected = IllegalArgumentException::class)
    fun toP2ThrowsIfGroupElementHasPrecompRepresentation() {
        // Arrange:
        val g = MathUtils.toRepresentation(MathUtils.randomGroupElement, Representation.PRECOMP)

        // Assert:
        Representation.P2.toRep(g)
    }

    @Test(expected = IllegalArgumentException::class)
    fun toP2ThrowsIfGroupElementHasCachedRepresentation() {
        // Arrange:
        val g = MathUtils.toRepresentation(MathUtils.randomGroupElement, Representation.CACHED)

        // Assert:
        Representation.P2.toRep(g)
    }

    @Test
    fun toP2ReturnsExpectedResultIfGroupElementHasP2Representation() {
        var i = 0
        while (10 > i) {
            // Arrange:
            val g = MathUtils.toRepresentation(MathUtils.randomGroupElement, Representation.P2)

            // Act:
            val h = Representation.P2.toRep(g)

            // Assert:
            assertThat(h, IsEqual.equalTo(g))
            assertThat(h.representation, IsEqual.equalTo(Representation.P2))
            assertThat(h.x, IsEqual.equalTo(g.x))
            assertThat(h.y, IsEqual.equalTo(g.y))
            assertThat(h.z, IsEqual.equalTo(g.z))
            assertThat(h.t, IsEqual.equalTo<FieldElement>(null))
            i++
        }
    }

    @Test
    fun toP2ReturnsExpectedResultIfGroupElementHasP3Representation() {
        var i = 0
        while (10 > i) {
            // Arrange:
            val g = MathUtils.randomGroupElement

            // Act:
            val h1 = Representation.P2.toRep(g)
            val h2 = MathUtils.toRepresentation(g, Representation.P2)

            // Assert:
            assertThat(h1, IsEqual.equalTo(h2))
            assertThat(h1.representation, IsEqual.equalTo(Representation.P2))
            assertThat(h1.x, IsEqual.equalTo(g.x))
            assertThat(h1.y, IsEqual.equalTo(g.y))
            assertThat(h1.z, IsEqual.equalTo(g.z))
            assertThat(h1.t, IsEqual.equalTo<FieldElement>(null))
            i++
        }
    }

    @Test
    fun toP2ReturnsExpectedResultIfGroupElementHasP1P1Representation() {
        var i = 0
        while (10 > i) {
            // Arrange:
            val g = MathUtils.toRepresentation(MathUtils.randomGroupElement, Representation.P1P1)

            // Act:
            val h1 = Representation.P2.toRep(g)
            val h2 = MathUtils.toRepresentation(g, Representation.P2)

            // Assert:
            assertThat(h1, IsEqual.equalTo(h2))
            assertThat(h1.representation, IsEqual.equalTo(Representation.P2))
            assertThat(h1.x, IsEqual.equalTo(g.x.multiply(g.t)))
            assertThat(h1.y, IsEqual.equalTo(g.y.multiply(g.z)))
            assertThat(h1.z, IsEqual.equalTo(g.z.multiply(g.t)))
            assertThat(h1.t, IsEqual.equalTo<FieldElement>(null))
            i++
        }
    }

    @Test(expected = IllegalArgumentException::class)
    fun toP3ThrowsIfGroupElementHasP2Representation() {
        // Arrange:
        val g = MathUtils.toRepresentation(MathUtils.randomGroupElement, Representation.P2)

        // Assert:
        Representation.P3.toRep(g)
    }

    @Test(expected = IllegalArgumentException::class)
    fun toP3ThrowsIfGroupElementHasPrecompRepresentation() {
        // Arrange:
        val g = MathUtils.toRepresentation(MathUtils.randomGroupElement, Representation.PRECOMP)

        // Assert:
        Representation.P3.toRep(g)
    }

    @Test(expected = IllegalArgumentException::class)
    fun toP3ThrowsIfGroupElementHasCachedRepresentation() {
        // Arrange:
        val g = MathUtils.toRepresentation(MathUtils.randomGroupElement, Representation.CACHED)

        // Assert:
        Representation.P3.toRep(g)
    }

    @Test
    fun toP3ReturnsExpectedResultIfGroupElementHasP1P1Representation() {
        var i = 0
        while (10 > i) {
            // Arrange:
            val g = MathUtils.toRepresentation(MathUtils.randomGroupElement, Representation.P1P1)

            // Act:
            val h1 = Representation.P3.toRep(g)
            val h2 = MathUtils.toRepresentation(g, Representation.P3)

            // Assert:
            assertThat(h1, IsEqual.equalTo(h2))
            assertThat(h1.representation, IsEqual.equalTo(Representation.P3))
            assertThat(h1.x, IsEqual.equalTo(g.x.multiply(g.t)))
            assertThat(h1.y, IsEqual.equalTo(g.y.multiply(g.z)))
            assertThat(h1.z, IsEqual.equalTo(g.z.multiply(g.t)))
            assertThat(h1.t, IsEqual.equalTo(g.x.multiply(g.y)))
            i++
        }
    }

    @Test
    fun toP3ReturnsExpectedResultIfGroupElementHasP3Representation() {
        var i = 0
        while (10 > i) {
            // Arrange:
            val g = MathUtils.randomGroupElement

            // Act:
            val h = Representation.P3.toRep(g)

            // Assert:
            assertThat(h, IsEqual.equalTo(g))
            assertThat(h.representation, IsEqual.equalTo(Representation.P3))
            assertThat(h, IsEqual.equalTo(g))
            assertThat(h.x, IsEqual.equalTo(g.x))
            assertThat(h.y, IsEqual.equalTo(g.y))
            assertThat(h.z, IsEqual.equalTo(g.z))
            assertThat(h.t, IsEqual.equalTo(g.t))
            i++
        }
    }

    @Test(expected = IllegalArgumentException::class)
    fun toCachedThrowsIfGroupElementHasP2Representation() {
        // Arrange:
        val g = MathUtils.toRepresentation(MathUtils.randomGroupElement, Representation.P2)

        // Assert:
        Representation.CACHED.toRep(g)
    }

    @Test(expected = IllegalArgumentException::class)
    fun toCachedThrowsIfGroupElementHasPrecompRepresentation() {
        // Arrange:
        val g = MathUtils.toRepresentation(MathUtils.randomGroupElement, Representation.PRECOMP)

        // Assert:
        Representation.CACHED.toRep(g)
    }

    @Test(expected = IllegalArgumentException::class)
    fun toCachedThrowsIfGroupElementHasP1P1Representation() {
        // Arrange:
        val g = MathUtils.toRepresentation(MathUtils.randomGroupElement, Representation.P1P1)

        // Assert:
        Representation.CACHED.toRep(g)
    }

    @Test
    fun toCachedReturnsExpectedResultIfGroupElementHasCachedRepresentation() {
        var i = 0
        while (10 > i) {
            // Arrange:
            val g = MathUtils.toRepresentation(MathUtils.randomGroupElement, Representation.CACHED)

            // Act:
            val h = Representation.CACHED.toRep(g)

            // Assert:
            assertThat(h, IsEqual.equalTo(g))
            assertThat(h.representation, IsEqual.equalTo(Representation.CACHED))
            assertThat(h, IsEqual.equalTo(g))
            assertThat(h.x, IsEqual.equalTo(g.x))
            assertThat(h.y, IsEqual.equalTo(g.y))
            assertThat(h.z, IsEqual.equalTo(g.z))
            assertThat(h.t, IsEqual.equalTo(g.t))
            i++
        }
    }

    @Test
    fun toCachedReturnsExpectedResultIfGroupElementHasP3Representation() {
        var i = 0
        while (10 > i) {
            // Arrange:
            val g = MathUtils.randomGroupElement

            // Act:
            val h1 = Representation.CACHED.toRep(g)
            val h2 = MathUtils.toRepresentation(g, Representation.CACHED)

            // Assert:
            assertThat(h1, IsEqual.equalTo(h2))
            assertThat(h1.representation, IsEqual.equalTo(Representation.CACHED))
            assertThat(h1, IsEqual.equalTo(g))
            assertThat(h1.x, IsEqual.equalTo(g.y.add(g.x)))
            assertThat(h1.y, IsEqual.equalTo(g.y.subtract(g.x)))
            assertThat(h1.z, IsEqual.equalTo(g.z))
            assertThat(h1.t, IsEqual.equalTo(g.t.multiply(curve.d2)))
            i++
        }
    }

    // endregion

    /**
     * Test method for precomputation.
     */
    @Test
    fun testPrecompute() {
        val B = ed25519.groupElement
        assertThat(B.precmp, `is`(equalTo(PrecomputationTestVectors.testPrecmp)))
        assertThat(B.dblPrecmp, `is`(equalTo(PrecomputationTestVectors.testDblPrecmp)))
    }

    @Test
    fun precomputedTableContainsExpectedGroupElements() {
        // Arrange:
        var g = ed25519.groupElement

        // Act + Assert:
        var i = 0
        while (32 > i) {
            var h = g
            var j = 0
            while (8 > j) {
                assertThat(MathUtils.toRepresentation(h, Representation.PRECOMP), IsEqual.equalTo(ed25519.groupElement.precmp!![i][j]))
                h = MathUtils.addGroupElements(h, g)
                j++
            }
            var k = 0
            while (8 > k) {
                g = MathUtils.addGroupElements(g, g)
                k++
            }
            i++
        }
    }

    @Test
    fun dblPrecomputedTableContainsExpectedGroupElements() {
        // Arrange:
        var g = ed25519.groupElement
        val h = MathUtils.addGroupElements(g, g)

        // Act + Assert:
        var i = 0
        while (8 > i) {
            assertThat(MathUtils.toRepresentation(g, Representation.PRECOMP), IsEqual.equalTo(ed25519.groupElement.dblPrecmp!![i]))
            g = MathUtils.addGroupElements(g, h)
            i++
        }
    }

    /**
     * Test method for [BaseGroupElement.dbl].
     */
    @Test
    fun testDbl() {
        val B = ed25519.groupElement
        // 2 * B = B + B
        assertThat(B.dbl(), `is`(equalTo(B.add(Representation.CACHED.toRep(B)))))
    }

    @Test
    fun dblReturnsExpectedResult() {
        var i = 0
        while (1000 > i) {
            // Arrange:
            val g = MathUtils.randomGroupElement

            // Act:
            val h1 = g.dbl()
            val h2 = MathUtils.doubleGroupElement(g)

            // Assert:
            assertThat(h2, IsEqual.equalTo(h1))
            i++
        }
    }

    @Test
    fun addingNeutralGroupElementDoesNotChangeGroupElement() {
        /**
         * Creates a new group element in P3 representation.
         *
         * @param curve The curve.
         * @param X The $X$ coordinate.
         * @param Y The $Y$ coordinate.
         * @param Z The $Z$ coordinate.
         * @param T The $T$ coordinate.
         * @param precomputeDoubleOnly If true, populate dblPrecmp, else set to null.
         * @return The group element in P3 representation.
         */
        val neutral = if (false) P3PreGroupElement(curve, curve.edDSAFiniteField.ZERO, curve.edDSAFiniteField.ONE, curve.edDSAFiniteField.ONE, curve.edDSAFiniteField.ZERO) else P3GroupElement(curve, curve.edDSAFiniteField.ZERO, curve.edDSAFiniteField.ONE, curve.edDSAFiniteField.ONE, curve.edDSAFiniteField.ZERO)
        var i = 0
        while (1000 > i) {
            // Arrange:
            val g = MathUtils.randomGroupElement

            // Act:
            val h1 = g.add(Representation.CACHED.toRep(neutral))
            val h2 = neutral.add(Representation.CACHED.toRep(g))

            // Assert:
            assertThat(g, IsEqual.equalTo<GroupElement>(h1))
            assertThat(g, IsEqual.equalTo(h2))
            i++
        }
    }

    @Test
    fun addReturnsExpectedResult() {
        var i = 0
        while (1000 > i) {
            // Arrange:
            val g1 = MathUtils.randomGroupElement
            val g2 = MathUtils.randomGroupElement

            // Act:
            val h1 = g1.add(Representation.CACHED.toRep(g2))
            val h2 = MathUtils.addGroupElements(g1, g2)

            // Assert:
            assertThat(h2, IsEqual.equalTo(h1))
            i++
        }
    }

    @Test
    fun subReturnsExpectedResult() {
        var i = 0
        while (1000 > i) {
            // Arrange:
            val g1 = MathUtils.randomGroupElement
            val g2 = MathUtils.randomGroupElement

            // Act:
            val h1 = g1.sub(Representation.CACHED.toRep(g2))
            val h2 = MathUtils.addGroupElements(g1, negateGroupElement(g2))

            // Assert:
            assertThat(h2, IsEqual.equalTo(h1))
            i++
        }
    }

    // region hashCode / equals
    /**
     * Test method for [BaseGroupElement.equals].
     */
    @Test
    fun testEqualsObject() {
        assertThat(P2GroupElement(curve, ZERO, ONE, ONE),
                `is`(equalTo<GroupElement>(P2_ZERO)))
    }

    @Test
    fun equalsOnlyReturnsTrueForEquivalentObjects() {
        // Arrange:
        val g1 = MathUtils.randomGroupElement
        val g2 = MathUtils.toRepresentation(g1, Representation.P2)
        val g3 = MathUtils.toRepresentation(g1, Representation.CACHED)
        val g4 = MathUtils.toRepresentation(g1, Representation.P1P1)
        val g5 = MathUtils.randomGroupElement

        // Assert
        assertThat(g2, IsEqual.equalTo(g1))
        assertThat(g3, IsEqual.equalTo(g1))
        assertThat(g1, IsEqual.equalTo(g4))
        assertThat(g1, IsNot.not(IsEqual.equalTo<GroupElement>(g5)))
        assertThat(g2, IsNot.not(IsEqual.equalTo(g5)))
        assertThat(g3, IsNot.not(IsEqual.equalTo(g5)))
        assertThat(g5, IsNot.not(IsEqual.equalTo(g4)))
    }

    @Test
    fun hashCodesAreEqualForEquivalentObjects() {
        // Arrange:
        val g1 = MathUtils.randomGroupElement
        val g2 = MathUtils.toRepresentation(g1, Representation.P2)
        val g3 = MathUtils.toRepresentation(g1, Representation.P1P1)
        val g4 = MathUtils.randomGroupElement

        // Assert
        assertThat(Integer.valueOf(g2.hashCode()), IsEqual.equalTo(Integer.valueOf(g1.hashCode())))
        assertThat(Integer.valueOf(g3.hashCode()), IsEqual.equalTo(Integer.valueOf(g1.hashCode())))
        assertThat(Integer.valueOf(g1.hashCode()), IsNot.not(IsEqual.equalTo<Int>(Integer.valueOf(g4.hashCode()))))
        assertThat(Integer.valueOf(g2.hashCode()), IsNot.not(IsEqual.equalTo(Integer.valueOf(g4.hashCode()))))
        assertThat(Integer.valueOf(g3.hashCode()), IsNot.not(IsEqual.equalTo(Integer.valueOf(g4.hashCode()))))
    }

    /**
     * Test method for [BaseGroupElement.toRadix16].
     */
    @Test
    fun testToRadix16() {
        assertThat(GroupElement.toRadix16(BYTES_ZERO), `is`(RADIX16_ZERO))
        assertThat(GroupElement.toRadix16(BYTES_ONE), `is`(RADIX16_ONE))
        assertThat(GroupElement.toRadix16(BYTES_42), `is`(RADIX16_42))

        val from1234567890 = GroupElement.toRadix16(BYTES_1234567890)
        var total = 0
        for (i in from1234567890.indices) {
            assertThat(java.lang.Byte.valueOf(from1234567890[i]), `is`(greaterThanOrEqualTo(java.lang.Byte.valueOf((-8).toByte()))))
            assertThat(java.lang.Byte.valueOf(from1234567890[i]), `is`(lessThanOrEqualTo(java.lang.Byte.valueOf(8.toByte()))))
            total = (total.toDouble() + from1234567890[i] * StrictMath.pow(16.0, i.toDouble())).toInt()
        }
        assertThat(Integer.valueOf(total), `is`(Integer.valueOf(1234567890)))

        val pkrR16 = GroupElement.toRadix16(BYTES_PKR)
        val bound = pkrR16.size
        for (i in 0 until bound) {
            assertThat(java.lang.Byte.valueOf(pkrR16[i]), `is`(greaterThanOrEqualTo(java.lang.Byte.valueOf((-8).toByte()))))
            assertThat(java.lang.Byte.valueOf(pkrR16[i]), `is`(lessThanOrEqualTo(java.lang.Byte.valueOf(8.toByte()))))
        }
    }

    /**
     * Test method for [BaseGroupElement.cmov].
     */
    @Test
    fun testCmov() {
        val a = curve.get(Representation.PRECOMP)
        val b = PrecompGroupElement(curve, TWO, ZERO, TEN)
        assertThat(a.cmov(b, 0), `is`(equalTo(a)))
        assertThat(a.cmov(b, 1), `is`(equalTo<GroupElement>(b)))
    }

    /**
     * Test method for [BaseGroupElement.select].
     */
    @Test
    fun testSelect() {
        val B = ed25519.groupElement
        var i = 0
        while (32 > i) {
            // 16^i 0 B
            assertThat(i.toString() + ",0", B.select(i, 0),
                    `is`(equalTo(PrecompGroupElement(curve, ONE, ONE, ZERO))))
            var j = 1
            while (8 > j) {
                // 16^i r_i B
                val t = B.select(i, j)
                assertThat<GroupElement>(i.toString() + "," + j,
                        t, `is`(equalTo(B.precmp!![i][j - 1])))
                // -16^i r_i B
                val t3 = B.select(i, -j)
                val neg = PrecompGroupElement(curve, B.precmp!![i][j - 1].y, B.precmp!![i][j - 1].x, B.precmp!![i][j - 1].z.negate())
                assertThat<GroupElement>(i.toString() + "," + -j,
                        t3, `is`(equalTo<GroupElement>(neg)))
                j++
            }
            i++
        }
    }

    // region scalar multiplication
    /**
     * Test method for [BaseGroupElement.scalarMultiply].
     * Test values generated with Python Ed25519 implementation.
     */
    @Test
    fun testScalarMultiplyByteArray() {
        // Little-endian
        val zero = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000")
        val one = Utils.hexToBytes("0100000000000000000000000000000000000000000000000000000000000000")
        val two = Utils.hexToBytes("0200000000000000000000000000000000000000000000000000000000000000")
        val a = Utils.hexToBytes("d072f8dd9c07fa7bc8d22a4b325d26301ee9202f6db89aa7c3731529e37e437c")
        val A = object : P3GroupElement(curve, Utils.hexToBytes("d4cf8595571830644bd14af416954d09ab7159751ad9e0f7a6cbd92379e71a66")) {

        }

        assertThat("scalarMultiply(0) failed",
                ed25519.groupElement.scalarMultiply(zero), `is`(equalTo(curve.get(Representation.P3))))
        assertThat("scalarMultiply(1) failed",
                ed25519.groupElement.scalarMultiply(one), `is`(equalTo(ed25519.groupElement)))
        assertThat("scalarMultiply(2) failed",
                ed25519.groupElement.scalarMultiply(two), `is`(equalTo(ed25519.groupElement.dbl())))

        assertThat("scalarMultiply(a) failed",
                ed25519.groupElement.scalarMultiply(a), `is`(equalTo<GroupElement>(A)))
    }

    @Test
    fun scalarMultiplyBasePointWithZeroReturnsNeutralElement() {
        // Arrange:
        val basePoint = ed25519.groupElement

        // Act:
        val g = basePoint.scalarMultiply(curve.edDSAFiniteField.ZERO.toByteArray())

        // Assert:
        assertThat(curve.get(Representation.P3), IsEqual.equalTo(g))
    }

    @Test
    fun scalarMultiplyBasePointWithOneReturnsBasePoint() {
        // Arrange:
        val basePoint = ed25519.groupElement

        // Act:
        val g = basePoint.scalarMultiply(curve.edDSAFiniteField.ONE.toByteArray())

        // Assert:
        assertThat(basePoint, IsEqual.equalTo(g))
    }

    // This test is slow (~6s) due to math utils using an inferior algorithm to calculate the result.
    @Test
    fun scalarMultiplyBasePointReturnsExpectedResult() {
        var i = 0
        while (10 > i) {
            // Arrange:
            val basePoint = ed25519.groupElement
            val f = MathUtils.randomFieldElement

            // Act:
            val g = basePoint.scalarMultiply(f.toByteArray())
            val h = MathUtils.scalarMultiplyGroupElement(basePoint, f)

            // Assert:
            assertThat(g, IsEqual.equalTo(h))
            i++
        }
    }

    @Test
    fun testDoubleScalarMultiplyVariableTime() {
        // Little-endian
        val zero = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000")
        val one = Utils.hexToBytes("0100000000000000000000000000000000000000000000000000000000000000")
        val two = Utils.hexToBytes("0200000000000000000000000000000000000000000000000000000000000000")
        val a = Utils.hexToBytes("d072f8dd9c07fa7bc8d22a4b325d26301ee9202f6db89aa7c3731529e37e437c")
        val A = P3GroupElement(curve, Utils.hexToBytes("d4cf8595571830644bd14af416954d09ab7159751ad9e0f7a6cbd92379e71a66"))
        val B = ed25519.groupElement
        val geZero = curve.get(Representation.P3PrecomputedDouble)

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
                `is`(equalTo(Representation.P3.toRep(B.dbl()).add(Representation.CACHED.toRep(B)))))
        // 2 * B + 2 * B = 4 * B
        assertThat(B.doubleScalarMultiplyVariableTime(B, two, two),
                `is`(equalTo(Representation.P3.toRep(B.dbl()).dbl())))

        // 0 * B + a * B = A
        assertThat(B.doubleScalarMultiplyVariableTime(B, zero, a),
                `is`(equalTo<GroupElement>(A)))
        // a * B + 0 * B = A
        assertThat(B.doubleScalarMultiplyVariableTime(B, a, zero),
                `is`(equalTo<GroupElement>(A)))
        // a * B + a * B = 2 * A
        assertThat(B.doubleScalarMultiplyVariableTime(B, a, a),
                `is`(equalTo(A.dbl())))
    }

    // This test is slow (~6s) due to math utils using an inferior algorithm to calculate the result.
    @Test
    fun doubleScalarMultiplyVariableTimeReturnsExpectedResult() {
        var i = 0
        while (10 > i) {
            // Arrange:
            val basePoint = ed25519.groupElement
            val bytes = ByteArray(32)
            var ret: GroupElement
            while (true) {
                try {
                    MathUtils.random.nextBytes(bytes)
                    ret = P3PreGroupElement(MathUtils.curve, bytes)
                    break
                } catch (e: Throwable) {
                    // Will fail in about 87.5%, so try again.
                }

            }
            val f1 = MathUtils.randomFieldElement
            val f2 = MathUtils.randomFieldElement

            // Act:
            val h1 = basePoint.doubleScalarMultiplyVariableTime(ret, f2.toByteArray(), f1.toByteArray())
            val h2 = doubleScalarMultiplyGroupElements(basePoint, f1, ret, f2)

            // Assert:
            assertThat(h1, IsEqual.equalTo(h2))
            i++
        }
    }

    // endregion

    /**
     * Test method for [BaseGroupElement.isOnCurve].
     */
    @Test
    fun testIsOnCurve() {
        assertThat(java.lang.Boolean.valueOf(P2_ZERO.isOnCurve(curve)),
                `is`(java.lang.Boolean.TRUE))
        assertThat(java.lang.Boolean.valueOf(P2GroupElement(curve, ZERO, ZERO, ONE).isOnCurve(curve)),
                `is`(java.lang.Boolean.FALSE))
        assertThat(java.lang.Boolean.valueOf(P2GroupElement(curve, ONE, ONE, ONE).isOnCurve(curve)),
                `is`(java.lang.Boolean.FALSE))
        assertThat(java.lang.Boolean.valueOf(P2GroupElement(curve, TEN, ZERO, ONE).isOnCurve(curve)),
                `is`(java.lang.Boolean.FALSE))
        assertThat(java.lang.Boolean.valueOf(P2GroupElement(curve, ONE, TEN, ONE).isOnCurve(curve)),
                `is`(java.lang.Boolean.FALSE))
        assertThat(java.lang.Boolean.valueOf(P2GroupElement(curve, PKR[0], PKR[1], ONE).isOnCurve(curve)),
                `is`(java.lang.Boolean.TRUE))
    }

    @Test
    fun isOnCurveReturnsTrueForPointsOnTheCurve() {
        var i = 0
        while (100 > i) {
            // Arrange:
            val g = MathUtils.randomGroupElement

            // Assert:
            assertThat(java.lang.Boolean.valueOf(g.isOnCurve), IsEqual.equalTo(java.lang.Boolean.TRUE))
            i++
        }
    }

    @Test
    fun isOnCurveReturnsFalseForPointsNotOnTheCurve() {
        var i = 0
        while (100 > i) {
            // Arrange:
            val g = MathUtils.randomGroupElement
            val h = P2GroupElement(curve, g.x, g.y, g.z.multiply(curve.edDSAFiniteField.TWO))

            // Assert (can only fail for 5*Z^2=1):
            assertThat(java.lang.Boolean.valueOf(h.isOnCurve), IsEqual.equalTo(java.lang.Boolean.FALSE))
            i++
        }
    }

    companion object {
        private val BYTES_ZEROZERO = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000")
        private val BYTES_ONEONE = Utils.hexToBytes("0100000000000000000000000000000000000000000000000000000000000080")
        private val BYTES_TENZERO = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000")
        private val BYTES_ONETEN = Utils.hexToBytes("0a00000000000000000000000000000000000000000000000000000000000080")

        private val ed25519 = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)
        private val curve = ed25519.curve

        private val ZERO = curve.edDSAFiniteField.ZERO
        private val ONE = curve.edDSAFiniteField.ONE
        private val TWO = curve.edDSAFiniteField.TWO
        private val TEN = curve.edDSAFiniteField.fromByteArray(Utils.hexToBytes("0a00000000000000000000000000000000000000000000000000000000000000"))

        private val P2_ZERO = P2GroupElement(curve, ZERO, ONE, ONE)

        private val PKR = arrayOf(curve.edDSAFiniteField.fromByteArray(Utils.hexToBytes("5849722e338aced7b50c7f0e9328f9a10c847b08e40af5c5b0577b0fd8984f15")), curve.edDSAFiniteField.fromByteArray(Utils.hexToBytes("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29")))
        private val BYTES_PKR = Utils.hexToBytes("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29")

        /**
         * Negates a group element.
         *
         * @param g The group element.
         * @return The negated group element.
         */
        private fun negateGroupElement(g: GroupElement): GroupElement {
            if (Representation.P3 !== g.representation) {
                throw IllegalArgumentException("g must have representation P3")
            }

            val curve1 = g.curve
            val x = g.x.negate()
            val y = g.y
            val z = g.z
            val t = g.t.negate()
            /**
             * Creates a new group element in P3 representation.
             *
             * @param curve The curve.
             * @param X The $X$ coordinate.
             * @param Y The $Y$ coordinate.
             * @param Z The $Z$ coordinate.
             * @param T The $T$ coordinate.
             * @param precomputeDoubleOnly If true, populate dblPrecmp, else set to null.
             * @return The group element in P3 representation.
             */
            return if (false) P3PreGroupElement(curve1, x, y, z, t) else P3GroupElement(curve1, x, y, z, t)
        }

        /**
         * Calculates f1 * g1 + f2 * g2.
         *
         * @param g1 The first group element.
         * @param f1 The first multiplier.
         * @param g2 The second group element.
         * @param f2 The second multiplier.
         * @return The resulting group element.
         */
        private fun doubleScalarMultiplyGroupElements(
                g1: GroupElement,
                f1: FieldElement,
                g2: GroupElement,
                f2: FieldElement): GroupElement {
            val h1 = MathUtils.scalarMultiplyGroupElement(g1, f1)
            val h2 = MathUtils.scalarMultiplyGroupElement(g2, f2)
            return MathUtils.addGroupElements(h1, h2)
        }

        /**
         * Creates a group element from a byte array.
         *
         *
         * Bit 0 to 254 are the affine y-coordinate, bit 255 is the sign of the affine x-coordinate.
         *
         * @param bytes the byte array.
         * @return The group element.
         */
        private fun toGroupElement(bytes: ByteArray): GroupElement {
            val shouldBeNegative = 0 != bytes[31] as Int shr 7
            bytes[31] = (bytes[31] as Int and 0x7f).toByte()
            val y = MathUtils.toBigInteger(bytes)

            // x = sign(x) * sqrt((y^2 - 1) / (d * y^2 + 1))
            val u = y.multiply(y).subtract(BigInteger.ONE).mod(MathUtils.q)
            val v = MathUtils.d.multiply(y).multiply(y).add(BigInteger.ONE).mod(MathUtils.q)
            val tmp = u.multiply(v.pow(7)).modPow(BigInteger.ONE.shiftLeft(252).subtract(BigInteger("3")), MathUtils.q).mod(MathUtils.q)
            var x = tmp.multiply(u).multiply(v.pow(3)).mod(MathUtils.q)
            if (v.multiply(x).multiply(x).subtract(u).mod(MathUtils.q) != BigInteger.ZERO) {
                if (v.multiply(x).multiply(x).add(u).mod(MathUtils.q) != BigInteger.ZERO) {
                    throw IllegalArgumentException("not a valid GroupElement")
                }
                x = x.multiply(MathUtils.toBigInteger(MathUtils.curve.i)).mod(MathUtils.q)
            }
            val isNegative = x.mod(BigInteger("2")) == BigInteger.ONE
            if (shouldBeNegative && !isNegative || !shouldBeNegative && isNegative) {
                x = x.negate().mod(MathUtils.q)
            }

            val x1 = MathUtils.toFieldElement(x)
            val y1 = MathUtils.toFieldElement(y)
            val t = MathUtils.toFieldElement(x.multiply(y).mod(MathUtils.q))
            /**
             * Creates a new group element in P3 representation.
             *
             * @param curve The curve.
             * @param X The $X$ coordinate.
             * @param Y The $Y$ coordinate.
             * @param Z The $Z$ coordinate.
             * @param T The $T$ coordinate.
             * @param precomputeDoubleOnly If true, populate dblPrecmp, else set to null.
             * @return The group element in P3 representation.
             */
            return if (false) P3PreGroupElement(MathUtils.curve, x1, y1, MathUtils.edDSAFiniteField.ONE, t) else P3GroupElement(MathUtils.curve, x1, y1, MathUtils.edDSAFiniteField.ONE, t)
        }

        // endregion

        private val BYTES_ZERO = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000")
        private val BYTES_ONE = Utils.hexToBytes("0100000000000000000000000000000000000000000000000000000000000000")
        private val BYTES_42 = Utils.hexToBytes("2A00000000000000000000000000000000000000000000000000000000000000")
        private val BYTES_1234567890 = Utils.hexToBytes("D202964900000000000000000000000000000000000000000000000000000000")

        private val RADIX16_ZERO = Utils.hexToBytes("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
        private val RADIX16_ONE = Utils.hexToBytes("01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
        private val RADIX16_42 = Utils.hexToBytes("FA030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
    }
}
