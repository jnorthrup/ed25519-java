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

import net.i2p.crypto.eddsa.Utils
import net.i2p.crypto.eddsa.math.ed25519.*
import net.i2p.crypto.eddsa.spec.*
import org.hamcrest.core.IsEqual
import org.junit.*

import java.math.BigInteger
import java.security.SecureRandom

/**
 * Utility class to help with calculations.
 */
class MathUtils {

    // Start TODO BR: Remove when finished!
    @Test
    fun mathUtilsWorkAsExpected() {
        val neutral = GroupElement.p3(curve, curve.field.ZERO, curve.field.ONE, curve.field.ONE, curve.field.ZERO)
        run {
            var i = 0
            while (1000 > i) {
                val g = randomGroupElement

                // Act:
                val h1 = addGroupElements(g, neutral)
                val h2 = addGroupElements(neutral, g)

                // Assert:
                Assert.assertThat(g, IsEqual.equalTo(h1))
                Assert.assertThat(g, IsEqual.equalTo(h2))
                i++
            }
        }

        run {
            var i = 0
            while (1000 > i) {
                val g1 = randomGroupElement

                // P3 -> P2.
                val h = toRepresentation(g1, GroupElement.Representation.P2)
                Assert.assertThat(h, IsEqual.equalTo(g1))
                // P3 -> P1P1.
                val h2 = toRepresentation(g1, GroupElement.Representation.P1P1)
                Assert.assertThat(g1, IsEqual.equalTo(h2))

                // P3 -> CACHED.
                val h2a = toRepresentation(g1, GroupElement.Representation.CACHED)
                Assert.assertThat(h2a, IsEqual.equalTo(g1))
                var g: GroupElement
                var h4: GroupElement
                run {
                    // P3 -> P2 -> P3.
                    val g2 = toRepresentation(g1, GroupElement.Representation.P2)
                    run {
                        val h3 = toRepresentation(g2, GroupElement.Representation.P3)
                        Assert.assertThat(g2, IsEqual.equalTo(h3))
                        run {
                            // P3 -> P2 -> P1P1.
                            g = toRepresentation(g2, GroupElement.Representation.P2)
                            h4 = toRepresentation(g, GroupElement.Representation.P1P1)
                        }
                    }


                }


                Assert.assertThat(g, IsEqual.equalTo(h4))
                i++
            }
        }

        var i = 0
        while (10 > i) {
            // Arrange:
            val g = randomGroupElement

            // Act:
            val h = scalarMultiplyGroupElement(g, curve.field.ZERO)

            // Assert:
            Assert.assertThat(curve.getZero(GroupElement.Representation.P3), IsEqual.equalTo(h))
            i++
        }
    }

    companion object {
        private val exponents = intArrayOf(0, 26, 26 + 25, 2 * 26 + 25, 2 * 26 + 2 * 25, 3 * 26 + 2 * 25, 3 * 26 + 3 * 25, 4 * 26 + 3 * 25, 4 * 26 + 4 * 25, 5 * 26 + 4 * 25)
        private val random = SecureRandom()
        private val ed25519 = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)
        private val curve = ed25519.curve
        private val d = BigInteger("-121665").multiply(BigInteger("121666").modInverse(q))
        /**
         * Gets group order = 2^252 + 27742317777372353535851937790883648493 as BigInteger.
         */
        val groupOrder = BigInteger.ONE.shiftLeft(252).add(BigInteger("27742317777372353535851937790883648493"))

        /**
         * Gets q = 2^255 - 19 as BigInteger.
         */
        val q: BigInteger
            get() = BigInteger("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16)

        /**
         * Gets the underlying finite field with q=2^255 - 19 elements.
         *
         * @return The finite field.
         */
        // b
        // q
        val field: FiniteField
            get() = FiniteField(
                    256,
                    Utils.hexToBytes("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
                    Ed25519LittleEndianEncoding())

        // region field element

        /**
         * Converts a 2^25.5 bit representation to a BigInteger.
         *
         *
         * Value: 2^exponents[0] * t[0] + 2^exponents[1] * t[1] + ... + 2^exponents[9] * t[9]
         *
         * @param t The 2^25.5 bit representation.
         * @return The BigInteger.
         */
        fun toBigInteger(t: IntArray): BigInteger {
            var b = BigInteger.ZERO
            var i = 0
            while (10 > i) {
                b = b.add(BigInteger.ONE.multiply(BigInteger.valueOf(t[i].toLong())).shiftLeft(exponents[i]))
                i++
            }

            return b
        }

        /**
         * Converts a 2^8 bit representation to a BigInteger.
         *
         *
         * Value: bytes[0] + 2^8 * bytes[1] + ...
         *
         * @param bytes The 2^8 bit representation.
         * @return The BigInteger.
         */
        fun toBigInteger(bytes: ByteArray): BigInteger {
            var b = BigInteger.ZERO
            for (i in bytes.indices) {
                b = b.add(BigInteger.ONE.multiply(BigInteger.valueOf((bytes[i] and 0xff).toLong())).shiftLeft(i * 8))
            }

            return b
        }

        /**
         * Converts a field element to a BigInteger.
         *
         * @param f The field element.
         * @return The BigInteger.
         */
        fun toBigInteger(f: FieldElement): BigInteger {
            return toBigInteger(f.toByteArray())
        }

        /**
         * Converts a BigInteger to a field element.
         *
         * @param b The BigInteger.
         * @return The field element.
         */
        private fun toFieldElement(b: BigInteger): FieldElement {
            return field.encoding.decode(toByteArray(b))
        }

        /**
         * Converts a BigInteger to a little endian 32 byte representation.
         *
         * @param b The BigInteger.
         * @return The 32 byte representation.
         */
        fun toByteArray(b: BigInteger): ByteArray {
            if (0 <= b.compareTo(BigInteger.ONE.shiftLeft(256))) {
                throw RuntimeException("only numbers < 2^256 are allowed")
            }
            val bytes = ByteArray(32)
            val original = b.toByteArray()

            // Although b < 2^256, original can have length > 32 with some bytes set to 0.
            val offset = if (32 < original.size) original.size - 32 else 0
            for (i in 0 until original.size - offset) {
                bytes[original.size - i - offset - 1] = original[i + offset]
            }

            return bytes
        }

        /**
         * Reduces an integer in 2^8 bit representation modulo the group order and returns the result.
         *
         * @param bytes The integer in 2^8 bit representation.
         * @return The mod group order reduced integer.
         */
        fun reduceModGroupOrder(bytes: ByteArray): ByteArray {
            val b = toBigInteger(bytes).mod(groupOrder)
            return toByteArray(b)
        }

        /**
         * Calculates (a * b + c) mod group order and returns the result.
         *
         *
         * a, b and c are given in 2^8 bit representation.
         *
         * @param a The first integer.
         * @param b The second integer.
         * @param c The third integer.
         * @return The mod group order reduced result.
         */
        fun multiplyAndAddModGroupOrder(a: ByteArray, b: ByteArray, c: ByteArray): ByteArray {
            val result = toBigInteger(a).multiply(toBigInteger(b)).add(toBigInteger(c)).mod(groupOrder)
            return toByteArray(result)
        }

        fun getRandomByteArray(length: Int): ByteArray {
            val bytes = ByteArray(length)
            random.nextBytes(bytes)
            return bytes
        }

        /**
         * Gets a random field element where |t[i]| <= 2^24 for 0 <= i <= 9.
         *
         * @return The field element.
         */
        val randomFieldElement: FieldElement
            get() {
                val t = IntArray(10)
                var j = 0
                while (10 > j) {
                    t[j] = random.nextInt(1 shl 25) - (1 shl 24)
                    j++
                }
                return Ed25519FieldElement(field, t)
            }

        // endregion

        // region group element

        /**
         * Gets a random group element in P3 representation.
         *
         * @return The group element.
         */
        // Will fail in about 87.5%, so try again.
        val randomGroupElement: GroupElement
            get() {
                val bytes = ByteArray(32)
                while (true) {
                    try {
                        random.nextBytes(bytes)
                        return GroupElement(curve, bytes)
                    } catch (e: IllegalArgumentException) {
                    }

                }
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
        fun toGroupElement(bytes: ByteArray): GroupElement {
            val shouldBeNegative = 0 != bytes[31] shr 7
            bytes[31] = bytes[31] and 0x7f
            val y = toBigInteger(bytes)

            // x = sign(x) * sqrt((y^2 - 1) / (d * y^2 + 1))
            val u = y.multiply(y).subtract(BigInteger.ONE).mod(q)
            val v = d.multiply(y).multiply(y).add(BigInteger.ONE).mod(q)
            val tmp = u.multiply(v.pow(7)).modPow(BigInteger.ONE.shiftLeft(252).subtract(BigInteger("3")), q).mod(q)
            var x = tmp.multiply(u).multiply(v.pow(3)).mod(q)
            if (v.multiply(x).multiply(x).subtract(u).mod(q) != BigInteger.ZERO) {
                if (v.multiply(x).multiply(x).add(u).mod(q) != BigInteger.ZERO) {
                    throw IllegalArgumentException("not a valid GroupElement")
                }
                x = x.multiply(toBigInteger(curve.i)).mod(q)
            }
            val isNegative = x.mod(BigInteger("2")) == BigInteger.ONE
            if (if (shouldBeNegative) !isNegative else isNegative) {
                x = x.negate().mod(q)
            }

            return GroupElement.p3(curve, toFieldElement(x), toFieldElement(y), field.ONE, toFieldElement(x.multiply(y).mod(q)))
        }

        /**
         * Converts a group element from one representation to another.
         * This method is a helper used to test various methods in GroupElement.
         *
         * @param g The group element.
         * @param repr The desired representation.
         * @return The same group element in the new representation.
         */
        fun toRepresentation(g: GroupElement, repr: GroupElement.Representation): GroupElement {
            val x: BigInteger
            val y: BigInteger
            val gX = toBigInteger(g.x.toByteArray())
            val gY = toBigInteger(g.y.toByteArray())
            val gZ = toBigInteger(g.z.toByteArray())
            val gT = if (null == g.t) null else toBigInteger(g.t.toByteArray())

            // Switch to affine coordinates.
            when (g.representation) {
                GroupElement.Representation.P2, GroupElement.Representation.P3 -> {
                    x = gX.multiply(gZ.modInverse(q)).mod(q)
                    y = gY.multiply(gZ.modInverse(q)).mod(q)
                }
                GroupElement.Representation.P1P1 -> {
                    x = gX.multiply(gZ.modInverse(q)).mod(q)
                    y = gY.multiply(gT!!.modInverse(q)).mod(q)
                }
                GroupElement.Representation.CACHED -> {
                    x = gX.subtract(gY).multiply(gZ.multiply(BigInteger("2")).modInverse(q)).mod(q)
                    y = gX.add(gY).multiply(gZ.multiply(BigInteger("2")).modInverse(q)).mod(q)
                }
                GroupElement.Representation.PRECOMP -> {
                    x = gX.subtract(gY).multiply(BigInteger("2").modInverse(q)).mod(q)
                    y = gX.add(gY).multiply(BigInteger("2").modInverse(q)).mod(q)
                }
                else -> throw UnsupportedOperationException()
            }

            // Now back to the desired representation.
            when (repr) {
                GroupElement.Representation.P2 -> return GroupElement.p2(
                        curve,
                        toFieldElement(x),
                        toFieldElement(y),
                        field.ONE)
                GroupElement.Representation.P3 -> return GroupElement.p3(
                        curve,
                        toFieldElement(x),
                        toFieldElement(y),
                        field.ONE,
                        toFieldElement(x.multiply(y).mod(q)))
                GroupElement.Representation.P1P1 -> return GroupElement.p1p1(
                        curve,
                        toFieldElement(x),
                        toFieldElement(y),
                        field.ONE,
                        field.ONE)
                GroupElement.Representation.CACHED -> return GroupElement.cached(
                        curve,
                        toFieldElement(y.add(x).mod(q)),
                        toFieldElement(y.subtract(x).mod(q)),
                        field.ONE,
                        toFieldElement(d.multiply(BigInteger("2")).multiply(x).multiply(y).mod(q)))
                GroupElement.Representation.PRECOMP -> return GroupElement.precomp(
                        curve,
                        toFieldElement(y.add(x).mod(q)),
                        toFieldElement(y.subtract(x).mod(q)),
                        toFieldElement(d.multiply(BigInteger("2")).multiply(x).multiply(y).mod(q)))
                else -> throw UnsupportedOperationException()
            }
        }

        /**
         * Adds two group elements and returns the result in P3 representation.
         * It uses BigInteger arithmetic and the affine representation.
         * This method is a helper used to test the projective group addition formulas in GroupElement.
         *
         * @param g1 The first group element.
         * @param g2 The second group element.
         * @return The result of the addition.
         */
        fun addGroupElements(g1: GroupElement, g2: GroupElement): GroupElement {
            // Relying on a special representation of the group elements.
            if (GroupElement.Representation.P2 != g1.representation && GroupElement.Representation.P3 != g1.representation || GroupElement.Representation.P2 != g2.representation && GroupElement.Representation.P3 != g2.representation) {
                throw IllegalArgumentException("g1 and g2 must have representation P2 or P3")
            }

            // Projective coordinates
            val g1X = toBigInteger(g1.x.toByteArray())
            val g1Y = toBigInteger(g1.y.toByteArray())
            val g1Z = toBigInteger(g1.z.toByteArray())
            val g2X = toBigInteger(g2.x.toByteArray())
            val g2Y = toBigInteger(g2.y.toByteArray())
            val g2Z = toBigInteger(g2.z.toByteArray())

            // Affine coordinates
            val g1x = g1X.multiply(g1Z.modInverse(q)).mod(q)
            val g1y = g1Y.multiply(g1Z.modInverse(q)).mod(q)
            val g2x = g2X.multiply(g2Z.modInverse(q)).mod(q)
            val g2y = g2Y.multiply(g2Z.modInverse(q)).mod(q)

            // Addition formula for affine coordinates. The formula is complete in our case.
            //
            // (x3, y3) = (x1, y1) + (x2, y2) where
            //
            // x3 = (x1 * y2 + x2 * y1) / (1 + d * x1 * x2 * y1 * y2) and
            // y3 = (x1 * x2 + y1 * y2) / (1 - d * x1 * x2 * y1 * y2) and
            // d = -121665/121666
            val dx1x2y1y2 = d.multiply(g1x).multiply(g2x).multiply(g1y).multiply(g2y).mod(q)
            val x3 = g1x.multiply(g2y).add(g2x.multiply(g1y))
                    .multiply(BigInteger.ONE.add(dx1x2y1y2).modInverse(q)).mod(q)
            val y3 = g1x.multiply(g2x).add(g1y.multiply(g2y))
                    .multiply(BigInteger.ONE.subtract(dx1x2y1y2).modInverse(q)).mod(q)
            val t3 = x3.multiply(y3).mod(q)

            return GroupElement.p3(g1.curve, toFieldElement(x3), toFieldElement(y3), field.ONE, toFieldElement(t3))
        }

        /**
         * Doubles a group element and returns the result in P3 representation.
         * It uses BigInteger arithmetic and the affine representation.
         * This method is a helper used to test the projective group doubling formula in GroupElement.
         *
         * @param g The group element.
         * @return g+g.
         */
        fun doubleGroupElement(g: GroupElement): GroupElement {
            return addGroupElements(g, g)
        }

        /**
         * Scalar multiply the group element by the field element.
         *
         * @param g The group element.
         * @param f The field element.
         * @return The resulting group element.
         */
        fun scalarMultiplyGroupElement(g: GroupElement, f: FieldElement): GroupElement {
            val bytes = f.toByteArray()
            var h = curve.getZero(GroupElement.Representation.P3)
            var i = 254
            while (0 <= i) {
                h = doubleGroupElement(h)
                if (1 == Utils.bit(bytes, i)) {
                    h = addGroupElements(h, g)
                }
                i--
            }

            return h
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
        fun doubleScalarMultiplyGroupElements(
                g1: GroupElement,
                f1: FieldElement,
                g2: GroupElement,
                f2: FieldElement): GroupElement {
            val h1 = scalarMultiplyGroupElement(g1, f1)
            val h2 = scalarMultiplyGroupElement(g2, f2)
            return addGroupElements(h1, h2)
        }

        /**
         * Negates a group element.
         *
         * @param g The group element.
         * @return The negated group element.
         */
        fun negateGroupElement(g: GroupElement): GroupElement {
            if (GroupElement.Representation.P3 != g.representation) {
                throw IllegalArgumentException("g must have representation P3")
            }

            return GroupElement.p3(g.curve, g.x.negate(), g.y, g.z, g.t.negate())
        }
    }
    // End TODO BR: Remove when finished!
}
