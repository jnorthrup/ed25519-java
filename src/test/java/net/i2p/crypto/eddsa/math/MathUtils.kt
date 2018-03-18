/**
 * EdDSA-Java by str4d
 *
 *
 * To the extent possible under law, the person who associated CC0 with
 * EdDSA-Java has waived all copyright and related or neighboring rights
 * to EdDSA-Java.
 *
 *
 * You should have received a copy of the CC0 legalcode along with this
 * work. If not, see <https:></https:>//creativecommons.org/publicdomain/zero/1.0/>.
 */
package net.i2p.crypto.eddsa.math

import net.i2p.crypto.eddsa.Utils
import net.i2p.crypto.eddsa.math.ed25519.Ed25519FieldElement
import net.i2p.crypto.eddsa.math.ed25519.Ed25519LittleEndianEncoding
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable
import org.hamcrest.core.IsEqual
import org.junit.Assert
import org.junit.Test

import java.math.BigInteger
import java.security.SecureRandom

/**
 * Utility class to help with calculations.
 */
class MathUtils {

    // Start TODO BR: Remove when finished!
    @Test
    fun mathUtilsWorkAsExpected() {
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
                val ga1 = randomGroupElement

                // P3 -> P2.
                val h = toRepresentation(ga1, Representation.P2)
                Assert.assertThat(h, IsEqual.equalTo(ga1))
                // P3 -> P1P1.
                val g2 = toRepresentation(ga1, Representation.P1P1)
                Assert.assertThat(ga1, IsEqual.equalTo(g2))

                // P3 -> CACHED.
                val g3 = toRepresentation(ga1, Representation.CACHED)
                Assert.assertThat(g3, IsEqual.equalTo(ga1))
                // P3 -> P2 -> P3.
                val gb1 = toRepresentation(ga1, Representation.P2)
                val g4 = toRepresentation(gb1, Representation.P3)
                Assert.assertThat(gb1, IsEqual.equalTo(g4))
                // P3 -> P2 -> P1P1.
                val g = toRepresentation(gb1, Representation.P2)
                val g5 = toRepresentation(g, Representation.P1P1)
                Assert.assertThat(g, IsEqual.equalTo(g5))
                i++


            }
        }

        var i = 0
        while (10 > i) {
            // Arrange:
            val g = MathUtils.randomGroupElement

            // Act:
            val h = MathUtils.scalarMultiplyGroupElement(g, curve.edDSAFiniteField.ZERO)

            // Assert:
            Assert.assertThat(curve.get(Representation.P3), IsEqual.equalTo(h))
            i++
        }
    }

    companion object {
        val exponents = intArrayOf(0, 26, 26 + 25, 2 * 26 + 25, 2 * 26 + 2 * 25, 3 * 26 + 2 * 25, 3 * 26 + 3 * 25, 4 * 26 + 3 * 25, 4 * 26 + 4 * 25, 5 * 26 + 4 * 25)
        val random = SecureRandom()
        val d = BigInteger("-121665").multiply(BigInteger("121666").modInverse(q))
        val groupOrder = BigInteger.ONE.shiftLeft(252).add(BigInteger("27742317777372353535851937790883648493"))
        private val ed25519 = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)
        val curve = ed25519.curve

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
        val edDSAFiniteField: EdDSAFiniteField
            get() = EdDSAFiniteField(
                    256,
                    Utils.hexToBytes("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
                    Ed25519LittleEndianEncoding().getEmptyEncoding())

        // region field element

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
                b = b.add(BigInteger.ONE.multiply(BigInteger.valueOf((bytes[i] as Int and 0xff).toLong())).shiftLeft(i * 8))
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
        fun toFieldElement(b: BigInteger): FieldElement {
            return edDSAFiniteField.encoding.decode(toByteArray(b))
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
                return Ed25519FieldElement(edDSAFiniteField, t)
            }

        // endregion

        // region group element

        /**
         * Gets a random group element in P3 representation.
         *
         * @return The group element.
         */
        val randomGroupElement: GroupElement
            get() = getRandomGroupElement(false)

        /**
         * Gets a random group element in P3 representation, with precmp and dblPrecmp populated.
         *
         * @return The group element.
         */
        fun getRandomGroupElement(precompute: Boolean): GroupElement {
            val bytes = ByteArray(32)
            var ret: GroupElement
            while (true) {
                try {
                    random.nextBytes(bytes)
                    ret = BaseGroupElement(curve, bytes, precompute)
                    break
                } catch (e: Throwable) {
                    // Will fail in about 87.5%, so try again.
                }

            }
            return ret
        }

        /**
         * Converts a group element from one representation to another.
         * This method is a helper used to test various methods in GroupElement.
         *
         * @param g    The group element.
         * @param repr The desired representation.
         * @return The same group element in the new representation.
         */
        fun toRepresentation(g: GroupElement, repr: Representation): GroupElement {
            val x: BigInteger
            val y: BigInteger
            val gX = toBigInteger(g.x.toByteArray())
            val gY = toBigInteger(g.y.toByteArray())
            val gZ = toBigInteger(g.z.toByteArray())
            val gT = if (null == g.t) null else toBigInteger(g.t.toByteArray())

            // Switch to affine coordinates.
            when (g.representation) {
                Representation.P2, Representation.P3 -> {
                    x = gX.multiply(gZ.modInverse(q)).mod(q)
                    y = gY.multiply(gZ.modInverse(q)).mod(q)
                }
                Representation.P1P1 -> {
                    x = gX.multiply(gZ.modInverse(q)).mod(q)
                    y = gY.multiply(gT!!.modInverse(q)).mod(q)
                }
                Representation.CACHED -> {
                    x = gX.subtract(gY).multiply(gZ.multiply(BigInteger("2")).modInverse(q)).mod(q)
                    y = gX.add(gY).multiply(gZ.multiply(BigInteger("2")).modInverse(q)).mod(q)
                }
                Representation.PRECOMP -> {
                    x = gX.subtract(gY).multiply(BigInteger("2").modInverse(q)).mod(q)
                    y = gX.add(gY).multiply(BigInteger("2").modInverse(q)).mod(q)
                }
                else -> throw UnsupportedOperationException()
            }

            // Now back to the desired representation.
            when (repr) {
                Representation.P2 -> return P2GroupElement(curve, toFieldElement(x), toFieldElement(y), edDSAFiniteField.ONE)
                Representation.P3 -> {
                    val x1 = toFieldElement(x)
                    val y1 = toFieldElement(y)
                    val t = toFieldElement(x.multiply(y).mod(q))
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
                    return if (false) P3PreGroupElement(curve, x1, y1, edDSAFiniteField.ONE, t) else P3GroupElement(curve, x1, y1, edDSAFiniteField.ONE, t)
                }
                Representation.P1P1 ->   return P1pGroupElement(curve, toFieldElement(x), toFieldElement(y), edDSAFiniteField.ONE, edDSAFiniteField.ONE)
                Representation.CACHED -> return CachedGroupElement(curve, toFieldElement(y.add(x).mod(q)), toFieldElement(y.subtract(x).mod(q)), edDSAFiniteField.ONE, toFieldElement(d.multiply(BigInteger("2")).multiply(x).multiply(y).mod(q)))
                Representation.PRECOMP -> return PrecompGroupElement(curve, toFieldElement(y.add(x).mod(q)), toFieldElement(y.subtract(x).mod(q)), toFieldElement(d.multiply(BigInteger("2")).multiply(x).multiply(y).mod(q)))
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
            if (Representation.P2 !== g1.representation && Representation.P3 !== g1.representation || Representation.P2 !== g2.representation && Representation.P3 !== g2.representation) {
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

            val curve1 = g1.curve
            val x = toFieldElement(x3)
            val y = toFieldElement(y3)
            val t = toFieldElement(t3)
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
            return if (false) P3PreGroupElement(curve1, x, y, edDSAFiniteField.ONE, t) else P3GroupElement(curve1, x, y, edDSAFiniteField.ONE, t)
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
            var h = curve.get(Representation.P3)
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
    }
    // End TODO BR: Remove when finished!
}
