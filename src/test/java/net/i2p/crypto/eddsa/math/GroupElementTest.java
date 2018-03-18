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
package net.i2p.crypto.eddsa.math;

import net.i2p.crypto.eddsa.*;
import net.i2p.crypto.eddsa.spec.*;
import org.hamcrest.core.*;
import org.junit.*;
import org.junit.rules.ExpectedException;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Iterator;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

/**
 * @author str4d
 * Additional tests by NEM project team.
 *
 */
public class GroupElementTest {
    static final byte[] BYTES_ZEROZERO = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000");
    static final byte[] BYTES_ONEONE = Utils.hexToBytes("0100000000000000000000000000000000000000000000000000000000000080");
    static final byte[] BYTES_TENZERO = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000");
    static final byte[] BYTES_ONETEN = Utils.hexToBytes("0a00000000000000000000000000000000000000000000000000000000000080");

    static final EdDSANamedCurveSpec ed25519 = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
    static final Curve curve = ed25519.curve;

    static final FieldElement ZERO = curve.getEdDSAFiniteField().ZERO;
    static final FieldElement ONE = curve.getEdDSAFiniteField().ONE;
    static final FieldElement TWO = curve.getEdDSAFiniteField().TWO;
    static final FieldElement TEN = curve.getEdDSAFiniteField().fromByteArray(Utils.hexToBytes("0a00000000000000000000000000000000000000000000000000000000000000"));

    static final GroupElement P2_ZERO = GroupElement.p2(curve, ZERO, ONE, ONE);

    static final FieldElement[] PKR = {
        curve.getEdDSAFiniteField().fromByteArray(Utils.hexToBytes("5849722e338aced7b50c7f0e9328f9a10c847b08e40af5c5b0577b0fd8984f15")),
        curve.getEdDSAFiniteField().fromByteArray(Utils.hexToBytes("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"))
        };
    static final byte[] BYTES_PKR = Utils.hexToBytes("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29");

    @Rule
    public ExpectedException exception = ExpectedException.none();

    /**
     * Negates a group element.
     *
     * @param g The group element.
     * @return The negated group element.
     */
    public static GroupElement negateGroupElement(final GroupElement g) {
        if (GroupElement.Representation.P3 != g.getRepresentation()) {
            throw new IllegalArgumentException("g must have representation P3");
        }

        return GroupElement.p3(g.getCurve(), g.getX().negate(), g.getY(), g.getZ(), g.getT().negate(), false);
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
    public static GroupElement doubleScalarMultiplyGroupElements(
            final GroupElement g1,
            final FieldElement f1,
            final GroupElement g2,
            final FieldElement f2) {
        final GroupElement h1 = MathUtils.scalarMultiplyGroupElement(g1, f1);
        final GroupElement h2 = MathUtils.scalarMultiplyGroupElement(g2, f2);
        return MathUtils.addGroupElements(h1, h2);
    }

    /**
     * Creates a group element from a byte array.
     * <p>
     * Bit 0 to 254 are the affine y-coordinate, bit 255 is the sign of the affine x-coordinate.
     *
     * @param bytes the byte array.
     * @return The group element.
     */
    public static GroupElement toGroupElement(final byte[] bytes) {
        final boolean shouldBeNegative = 0 != (bytes[31] >> 7);
        bytes[31] = (byte) (bytes[31] & 0x7f);
        final BigInteger y = MathUtils.toBigInteger(bytes);

        // x = sign(x) * sqrt((y^2 - 1) / (d * y^2 + 1))
        final BigInteger u = y.multiply(y).subtract(BigInteger.ONE).mod(MathUtils.getQ());
        final BigInteger v = MathUtils.d.multiply(y).multiply(y).add(BigInteger.ONE).mod(MathUtils.getQ());
        final BigInteger tmp = u.multiply(v.pow(7)).modPow(BigInteger.ONE.shiftLeft(252).subtract(new BigInteger("3")), MathUtils.getQ()).mod(MathUtils.getQ());
        BigInteger x = tmp.multiply(u).multiply(v.pow(3)).mod(MathUtils.getQ());
        if (!v.multiply(x).multiply(x).subtract(u).mod(MathUtils.getQ()).equals(BigInteger.ZERO)) {
            if (!v.multiply(x).multiply(x).add(u).mod(MathUtils.getQ()).equals(BigInteger.ZERO)) {
                throw new IllegalArgumentException("not a valid GroupElement");
            }
            x = x.multiply(MathUtils.toBigInteger(MathUtils.curve.getI())).mod(MathUtils.getQ());
        }
        final boolean isNegative = x.mod(new BigInteger("2")).equals(BigInteger.ONE);
        if ((shouldBeNegative && !isNegative) || (!shouldBeNegative && isNegative)) {
            x = x.negate().mod(MathUtils.getQ());
        }

        return GroupElement.p3(MathUtils.curve, MathUtils.toFieldElement(x), MathUtils.toFieldElement(y), MathUtils.getEdDSAFiniteField().ONE, MathUtils.toFieldElement(x.multiply(y).mod(MathUtils.getQ())), false);
    }

    /**
     * Test method for {@link GroupElement#p2(Curve, FieldElement, FieldElement, FieldElement)}.
     */
    @Test
    public void testP2() {
        final GroupElement t = GroupElement.p2(curve, ZERO, ONE, ONE);
        assertThat(t.curve, is(equalTo(curve)));
        assertThat(t.repr, is(GroupElement.Representation.P2));
        assertThat(t.X, is(ZERO));
        assertThat(t.Y, is(ONE));
        assertThat(t.Z, is(ONE));
        assertThat(t.T, is((FieldElement) null));
    }

    /**
     * Test method for {@link GroupElement#p3(Curve, FieldElement, FieldElement, FieldElement, FieldElement, boolean)}.
     */
    @Test
    public void testP3() {
        final GroupElement t = GroupElement.p3(curve, ZERO, ONE, ONE, ZERO, false);
        assertThat(t.curve, is(equalTo(curve)));
        assertThat(t.repr, is(GroupElement.Representation.P3));
        assertThat(t.X, is(ZERO));
        assertThat(t.Y, is(ONE));
        assertThat(t.Z, is(ONE));
        assertThat(t.T, is(ZERO));
    }

    /**
     * Test method for {@link GroupElement#p1p1(Curve, FieldElement, FieldElement, FieldElement, FieldElement)}.
     */
    @Test
    public void testP1p1() {
        final GroupElement t = GroupElement.p1p1(curve, ZERO, ONE, ONE, ONE);
        assertThat(t.curve, is(equalTo(curve)));
        assertThat(t.repr, is(GroupElement.Representation.P1P1));
        assertThat(t.X, is(ZERO));
        assertThat(t.Y, is(ONE));
        assertThat(t.Z, is(ONE));
        assertThat(t.T, is(ONE));
    }

    /**
     * Test method for {@link GroupElement#precomp(Curve, FieldElement, FieldElement, FieldElement)}.
     */
    @Test
    public void testPrecomp() {
        final GroupElement t = GroupElement.precomp(curve, ONE, ONE, ZERO);
        assertThat(t.curve, is(equalTo(curve)));
        assertThat(t.repr, is(GroupElement.Representation.PRECOMP));
        assertThat(t.X, is(ONE));
        assertThat(t.Y, is(ONE));
        assertThat(t.Z, is(ZERO));
        assertThat(t.T, is((FieldElement) null));
    }

    /**
     * Test method for {@link GroupElement#cached(Curve, FieldElement, FieldElement, FieldElement, FieldElement)}.
     */
    @Test
    public void testCached() {
        final GroupElement t = GroupElement.cached(curve, ONE, ONE, ONE, ZERO);
        assertThat(t.curve, is(equalTo(curve)));
        assertThat(t.repr, is(GroupElement.Representation.CACHED));
        assertThat(t.X, is(ONE));
        assertThat(t.Y, is(ONE));
        assertThat(t.Z, is(ONE));
        assertThat(t.T, is(ZERO));
    }

    /**
     * Test method for {@link GroupElement#GroupElement(Curve, GroupElement.Representation, FieldElement, FieldElement, FieldElement, FieldElement, boolean)}.
     */
    @Test
    public void testGroupElementCurveRepresentationFieldElementFieldElementFieldElementFieldElement() {
        final GroupElement t = new GroupElement(curve, GroupElement.Representation.P3, ZERO, ONE, ONE, ZERO, false);
        assertThat(t.curve, is(equalTo(curve)));
        assertThat(t.repr, is(GroupElement.Representation.P3));
        assertThat(t.X, is(ZERO));
        assertThat(t.Y, is(ONE));
        assertThat(t.Z, is(ONE));
        assertThat(t.T, is(ZERO));
    }

    /**
     * Tests {@link GroupElement#GroupElement(Curve, byte[])} and
     * {@link GroupElement#toByteArray()} against valid public keys.
     */
    @Test
    public void testToAndFromByteArray() {
        GroupElement t;
        for (Iterator<Ed25519TestVectors.TestTuple> iterator = Ed25519TestVectors.testCases.iterator(); iterator.hasNext(); ) {
            Ed25519TestVectors.TestTuple testCase = iterator.next();
            t = new GroupElement(curve, testCase.pk);
            assertThat("Test case " + testCase.caseNum + " failed",
                    t.toByteArray(), is(equalTo(testCase.pk)));
        }
    }

    /**
     * Test method for {@link GroupElement#GroupElement(Curve, byte[])}.
     */
    @Test
    public void testGroupElementByteArray() {
        final GroupElement t = new GroupElement(curve, BYTES_PKR);
        final GroupElement s = GroupElement.p3(curve, PKR[0], PKR[1], ONE, PKR[0].multiply(PKR[1]),false);
        assertThat(t, is(equalTo(s)));
    }

    @Test
    public void constructorUsingByteArrayReturnsExpectedResult() {
        for (int i = 0; 100 > i; i++) {
            // Arrange:
            final GroupElement g = MathUtils.getRandomGroupElement();
            final byte[] bytes = g.toByteArray();

            // Act:
            final GroupElement h1 = new GroupElement(curve, bytes);
            final GroupElement h2 = toGroupElement(bytes);

            // Assert:
            assertThat(h1, IsEqual.equalTo(h2));
        }
    }

    /**
     * Test method for {@link GroupElement#toByteArray()}.
     * <p>
     * TODO 20141001 BR: why test with points which are not on the curve?
     */
    @Test
    public void testToByteArray() {
        final byte[] zerozero = GroupElement.p2(curve, ZERO, ZERO, ONE).toByteArray();
        assertThat(Integer.valueOf(zerozero.length), is(equalTo(Integer.valueOf(BYTES_ZEROZERO.length))));
        assertThat(zerozero, is(equalTo(BYTES_ZEROZERO)));

        final byte[] oneone = GroupElement.p2(curve, ONE, ONE, ONE).toByteArray();
        assertThat(Integer.valueOf(oneone.length), is(equalTo(Integer.valueOf(BYTES_ONEONE.length))));
        assertThat(oneone, is(equalTo(BYTES_ONEONE)));

        final byte[] tenzero = GroupElement.p2(curve, TEN, ZERO, ONE).toByteArray();
        assertThat(Integer.valueOf(tenzero.length), is(equalTo(Integer.valueOf(BYTES_TENZERO.length))));
        assertThat(tenzero, is(equalTo(BYTES_TENZERO)));

        final byte[] oneten = GroupElement.p2(curve, ONE, TEN, ONE).toByteArray();
        assertThat(Integer.valueOf(oneten.length), is(equalTo(Integer.valueOf(BYTES_ONETEN.length))));
        assertThat(oneten, is(equalTo(BYTES_ONETEN)));

        final byte[] pkr = GroupElement.p2(curve, PKR[0], PKR[1], ONE).toByteArray();
        assertThat(Integer.valueOf(pkr.length), is(equalTo(Integer.valueOf(BYTES_PKR.length))));
        assertThat(pkr, is(equalTo(BYTES_PKR)));
    }

     @Test
     public void toByteArrayReturnsExpectedResult() {
         for (int i = 0; 100 > i; i++) {
             // Arrange:
             final GroupElement g = MathUtils.getRandomGroupElement();

             // Act:
             final byte[] gBytes = g.toByteArray();
             final byte[] bytes = MathUtils.toByteArray(MathUtils.toBigInteger(g.getY()));
             if (MathUtils.toBigInteger(g.getX()).mod(new BigInteger("2")).equals(BigInteger.ONE)) {
                 bytes[31] = (byte) (bytes[31] | 0x80);
             }

             // Assert:
             assertThat(Boolean.valueOf(Arrays.equals(gBytes, bytes)), IsEqual.equalTo(Boolean.TRUE));
         }
     }

    // region toX where X is the representation

    /**
     * Test method for {@link GroupElement#toP2()}.
     */
    @Test
    public void testToP2() {
        final GroupElement p3zero = curve.getZero(GroupElement.Representation.P3);
        final GroupElement t = p3zero.toP2();
        assertThat(t.repr, is(GroupElement.Representation.P2));
        assertThat(t.X, is(p3zero.X));
        assertThat(t.Y, is(p3zero.Y));
        assertThat(t.Z, is(p3zero.Z));
        assertThat(t.T, is((FieldElement) null));

        final GroupElement B = ed25519.groupElement;
        final GroupElement t2 = B.toP2();
        assertThat(t2.repr, is(GroupElement.Representation.P2));
        assertThat(t2.X, is(B.X));
        assertThat(t2.Y, is(B.Y));
        assertThat(t2.Z, is(B.Z));
        assertThat(t2.T, is((FieldElement) null));
    }

    @Test (expected = IllegalArgumentException.class)
    public void toP2ThrowsIfGroupElementHasPrecompRepresentation() {
        // Arrange:
        final GroupElement g = MathUtils.toRepresentation(MathUtils.getRandomGroupElement(), GroupElement.Representation.PRECOMP);

        // Assert:
        g.toP2();
    }

    @Test (expected = IllegalArgumentException.class)
    public void toP2ThrowsIfGroupElementHasCachedRepresentation() {
        // Arrange:
        final GroupElement g =  MathUtils.toRepresentation(MathUtils.getRandomGroupElement(), GroupElement.Representation.CACHED);

        // Assert:
        g.toP2();
    }

    @Test
    public void toP2ReturnsExpectedResultIfGroupElementHasP2Representation() {
        for (int i = 0; 10 > i; i++) {
            // Arrange:
            final GroupElement g = MathUtils.toRepresentation(MathUtils.getRandomGroupElement(), GroupElement.Representation.P2);

            // Act:
            final GroupElement h = g.toP2();

            // Assert:
            assertThat(h, IsEqual.equalTo(g));
            assertThat(h.getRepresentation(), IsEqual.equalTo(GroupElement.Representation.P2));
            assertThat(h.getX(), IsEqual.equalTo(g.getX()));
            assertThat(h.getY(), IsEqual.equalTo(g.getY()));
            assertThat(h.getZ(), IsEqual.equalTo(g.getZ()));
            assertThat(h.getT(), IsEqual.equalTo(null));
        }
    }

    @Test
    public void toP2ReturnsExpectedResultIfGroupElementHasP3Representation() {
        for (int i = 0; 10 > i; i++) {
            // Arrange:
            final GroupElement g = MathUtils.getRandomGroupElement();

            // Act:
            final GroupElement h1 = g.toP2();
            final GroupElement h2 = MathUtils.toRepresentation(g, GroupElement.Representation.P2);

            // Assert:
            assertThat(h1, IsEqual.equalTo(h2));
            assertThat(h1.getRepresentation(), IsEqual.equalTo(GroupElement.Representation.P2));
            assertThat(h1.getX(), IsEqual.equalTo(g.getX()));
            assertThat(h1.getY(), IsEqual.equalTo(g.getY()));
            assertThat(h1.getZ(), IsEqual.equalTo(g.getZ()));
            assertThat(h1.getT(), IsEqual.equalTo(null));
        }
    }

    @Test
    public void toP2ReturnsExpectedResultIfGroupElementHasP1P1Representation() {
        for (int i = 0; 10 > i; i++) {
            // Arrange:
            final GroupElement g = MathUtils.toRepresentation(MathUtils.getRandomGroupElement(), GroupElement.Representation.P1P1);

            // Act:
            final GroupElement h1 = g.toP2();
            final GroupElement h2 = MathUtils.toRepresentation(g, GroupElement.Representation.P2);

            // Assert:
            assertThat(h1, IsEqual.equalTo(h2));
            assertThat(h1.getRepresentation(), IsEqual.equalTo(GroupElement.Representation.P2));
            assertThat(h1.getX(), IsEqual.equalTo(g.getX().multiply(g.getT())));
            assertThat(h1.getY(), IsEqual.equalTo(g.getY().multiply(g.getZ())));
            assertThat(h1.getZ(), IsEqual.equalTo(g.getZ().multiply(g.getT())));
            assertThat(h1.getT(), IsEqual.equalTo(null));
        }
    }

    @Test (expected = IllegalArgumentException.class)
    public void toP3ThrowsIfGroupElementHasP2Representation() {
        // Arrange:
        final GroupElement g = MathUtils.toRepresentation(MathUtils.getRandomGroupElement(), GroupElement.Representation.P2);

        // Assert:
        g.toP3();
    }

    @Test (expected = IllegalArgumentException.class)
    public void toP3ThrowsIfGroupElementHasPrecompRepresentation() {
        // Arrange:
        final GroupElement g = MathUtils.toRepresentation(MathUtils.getRandomGroupElement(), GroupElement.Representation.PRECOMP);

        // Assert:
        g.toP3();
    }

    @Test (expected = IllegalArgumentException.class)
    public void toP3ThrowsIfGroupElementHasCachedRepresentation() {
        // Arrange:
        final GroupElement g = MathUtils.toRepresentation(MathUtils.getRandomGroupElement(), GroupElement.Representation.CACHED);

        // Assert:
        g.toP3();
    }

    @Test
    public void toP3ReturnsExpectedResultIfGroupElementHasP1P1Representation() {
        for (int i = 0; 10 > i; i++) {
            // Arrange:
            final GroupElement g = MathUtils.toRepresentation(MathUtils.getRandomGroupElement(), GroupElement.Representation.P1P1);

            // Act:
            final GroupElement h1 = g.toP3();
            final GroupElement h2 = MathUtils.toRepresentation(g, GroupElement.Representation.P3);

            // Assert:
            assertThat(h1, IsEqual.equalTo(h2));
            assertThat(h1.getRepresentation(), IsEqual.equalTo(GroupElement.Representation.P3));
            assertThat(h1.getX(), IsEqual.equalTo(g.getX().multiply(g.getT())));
            assertThat(h1.getY(), IsEqual.equalTo(g.getY().multiply(g.getZ())));
            assertThat(h1.getZ(), IsEqual.equalTo(g.getZ().multiply(g.getT())));
            assertThat(h1.getT(), IsEqual.equalTo(g.getX().multiply(g.getY())));
        }
    }

    @Test
    public void toP3ReturnsExpectedResultIfGroupElementHasP3Representation() {
        for (int i = 0; 10 > i; i++) {
            // Arrange:
            final GroupElement g = MathUtils.getRandomGroupElement();

            // Act:
            final GroupElement h = g.toP3();

            // Assert:
            assertThat(h, IsEqual.equalTo(g));
            assertThat(h.getRepresentation(), IsEqual.equalTo(GroupElement.Representation.P3));
            assertThat(h, IsEqual.equalTo(g));
            assertThat(h.getX(), IsEqual.equalTo(g.getX()));
            assertThat(h.getY(), IsEqual.equalTo(g.getY()));
            assertThat(h.getZ(), IsEqual.equalTo(g.getZ()));
            assertThat(h.getT(), IsEqual.equalTo(g.getT()));
        }
    }

    @Test (expected = IllegalArgumentException.class)
    public void toCachedThrowsIfGroupElementHasP2Representation() {
        // Arrange:
        final GroupElement g = MathUtils.toRepresentation(MathUtils.getRandomGroupElement(), GroupElement.Representation.P2);

        // Assert:
        g.toCached();
    }

    @Test (expected = IllegalArgumentException.class)
    public void toCachedThrowsIfGroupElementHasPrecompRepresentation() {
        // Arrange:
        final GroupElement g = MathUtils.toRepresentation(MathUtils.getRandomGroupElement(), GroupElement.Representation.PRECOMP);

        // Assert:
        g.toCached();
    }

    @Test (expected = IllegalArgumentException.class)
    public void toCachedThrowsIfGroupElementHasP1P1Representation() {
        // Arrange:
        final GroupElement g = MathUtils.toRepresentation(MathUtils.getRandomGroupElement(), GroupElement.Representation.P1P1);

        // Assert:
        g.toCached();
    }

    @Test
    public void toCachedReturnsExpectedResultIfGroupElementHasCachedRepresentation() {
        for (int i = 0; 10 > i; i++) {
            // Arrange:
            final GroupElement g = MathUtils.toRepresentation(MathUtils.getRandomGroupElement(), GroupElement.Representation.CACHED);

            // Act:
            final GroupElement h = g.toCached();

            // Assert:
            assertThat(h, IsEqual.equalTo(g));
            assertThat(h.getRepresentation(), IsEqual.equalTo(GroupElement.Representation.CACHED));
            assertThat(h, IsEqual.equalTo(g));
            assertThat(h.getX(), IsEqual.equalTo(g.getX()));
            assertThat(h.getY(), IsEqual.equalTo(g.getY()));
            assertThat(h.getZ(), IsEqual.equalTo(g.getZ()));
            assertThat(h.getT(), IsEqual.equalTo(g.getT()));
        }
    }

    @Test
    public void toCachedReturnsExpectedResultIfGroupElementHasP3Representation() {
        for (int i = 0; 10 > i; i++) {
            // Arrange:
            final GroupElement g = MathUtils.getRandomGroupElement();

            // Act:
            final GroupElement h1 = g.toCached();
            final GroupElement h2 = MathUtils.toRepresentation(g, GroupElement.Representation.CACHED);

            // Assert:
            assertThat(h1, IsEqual.equalTo(h2));
            assertThat(h1.getRepresentation(), IsEqual.equalTo(GroupElement.Representation.CACHED));
            assertThat(h1, IsEqual.equalTo(g));
            assertThat(h1.getX(), IsEqual.equalTo(g.getY().add(g.getX())));
            assertThat(h1.getY(), IsEqual.equalTo(g.getY().subtract(g.getX())));
            assertThat(h1.getZ(), IsEqual.equalTo(g.getZ()));
            assertThat(h1.getT(), IsEqual.equalTo(g.getT().multiply(curve.get2D())));
        }
    }

    // endregion

    /**
     * Test method for precomputation.
     */
    @Test
    public void testPrecompute() {
        final GroupElement B = ed25519.groupElement;
        assertThat(B.precmp, is(equalTo(PrecomputationTestVectors.testPrecmp)));
        assertThat(B.dblPrecmp, is(equalTo(PrecomputationTestVectors.testDblPrecmp)));
    }

    @Test
    public void precomputedTableContainsExpectedGroupElements() {
        // Arrange:
        GroupElement g = ed25519.groupElement;

        // Act + Assert:
        for (int i = 0; 32 > i; i++) {
            GroupElement h = g;
            for (int j = 0; 8 > j; j++) {
                assertThat(MathUtils.toRepresentation(h, GroupElement.Representation.PRECOMP), IsEqual.equalTo(ed25519.groupElement.precmp[i][j]));
                h = MathUtils.addGroupElements(h, g);
            }
            for (int k = 0; 8 > k; k++) {
                g = MathUtils.addGroupElements(g, g);
            }
        }
    }

    @Test
    public void dblPrecomputedTableContainsExpectedGroupElements() {
        // Arrange:
        GroupElement g = ed25519.groupElement;
        final GroupElement h = MathUtils.addGroupElements(g, g);

        // Act + Assert:
        for (int i = 0; 8 > i; i++) {
            assertThat(MathUtils.toRepresentation(g, GroupElement.Representation.PRECOMP), IsEqual.equalTo(ed25519.groupElement.dblPrecmp[i]));
            g = MathUtils.addGroupElements(g, h);
        }
    }

    /**
     * Test method for {@link GroupElement#dbl()}.
     */
    @Test
    public void testDbl() {
        final GroupElement B = ed25519.groupElement;
        // 2 * B = B + B
        assertThat(B.dbl(), is(equalTo(B.add(B.toCached()))));
    }

    @Test
    public void dblReturnsExpectedResult() {
        for (int i = 0; 1000 > i; i++) {
            // Arrange:
            final GroupElement g = MathUtils.getRandomGroupElement();

            // Act:
            final GroupElement h1 = g.dbl();
            final GroupElement h2 = MathUtils.doubleGroupElement(g);

            // Assert:
            assertThat(h2, IsEqual.equalTo(h1));
        }
    }

    @Test
    public void addingNeutralGroupElementDoesNotChangeGroupElement() {
        final GroupElement neutral = GroupElement.p3(curve, curve.getEdDSAFiniteField().ZERO, curve.getEdDSAFiniteField().ONE, curve.getEdDSAFiniteField().ONE, curve.getEdDSAFiniteField().ZERO, false);
        for (int i = 0; 1000 > i; i++) {
            // Arrange:
            final GroupElement g = MathUtils.getRandomGroupElement();

            // Act:
            final GroupElement h1 = g.add(neutral.toCached());
            final GroupElement h2 = neutral.add(g.toCached());

            // Assert:
            assertThat(g, IsEqual.equalTo(h1));
            assertThat(g, IsEqual.equalTo(h2));
        }
    }

    @Test
    public void addReturnsExpectedResult() {
        for (int i = 0; 1000 > i; i++) {
            // Arrange:
            final GroupElement g1 = MathUtils.getRandomGroupElement();
            final GroupElement g2 = MathUtils.getRandomGroupElement();

            // Act:
            final GroupElement h1 = g1.add(g2.toCached());
            final GroupElement h2 = MathUtils.addGroupElements(g1, g2);

            // Assert:
            assertThat(h2, IsEqual.equalTo(h1));
        }
    }

    @Test
    public void subReturnsExpectedResult() {
        for (int i = 0; 1000 > i; i++) {
            // Arrange:
            final GroupElement g1 = MathUtils.getRandomGroupElement();
            final GroupElement g2 = MathUtils.getRandomGroupElement();

            // Act:
            final GroupElement h1 = g1.sub(g2.toCached());
            final GroupElement h2 = MathUtils.addGroupElements(g1, negateGroupElement(g2));

            // Assert:
            assertThat(h2, IsEqual.equalTo(h1));
        }
    }

    // region hashCode / equals
    /**
     * Test method for {@link GroupElement#equals(java.lang.Object)}.
     */
    @Test
    public void testEqualsObject() {
        assertThat(GroupElement.p2(curve, ZERO, ONE, ONE),
                is(equalTo(P2_ZERO)));
    }

    @Test
    public void equalsOnlyReturnsTrueForEquivalentObjects() {
        // Arrange:
        final GroupElement g1 = MathUtils.getRandomGroupElement();
        final GroupElement g2 = MathUtils.toRepresentation(g1, GroupElement.Representation.P2);
        final GroupElement g3 = MathUtils.toRepresentation(g1, GroupElement.Representation.CACHED);
        final GroupElement g4 = MathUtils.toRepresentation(g1, GroupElement.Representation.P1P1);
        final GroupElement g5 = MathUtils.getRandomGroupElement();

        // Assert
        assertThat(g2, IsEqual.equalTo(g1));
        assertThat(g3, IsEqual.equalTo(g1));
        assertThat(g1, IsEqual.equalTo(g4));
        assertThat(g1, IsNot.not(IsEqual.equalTo(g5)));
        assertThat(g2, IsNot.not(IsEqual.equalTo(g5)));
        assertThat(g3, IsNot.not(IsEqual.equalTo(g5)));
        assertThat(g5, IsNot.not(IsEqual.equalTo(g4)));
    }

    @Test
    public void hashCodesAreEqualForEquivalentObjects() {
        // Arrange:
        final GroupElement g1 = MathUtils.getRandomGroupElement();
        final GroupElement g2 = MathUtils.toRepresentation(g1, GroupElement.Representation.P2);
        final GroupElement g3 = MathUtils.toRepresentation(g1, GroupElement.Representation.P1P1);
        final GroupElement g4 = MathUtils.getRandomGroupElement();

        // Assert
        assertThat(Integer.valueOf(g2.hashCode()), IsEqual.equalTo(Integer.valueOf(g1.hashCode())));
        assertThat(Integer.valueOf(g3.hashCode()), IsEqual.equalTo(Integer.valueOf(g1.hashCode())));
        assertThat(Integer.valueOf(g1.hashCode()), IsNot.not(IsEqual.equalTo(Integer.valueOf(g4.hashCode()))));
        assertThat(Integer.valueOf(g2.hashCode()), IsNot.not(IsEqual.equalTo(Integer.valueOf(g4.hashCode()))));
        assertThat(Integer.valueOf(g3.hashCode()), IsNot.not(IsEqual.equalTo(Integer.valueOf(g4.hashCode()))));
    }

    // endregion

    static final byte[] BYTES_ZERO = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000");
    static final byte[] BYTES_ONE = Utils.hexToBytes("0100000000000000000000000000000000000000000000000000000000000000");
    static final byte[] BYTES_42 = Utils.hexToBytes("2A00000000000000000000000000000000000000000000000000000000000000");
    static final byte[] BYTES_1234567890 = Utils.hexToBytes("D202964900000000000000000000000000000000000000000000000000000000");

    static final byte[] RADIX16_ZERO = Utils.hexToBytes("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    static final byte[] RADIX16_ONE = Utils.hexToBytes("01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    static final byte[] RADIX16_42 = Utils.hexToBytes("FA030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

    /**
     * Test method for {@link GroupElement#toRadix16(byte[])}.
     */
    @Test
    public void testToRadix16() {
        assertThat(GroupElement.toRadix16(BYTES_ZERO), is(RADIX16_ZERO));
        assertThat(GroupElement.toRadix16(BYTES_ONE), is(RADIX16_ONE));
        assertThat(GroupElement.toRadix16(BYTES_42), is(RADIX16_42));

        final byte[] from1234567890 = GroupElement.toRadix16(BYTES_1234567890);
        int total = 0;
        for (int i = 0; i < from1234567890.length; i++) {
            assertThat(Byte.valueOf(from1234567890[i]), is(greaterThanOrEqualTo(Byte.valueOf((byte) -8))));
            assertThat(Byte.valueOf(from1234567890[i]), is(lessThanOrEqualTo(Byte.valueOf((byte) 8))));
            total = (int) ((double) total + from1234567890[i] * StrictMath.pow(16.0, (double) i));
        }
        assertThat(Integer.valueOf(total), is(Integer.valueOf(1234567890)));

        final byte[] pkrR16 = GroupElement.toRadix16(BYTES_PKR);
        final int bound = pkrR16.length;
        for (int i = 0; i < bound; i++) {
            assertThat(Byte.valueOf(pkrR16[i]), is(greaterThanOrEqualTo(Byte.valueOf((byte) -8))));
            assertThat(Byte.valueOf(pkrR16[i]), is(lessThanOrEqualTo(Byte.valueOf((byte) 8))));
        }
    }

    /**
     * Test method for {@link GroupElement#cmov(GroupElement, int)}.
     */
    @Test
    public void testCmov() {
        final GroupElement a = curve.getZero(GroupElement.Representation.PRECOMP);
        final GroupElement b = GroupElement.precomp(curve, TWO, ZERO, TEN);
        assertThat(a.cmov(b, 0), is(equalTo(a)));
        assertThat(a.cmov(b, 1), is(equalTo(b)));
    }

    /**
     * Test method for {@link GroupElement#select(int, int)}.
     */
    @Test
    public void testSelect() {
        final GroupElement B = ed25519.groupElement;
        for (int i = 0; 32 > i; i++) {
            // 16^i 0 B
            assertThat(i + ",0", B.select(i, 0),
                    is(equalTo(GroupElement.precomp(curve, ONE, ONE, ZERO))));
            for (int j = 1; 8 > j; j++) {
                // 16^i r_i B
                GroupElement t = B.select(i, j);
                assertThat(i + "," + j,
                        t, is(equalTo(B.precmp[i][j-1])));
                // -16^i r_i B
                final GroupElement t3 = B.select(i, -j);
                final GroupElement neg = GroupElement.precomp(curve,
                        B.precmp[i][j-1].Y,
                        B.precmp[i][j-1].X,
                        B.precmp[i][j-1].Z.negate());
                assertThat(i + "," + -j,
                        t3, is(equalTo(neg)));
            }
        }
    }

    // region scalar multiplication
    /**
     * Test method for {@link GroupElement#scalarMultiply(byte[])}.
     * Test values generated with Python Ed25519 implementation.
     */
    @Test
    public void testScalarMultiplyByteArray() {
        // Little-endian
        final byte[] zero = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000");
        final byte[] one = Utils.hexToBytes("0100000000000000000000000000000000000000000000000000000000000000");
        final byte[] two = Utils.hexToBytes("0200000000000000000000000000000000000000000000000000000000000000");
        final byte[] a = Utils.hexToBytes("d072f8dd9c07fa7bc8d22a4b325d26301ee9202f6db89aa7c3731529e37e437c");
        final GroupElement A = new GroupElement(curve, Utils.hexToBytes("d4cf8595571830644bd14af416954d09ab7159751ad9e0f7a6cbd92379e71a66"));

        assertThat("scalarMultiply(0) failed",
                ed25519.groupElement.scalarMultiply(zero), is(equalTo(curve.getZero(GroupElement.Representation.P3))));
        assertThat("scalarMultiply(1) failed",
                ed25519.groupElement.scalarMultiply(one), is(equalTo(ed25519.groupElement)));
        assertThat("scalarMultiply(2) failed",
                ed25519.groupElement.scalarMultiply(two), is(equalTo(ed25519.groupElement.dbl())));

        assertThat("scalarMultiply(a) failed",
                ed25519.groupElement.scalarMultiply(a), is(equalTo(A)));
    }

    @Test
    public void scalarMultiplyBasePointWithZeroReturnsNeutralElement() {
        // Arrange:
        final GroupElement basePoint = ed25519.groupElement;

        // Act:
        final GroupElement g = basePoint.scalarMultiply(curve.getEdDSAFiniteField().ZERO.toByteArray());

        // Assert:
        assertThat(curve.getZero(GroupElement.Representation.P3), IsEqual.equalTo(g));
    }

    @Test
    public void scalarMultiplyBasePointWithOneReturnsBasePoint() {
        // Arrange:
        final GroupElement basePoint = ed25519.groupElement;

        // Act:
        final GroupElement g = basePoint.scalarMultiply(curve.getEdDSAFiniteField().ONE.toByteArray());

        // Assert:
        assertThat(basePoint, IsEqual.equalTo(g));
    }

    // This test is slow (~6s) due to math utils using an inferior algorithm to calculate the result.
    @Test
    public void scalarMultiplyBasePointReturnsExpectedResult() {
        for (int i = 0; 10 > i; i++) {
            // Arrange:
            final GroupElement basePoint = ed25519.groupElement;
            final FieldElement f = MathUtils.getRandomFieldElement();

            // Act:
            final GroupElement g = basePoint.scalarMultiply(f.toByteArray());
            final GroupElement h = MathUtils.scalarMultiplyGroupElement(basePoint, f);

            // Assert:
            assertThat(g, IsEqual.equalTo(h));
        }
    }

    @Test
    public void testDoubleScalarMultiplyVariableTime() {
        // Little-endian
        final byte[] zero = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000");
        final byte[] one = Utils.hexToBytes("0100000000000000000000000000000000000000000000000000000000000000");
        final byte[] two = Utils.hexToBytes("0200000000000000000000000000000000000000000000000000000000000000");
        final byte[] a = Utils.hexToBytes("d072f8dd9c07fa7bc8d22a4b325d26301ee9202f6db89aa7c3731529e37e437c");
        final GroupElement A = new GroupElement(curve, Utils.hexToBytes("d4cf8595571830644bd14af416954d09ab7159751ad9e0f7a6cbd92379e71a66"));
        final GroupElement B = ed25519.groupElement;
        final GroupElement geZero = curve.getZero(GroupElement.Representation.P3PrecomputedDouble);

        // 0 * GE(0) + 0 * GE(0) = GE(0)
        assertThat(geZero.doubleScalarMultiplyVariableTime(geZero, zero, zero),
                is(equalTo(geZero)));
        // 0 * GE(0) + 0 * B = GE(0)
        assertThat(B.doubleScalarMultiplyVariableTime(geZero, zero, zero),
                is(equalTo(geZero)));
        // 1 * GE(0) + 0 * B = GE(0)
        assertThat(B.doubleScalarMultiplyVariableTime(geZero, one, zero),
                is(equalTo(geZero)));
        // 1 * GE(0) + 1 * B = B
        assertThat(B.doubleScalarMultiplyVariableTime(geZero, one, one),
                is(equalTo(B)));
        // 1 * B + 1 * B = 2 * B
        assertThat(B.doubleScalarMultiplyVariableTime(B, one, one),
                is(equalTo(B.dbl())));
        // 1 * B + 2 * B = 3 * B
        assertThat(B.doubleScalarMultiplyVariableTime(B, one, two),
                is(equalTo(B.dbl().toP3().add(B.toCached()))));
        // 2 * B + 2 * B = 4 * B
        assertThat(B.doubleScalarMultiplyVariableTime(B, two, two),
                is(equalTo(B.dbl().toP3().dbl())));

        // 0 * B + a * B = A
        assertThat(B.doubleScalarMultiplyVariableTime(B, zero, a),
                is(equalTo(A)));
        // a * B + 0 * B = A
        assertThat(B.doubleScalarMultiplyVariableTime(B, a, zero),
                is(equalTo(A)));
        // a * B + a * B = 2 * A
        assertThat(B.doubleScalarMultiplyVariableTime(B, a, a),
                is(equalTo(A.dbl())));
    }

    // This test is slow (~6s) due to math utils using an inferior algorithm to calculate the result.
    @Test
    public void doubleScalarMultiplyVariableTimeReturnsExpectedResult() {
        for (int i = 0; 10 > i; i++) {
            // Arrange:
            final GroupElement basePoint = ed25519.groupElement;
            final GroupElement g = MathUtils.getRandomGroupElement(true);
            final FieldElement f1 = MathUtils.getRandomFieldElement();
            final FieldElement f2 = MathUtils.getRandomFieldElement();

            // Act:
            final GroupElement h1 = basePoint.doubleScalarMultiplyVariableTime(g, f2.toByteArray(), f1.toByteArray());
            final GroupElement h2 = doubleScalarMultiplyGroupElements(basePoint, f1, g, f2);

            // Assert:
            assertThat(h1, IsEqual.equalTo(h2));
        }
    }

    // endregion

    /**
     * Test method for {@link GroupElement#isOnCurve(Curve)}.
     */
    @Test
    public void testIsOnCurve() {
        assertThat(Boolean.valueOf(P2_ZERO.isOnCurve(curve)),
                is(Boolean.TRUE));
        assertThat(Boolean.valueOf(GroupElement.p2(curve, ZERO, ZERO, ONE).isOnCurve(curve)),
                is(Boolean.FALSE));
        assertThat(Boolean.valueOf(GroupElement.p2(curve, ONE, ONE, ONE).isOnCurve(curve)),
                is(Boolean.FALSE));
        assertThat(Boolean.valueOf(GroupElement.p2(curve, TEN, ZERO, ONE).isOnCurve(curve)),
                is(Boolean.FALSE));
        assertThat(Boolean.valueOf(GroupElement.p2(curve, ONE, TEN, ONE).isOnCurve(curve)),
                is(Boolean.FALSE));
        assertThat(Boolean.valueOf(GroupElement.p2(curve, PKR[0], PKR[1], ONE).isOnCurve(curve)),
                is(Boolean.TRUE));
    }

    @Test
    public void isOnCurveReturnsTrueForPointsOnTheCurve() {
        for (int i = 0; 100 > i; i++) {
            // Arrange:
            final GroupElement g = MathUtils.getRandomGroupElement();

            // Assert:
            assertThat(Boolean.valueOf(g.isOnCurve()), IsEqual.equalTo(Boolean.TRUE));
        }
    }

    @Test
    public void isOnCurveReturnsFalseForPointsNotOnTheCurve() {
        for (int i = 0; 100 > i; i++) {
            // Arrange:
            final GroupElement g = MathUtils.getRandomGroupElement();
            final GroupElement h = GroupElement.p2(curve, g.getX(), g.getY(), g.getZ().multiply(curve.getEdDSAFiniteField().TWO));

            // Assert (can only fail for 5*Z^2=1):
            assertThat(Boolean.valueOf(h.isOnCurve()), IsEqual.equalTo(Boolean.FALSE));
        }
    }
}
