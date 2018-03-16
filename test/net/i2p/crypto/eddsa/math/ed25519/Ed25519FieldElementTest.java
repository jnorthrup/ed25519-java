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
package net.i2p.crypto.eddsa.math.ed25519;

import net.i2p.crypto.eddsa.math.*;
import org.hamcrest.core.*;
import org.junit.*;

import java.math.BigInteger;

/**
 * Tests rely on the BigInteger class.
 */
public class Ed25519FieldElementTest extends AbstractFieldElementTest {

    private static final byte[] BYTES = {
            (byte) (0 + 1),
            (byte) (1 + 1),
            (byte) (2 + 1),
            (byte) (3 + 1),
            (byte) (4 + 1),
            (byte) (5 + 1),
            (byte) (6 + 1),
            (byte) (7 + 1),
            (byte) (8 + 1),
            (byte) (9 + 1),
            (byte) (10 + 1),
            (byte) (11 + 1),
            (byte) (12 + 1),
            (byte) (13 + 1),
            (byte) (14 + 1),
            (byte) (15 + 1),
            (byte) (16 + 1),
            (byte) (17 + 1),
            (byte) (18 + 1),
            (byte) (19 + 1),
            (byte) (20 + 1),
            (byte) (21 + 1),
            (byte) (22 + 1),
            (byte) (23 + 1),
            (byte) (24 + 1),
            (byte) (25 + 1),
            (byte) (26 + 1),
            (byte) (27 + 1),
            (byte) (28 + 1),
            (byte) (29 + 1),
            (byte) (30 + 1),
            (byte) (31 + 1)};

    protected FieldElement getRandomFieldElement() {
        return MathUtils.getRandomFieldElement();
    }

    protected BigInteger toBigInteger(FieldElement f) {
        return MathUtils.toBigInteger(f);
    }

    protected BigInteger getQ() {
        return MathUtils.getQ();
    }

    protected Field getField() {
        return MathUtils.getField();
    }

    // region constructor

    @Test
    public void canConstructFieldElementFromArrayWithCorrectLength() {
        // Assert:
        new Ed25519FieldElement(MathUtils.getField(), new int[10]);
    }

    @Test (expected = IllegalArgumentException.class)
    public void cannotConstructFieldElementFromArrayWithIncorrectLength() {
        // Assert:
        new Ed25519FieldElement(MathUtils.getField(), new int[9]);
    }

    @Test (expected = IllegalArgumentException.class)
    public void cannotConstructFieldElementWithoutField() {
        // Assert:
        new Ed25519FieldElement(null, new int[9]);
    }

    // endregion

    // region isNonZero

    protected FieldElement getZeroFieldElement() {
        return new Ed25519FieldElement(MathUtils.getField(), new int[10]);
    }

    protected FieldElement getNonZeroFieldElement() {
        final int[] t = new int[10];
        t[0] = 5;
        return new Ed25519FieldElement(MathUtils.getField(), t);
    }

    // endregion

    // region toString

    @Test
    public void toStringReturnsCorrectRepresentation() {
        // Arrange:
        final FieldElement f = MathUtils.getField().getEncoding().decode(BYTES);

        // Act:
        final String fAsString = f.toString();
        final StringBuilder builder = new StringBuilder();
        builder.append("[Ed25519FieldElement val=");
        for (byte b : BYTES) {
            builder.append(String.format("%02x", b));
        }
        builder.append("]");

        // Assert:
        Assert.assertThat(fAsString, IsEqual.equalTo(builder.toString()));
    }

    // endregion
}
