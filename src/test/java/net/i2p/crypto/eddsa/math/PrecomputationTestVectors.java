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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import net.i2p.crypto.eddsa.Utils;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;

public class PrecomputationTestVectors {
    // Test files were generated using base.py and base2.py from ref10
    // (by printing hex(x%q) instead of the radix-255 representation).
    static GroupElement[][] testPrecmp = getPrecomputation("basePrecmp");
    static GroupElement[] testDblPrecmp = getDoublePrecomputation("baseDblPrecmp");

    public static GroupElement[][] getPrecomputation(final String fileName) {
        final EdDSANamedCurveSpec ed25519 = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        final Curve curve = ed25519.curve;
        final EdDSAFiniteField edDSAFiniteField = curve.getField();
        final GroupElement[][] precmp = new GroupElement[32][8];
        BufferedReader file = null;
        int row = 0, col = 0;
        try {
            final InputStream is = PrecomputationTestVectors.class.getResourceAsStream(fileName);
            if (null == is)
                throw new IOException("Resource not found: " + fileName);
            file = new BufferedReader(new InputStreamReader(is));
            String line;
            while (null != (line = file.readLine())) {
                if (line.equals(" },"))
                    col += 1;
                else if (line.equals("},")) {
                    col = 0;
                    row += 1;
                } else if (line.startsWith("  { ")) {
                    final String ypxStr = line.substring(4, line.lastIndexOf(' '));
                    final FieldElement ypx = edDSAFiniteField.fromByteArray(
                            Utils.hexToBytes(ypxStr));
                    line = file.readLine();
                    final String ymxStr = line.substring(4, line.lastIndexOf(' '));
                    final FieldElement ymx = edDSAFiniteField.fromByteArray(
                            Utils.hexToBytes(ymxStr));
                    line = file.readLine();
                    final String xy2dStr = line.substring(4, line.lastIndexOf(' '));
                    final FieldElement xy2d = edDSAFiniteField.fromByteArray(
                            Utils.hexToBytes(xy2dStr));
                    precmp[row][col] = GroupElement.precomp(curve,
                            ypx, ymx, xy2d);
                }
            }
        } catch (final IOException e) {
            e.printStackTrace();
        } finally {
            if (null != file) try { file.close(); } catch (final IOException e) {}
        }
        return precmp;
    }

    public static GroupElement[] getDoublePrecomputation(final String fileName) {
        final EdDSANamedCurveSpec ed25519 = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        final Curve curve = ed25519.curve;
        final EdDSAFiniteField edDSAFiniteField = curve.getField();
        final GroupElement[] dblPrecmp = new GroupElement[8];
        BufferedReader file = null;
        int row = 0;
        try {
            final InputStream is = PrecomputationTestVectors.class.getResourceAsStream(fileName);
            if (null == is)
                throw new IOException("Resource not found: " + fileName);
            file = new BufferedReader(new InputStreamReader(is));
            String line;
            while (null != (line = file.readLine())) {
                if (line.equals(" },")) {
                    row += 1;
                } else if (line.startsWith("  { ")) {
                    final String ypxStr = line.substring(4, line.lastIndexOf(' '));
                    final FieldElement ypx = edDSAFiniteField.fromByteArray(
                            Utils.hexToBytes(ypxStr));
                    line = file.readLine();
                    final String ymxStr = line.substring(4, line.lastIndexOf(' '));
                    final FieldElement ymx = edDSAFiniteField.fromByteArray(
                            Utils.hexToBytes(ymxStr));
                    line = file.readLine();
                    final String xy2dStr = line.substring(4, line.lastIndexOf(' '));
                    final FieldElement xy2d = edDSAFiniteField.fromByteArray(
                            Utils.hexToBytes(xy2dStr));
                    dblPrecmp[row] = GroupElement.precomp(curve,
                            ypx, ymx, xy2d);
                }
            }
        } catch (final IOException e) {
            e.printStackTrace();
        } finally {
            if (null != file) try { file.close(); } catch (final IOException e) {}
        }
        return dblPrecmp;
    }
}
