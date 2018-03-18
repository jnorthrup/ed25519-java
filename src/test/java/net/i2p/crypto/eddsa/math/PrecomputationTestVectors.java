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

class PrecomputationTestVectors {
    // Test files were generated using base.py and base2.py from ref10
    // (by printing hex(x%q) instead of the radix-255 representation).
    static final GroupElement[][] testPrecmp = getPrecomputation("basePrecmp");
    static final GroupElement[] testDblPrecmp = getDoublePrecomputation("baseDblPrecmp");

    private static GroupElement[][] getPrecomputation(final String fileName) {
        final EdDSANamedCurveSpec ed25519 = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        final Curve curve = ed25519.curve;
        final EdDSAFiniteField edDSAFiniteField = curve.getEdDSAFiniteField();
        final GroupElement[][] precmp = new GroupElement[32][8];
        BufferedReader file = null;
        int row = 0;
        int col = 0;
        try {
            final InputStream is = PrecomputationTestVectors.class.getResourceAsStream(fileName);
            if (null == is)
                throw new IOException("Resource not found: " + fileName);
            file = new BufferedReader(new InputStreamReader(is));
            while (true) {
                String  line = file.readLine();
                if ((null != (line))) {
                    if (!" },".equals(line)) {
                        if (!"},".equals(line)) {
                            if (line.startsWith("  { ")) {
                                final String ypxStr = line.substring(4, line.lastIndexOf(' '));
                                final FieldElement ypx = edDSAFiniteField.fromByteArray(
                                        Utils.hexToBytes(ypxStr));
                                String s = file.readLine();
                                final String ymxStr = s.substring(4, s.lastIndexOf(' '));
                                final FieldElement ymx = edDSAFiniteField.fromByteArray(
                                        Utils.hexToBytes(ymxStr));
                                String s3 = file.readLine();
                                final String xy2dStr = s3.substring(4, s3.lastIndexOf(' '));
                                final FieldElement xy2d = edDSAFiniteField.fromByteArray(
                                        Utils.hexToBytes(xy2dStr));
                                precmp[row][col] = GroupElement.precomp(curve,
                                        ypx, ymx, xy2d);
                            }
                        } else {
                            col = 0;
                            row += 1;
                        }
                    } else {
                        col += 1;
                    }
                } else {
                    break;
                }
            }
        } catch (final IOException e) {
            e.printStackTrace();
        } finally {
            if (null != file) try { file.close(); } catch (final IOException e) {}
        }
        return precmp;
    }

    private static GroupElement[] getDoublePrecomputation(final String fileName) {
        final EdDSANamedCurveSpec ed25519 = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        final Curve curve = ed25519.curve;
        final EdDSAFiniteField edDSAFiniteField = curve.getEdDSAFiniteField();
        final GroupElement[] dblPrecmp = new GroupElement[8];
        BufferedReader file = null;
        int row = 0;
        try {
            final InputStream is = PrecomputationTestVectors.class.getResourceAsStream(fileName);
            if (null == is)
                throw new IOException("Resource not found: " + fileName);
            file = new BufferedReader(new InputStreamReader(is));
            while (true) {
                String  line = file.readLine();
                if ((null != line)) {
                    if (!" },".equals(line)) {
                        if (line.startsWith("  { ")) {
                            final String ypxStr = line.substring(4, line.lastIndexOf(' '));
                            final FieldElement ypx = edDSAFiniteField.fromByteArray(
                                    Utils.hexToBytes(ypxStr));
                            String s2 = file.readLine();
                            final String ymxStr = s2.substring(4, s2.lastIndexOf(' '));
                            final FieldElement ymx = edDSAFiniteField.fromByteArray(
                                    Utils.hexToBytes(ymxStr));
                            String s4 = file.readLine();
                            final String xy2dStr = s4.substring(4, s4.lastIndexOf(' '));
                            final FieldElement xy2d = edDSAFiniteField.fromByteArray(
                                    Utils.hexToBytes(xy2dStr));
                            dblPrecmp[row] = GroupElement.precomp(curve,
                                    ypx, ymx, xy2d);
                        }
                    } else {
                        row += 1;
                    }
                } else {
                    break;
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
