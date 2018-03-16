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
package net.i2p.crypto.eddsa;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import static net.i2p.crypto.eddsa.Utils.*;

public interface  Ed25519TestVectors {
    final class TestTuple {
        private static int numCases;
        public final int caseNum;
        public final byte[] seed;
        public final byte[] pk;
        public final byte[] message;
        public final byte[] sig;

        private TestTuple(final String line) {
            caseNum = ++numCases;
            final String[] x = line.split(":");
            seed = hexToBytes(x[0].substring(0, 64));
            pk = hexToBytes(x[1]);
            message = hexToBytes(x[2]);
            sig = hexToBytes(x[3].substring(0, 128));
        }
    }

    Collection<Ed25519TestVectors.TestTuple> testCases = getTestData("test.data");

    static Collection<Ed25519TestVectors.TestTuple> getTestData(final String fileName) {
        List<Ed25519TestVectors.TestTuple> testCases = new ArrayList<Ed25519TestVectors.TestTuple>();
        BufferedReader file = null;
        try {
            final InputStream is = Ed25519TestVectors.class.getResourceAsStream(fileName);
            if (null == is)
                throw new IOException("Resource not found: " + fileName);
            file = new BufferedReader(new InputStreamReader(is));
            testCases = file.lines().map(Ed25519TestVectors.TestTuple::new).collect(Collectors.toList());
        } catch (final IOException e) {
            e.printStackTrace();
        } finally {
            if (null != file) try { file.close(); } catch (final IOException e) {}
        }
        return testCases;
    }
}
