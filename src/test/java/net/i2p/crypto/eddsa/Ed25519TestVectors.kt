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
package net.i2p.crypto.eddsa

import java.io.BufferedReader
import java.io.IOException
import java.io.InputStream
import java.io.InputStreamReader
import java.util.ArrayList

object Ed25519TestVectors {

    val testCases = getTestData("test.data")

    class TestTuple internal constructor(line: String) {
        val caseNum: Int
        val seed: ByteArray
        val pk: ByteArray
        val message: ByteArray
        val sig: ByteArray

        init {
            caseNum = ++numCases
            val x = line.split(":".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
            seed = Utils.hexToBytes(x[0].substring(0, 64))
            pk = Utils.hexToBytes(x[1])
            message = Utils.hexToBytes(x[2])
            sig = Utils.hexToBytes(x[3].substring(0, 128))
        }

        companion object {
            internal var numCases: Int = 0
        }
    }

    private fun getTestData(fileName: String): Collection<TestTuple> {
        val testCases = ArrayList<TestTuple>()
        var file: BufferedReader? = null
        try {
            val `is` = Ed25519TestVectors::class.java.getResourceAsStream(fileName)
                    ?: throw IOException("Resource not found: $fileName")
            file = BufferedReader(InputStreamReader(`is`))

            while (true) {
                val line = file.readLine() ?: break
                testCases.add(TestTuple(line))
            }
        } catch (e: IOException) {
            e.printStackTrace()
        } finally {
            if (null != file) try {
                file.close()
            } catch (e: IOException) {
            }

        }
        return testCases
    }
}
