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
import java.util.stream.Collectors

import net.i2p.crypto.eddsa.Utils.*

interface Ed25519TestVectors {
    class TestTuple private constructor(line: String) {
        val caseNum: Int
        val seed: ByteArray
        val pk: ByteArray
        val message: ByteArray
        val sig: ByteArray

        init {
            caseNum = ++numCases
            val x = line.split(":".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
            seed = hexToBytes(x[0].substring(0, 64))
            pk = hexToBytes(x[1])
            message = hexToBytes(x[2])
            sig = hexToBytes(x[3].substring(0, 128))
        }

        companion object {
            private var numCases: Int = 0
        }
    }

    companion object {

        val testCases: Collection<Ed25519TestVectors.TestTuple> = getTestData("test.data")

        fun getTestData(fileName: String): Collection<Ed25519TestVectors.TestTuple> {
            var testCases: List<Ed25519TestVectors.TestTuple> = ArrayList()
            var file: BufferedReader? = null
            try {
                val `is` = Ed25519TestVectors::class.java.getResourceAsStream(fileName)
                        ?: throw IOException("Resource not found: $fileName")
                file = BufferedReader(InputStreamReader(`is`))
                testCases = file.lines().map<TestTuple>(Function<String, TestTuple> { Ed25519TestVectors.TestTuple(it) }).collect<List<TestTuple>, Any>(Collectors.toList())
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
}
