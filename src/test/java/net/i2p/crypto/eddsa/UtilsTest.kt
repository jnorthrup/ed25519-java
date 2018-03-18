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

import org.hamcrest.core.IsEqual
import org.junit.*

import java.security.SecureRandom

import org.hamcrest.Matchers.`is`
import org.junit.Assert.assertThat

/**
 * @author str4d
 * additional test by the NEM project team.
 */
class UtilsTest {

    /**
     * Test method for [net.i2p.crypto.eddsa.Utils.equal].
     */
    @Test
    fun testIntEqual() {
        assertThat(Integer.valueOf(Utils.equal(0, 0)), `is`(Integer.valueOf(1)))
        assertThat(Integer.valueOf(Utils.equal(1, 1)), `is`(Integer.valueOf(1)))
        assertThat(Integer.valueOf(Utils.equal(1, 0)), `is`(Integer.valueOf(0)))
        assertThat(Integer.valueOf(Utils.equal(1, 127)), `is`(Integer.valueOf(0)))
        assertThat(Integer.valueOf(Utils.equal(-127, 127)), `is`(Integer.valueOf(0)))
        assertThat(Integer.valueOf(Utils.equal(-42, -42)), `is`(Integer.valueOf(1)))
        assertThat(Integer.valueOf(Utils.equal(255, 255)), `is`(Integer.valueOf(1)))
        assertThat(Integer.valueOf(Utils.equal(-255, -256)), `is`(Integer.valueOf(0)))
    }

    @Test
    fun equalsReturnsOneForEqualByteArrays() {
        val random = SecureRandom()
        val bytes1 = ByteArray(32)
        val bytes2 = ByteArray(32)
        var i = 0
        while (100 > i) {
            random.nextBytes(bytes1)
            System.arraycopy(bytes1, 0, bytes2, 0, 32)
            Assert.assertThat(Integer.valueOf(Utils.equal(bytes1, bytes2)), IsEqual.equalTo(Integer.valueOf(1)))
            i++
        }
    }

    @Test
    fun equalsReturnsZeroForUnequalByteArrays() {
        val random = SecureRandom()
        val bytes1 = ByteArray(32)
        val bytes2 = ByteArray(32)
        random.nextBytes(bytes1)
        var i = 0
        while (32 > i) {
            System.arraycopy(bytes1, 0, bytes2, 0, 32)
            bytes2[i] = (bytes2[i] as Int xor 0xff).toByte()
            Assert.assertThat(Integer.valueOf(Utils.equal(bytes1, bytes2)), IsEqual.equalTo(Integer.valueOf(0)))
            i++
        }
    }

    /**
     * Test method for [net.i2p.crypto.eddsa.Utils.equal].
     */
    @Test
    fun testByteArrayEqual() {
        val zero = ByteArray(32)
        val one = ByteArray(32)
        one[0] = 1.toByte()

        assertThat(Integer.valueOf(Utils.equal(zero, zero)), `is`(Integer.valueOf(1)))
        assertThat(Integer.valueOf(Utils.equal(one, one)), `is`(Integer.valueOf(1)))
        assertThat(Integer.valueOf(Utils.equal(one, zero)), `is`(Integer.valueOf(0)))
        assertThat(Integer.valueOf(Utils.equal(zero, one)), `is`(Integer.valueOf(0)))
    }

    /**
     * Test method for [net.i2p.crypto.eddsa.Utils.negative].
     */
    @Test
    fun testNegative() {
        assertThat(Integer.valueOf(Utils.negative(0)), `is`(Integer.valueOf(0)))
        assertThat(Integer.valueOf(Utils.negative(1)), `is`(Integer.valueOf(0)))
        assertThat(Integer.valueOf(Utils.negative(-1)), `is`(Integer.valueOf(1)))
        assertThat(Integer.valueOf(Utils.negative(32)), `is`(Integer.valueOf(0)))
        assertThat(Integer.valueOf(Utils.negative(-100)), `is`(Integer.valueOf(1)))
        assertThat(Integer.valueOf(Utils.negative(127)), `is`(Integer.valueOf(0)))
        assertThat(Integer.valueOf(Utils.negative(-255)), `is`(Integer.valueOf(1)))
    }

    /**
     * Test method for [net.i2p.crypto.eddsa.Utils.bit].
     */
    @Test
    fun testBit() {
        assertThat(Integer.valueOf(Utils.bit(byteArrayOf(0.toByte()), 0)), `is`(Integer.valueOf(0)))
        assertThat(Integer.valueOf(Utils.bit(byteArrayOf(8.toByte()), 3)), `is`(Integer.valueOf(1)))
        assertThat(Integer.valueOf(Utils.bit(byteArrayOf(1.toByte(), 2.toByte(), 3.toByte()), 9)), `is`(Integer.valueOf(1)))
        assertThat(Integer.valueOf(Utils.bit(byteArrayOf(1.toByte(), 2.toByte(), 3.toByte()), 15)), `is`(Integer.valueOf(0)))
        assertThat(Integer.valueOf(Utils.bit(byteArrayOf(1.toByte(), 2.toByte(), 3.toByte()), 16)), `is`(Integer.valueOf(1)))
    }

    @Test
    fun hexToBytesReturnsCorrectByteArray() {
        Assert.assertThat(Utils.hexToBytes(hex1), IsEqual.equalTo(bytes1))
        Assert.assertThat(Utils.hexToBytes(hex2), IsEqual.equalTo(bytes2))
        Assert.assertThat(Utils.hexToBytes(hex3), IsEqual.equalTo(bytes3))
    }

    @Test
    fun bytesToHexReturnsCorrectHexString() {
        Assert.assertThat(Utils.bytesToHex(bytes1), IsEqual.equalTo(hex1))
        Assert.assertThat(Utils.bytesToHex(bytes2), IsEqual.equalTo(hex2))
        Assert.assertThat(Utils.bytesToHex(bytes3), IsEqual.equalTo(hex3))
    }

    companion object {
        private val hex1 = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
        private val hex2 = "47a3f5b71494bcd961f3a4e859a238d6eaf8e648746d2f56a89b5e236f98d45f"
        private val hex3 = "5fd396e4a2b5dc9078f57e3ab5a87c28fd128e5f78cc4a97f4122dc45f6e4bb9"
        private val bytes1 = byteArrayOf(59.toByte(), 106.toByte(), 39.toByte(), (-68).toByte(), (-50).toByte(), (-74).toByte(), (-92).toByte(), 45.toByte(), 98.toByte(), (-93).toByte(), (-88).toByte(), (-48).toByte(), 42.toByte(), 111.toByte(), 13.toByte(), 115.toByte(), 101.toByte(), 50.toByte(), 21.toByte(), 119.toByte(), 29.toByte(), (-30).toByte(), 67.toByte(), (-90).toByte(), 58.toByte(), (-64).toByte(), 72.toByte(), (-95).toByte(), (-117).toByte(), 89.toByte(), (-38).toByte(), 41.toByte())
        private val bytes2 = byteArrayOf(71.toByte(), (-93).toByte(), (-11).toByte(), (-73).toByte(), 20.toByte(), (-108).toByte(), (-68).toByte(), (-39).toByte(), 97.toByte(), (-13).toByte(), (-92).toByte(), (-24).toByte(), 89.toByte(), (-94).toByte(), 56.toByte(), (-42).toByte(), (-22).toByte(), (-8).toByte(), (-26).toByte(), 72.toByte(), 116.toByte(), 109.toByte(), 47.toByte(), 86.toByte(), (-88).toByte(), (-101).toByte(), 94.toByte(), 35.toByte(), 111.toByte(), (-104).toByte(), (-44).toByte(), 95.toByte())
        private val bytes3 = byteArrayOf(95.toByte(), (-45).toByte(), (-106).toByte(), (-28).toByte(), (-94).toByte(), (-75).toByte(), (-36).toByte(), (-112).toByte(), 120.toByte(), (-11).toByte(), 126.toByte(), 58.toByte(), (-75).toByte(), (-88).toByte(), 124.toByte(), 40.toByte(), (-3).toByte(), 18.toByte(), (-114).toByte(), 95.toByte(), 120.toByte(), (-52).toByte(), 74.toByte(), (-105).toByte(), (-12).toByte(), 18.toByte(), 45.toByte(), (-60).toByte(), 95.toByte(), 110.toByte(), 75.toByte(), (-71).toByte())
    }
}
