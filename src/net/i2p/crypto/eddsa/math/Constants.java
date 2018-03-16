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

import net.i2p.crypto.eddsa.Utils;

  interface Constants {
    byte[] ZERO = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000") 
    , ONE = Utils.hexToBytes("0100000000000000000000000000000000000000000000000000000000000000") 
    , TWO = Utils.hexToBytes("0200000000000000000000000000000000000000000000000000000000000000") 
    , FOUR = Utils.hexToBytes("0400000000000000000000000000000000000000000000000000000000000000") 
    , FIVE = Utils.hexToBytes("0500000000000000000000000000000000000000000000000000000000000000") 
    , EIGHT = Utils.hexToBytes("0800000000000000000000000000000000000000000000000000000000000000");
}
