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

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.SignatureException
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.InvalidKeySpecException
import java.security.spec.X509EncodedKeySpec
import java.util.Arrays
import java.util.Objects
import java.util.stream.IntStream

import sun.security.x509.X509Key

/**
 * Signing and verification for EdDSA.
 *
 *
 * The EdDSA sign and verify algorithms do not interact well with
 * the Java Signature API, as one or more update() methods must be
 * called before sign() or verify(). Using the standard API,
 * this implementation must copy and buffer all data passed in
 * via update().
 *
 *
 * This implementation offers two ways to avoid this copying,
 * but only if all data to be signed or verified is available
 * in a single byte array.
 *
 *
 * Option 1:
 *
 *  1. Call initSign() or initVerify() as usual.
 *  1. Call setParameter(ONE_SHOT_MODE)
 *  1. Call update(byte[]) or update(byte[], int, int) exactly once
 *  1. Call sign() or verify() as usual.
 *  1. If doing additional one-shot signs or verifies with this object, you must
 * call setParameter(ONE_SHOT_MODE) each time
 *
 *
 *
 *
 * Option 2:
 *
 *  1. Call initSign() or initVerify() as usual.
 *  1. Call one of the signOneShot() or verifyOneShot() methods.
 *  1. If doing additional one-shot signs or verifies with this object,
 * just call signOneShot() or verifyOneShot() again.
 *
 *
 * @author str4d
 */
class EdDSAEngine
/**
 * No specific EdDSA-internal hash requested, allows any EdDSA key.
 */
() : Signature(SIGNATURE_ALGORITHM) {

    private var digest: MessageDigest? = null
    private var baos: ByteArrayOutputStream? = null
    private var key: EdDSAKey? = null
    var oneShotMode: Boolean = false
    var oneShotBytes: ByteArray? = null
    var oneShotOffset: Int = 0
    var oneShotLength: Int = 0

    class OneShotSpec : AlgorithmParameterSpec

    /**
     * Specific EdDSA-internal hash requested, only matching keys will be allowed.
     * @param digest the hash algorithm that keys must have to sign or verify.
     */
    constructor(digest: MessageDigest) : this() {
        this.digest = digest
    }

    fun reset() {
        if (null != digest)
            digest!!.reset()
        if (null != baos)
            baos!!.reset()
        oneShotMode = false
        oneShotBytes = null
    }

    @Throws(InvalidKeyException::class)
    override fun engineInitSign(privateKey: PrivateKey) {
        reset()
        if (privateKey is EdDSAPrivateKey) {
            key = privateKey

            if (null == digest) {
                // Instantiate the digest from the key parameters
                try {
                    digest = MessageDigest.getInstance(key!!.edDSAParameterSpec.hashAlgo)
                } catch (e: NoSuchAlgorithmException) {
                    throw InvalidKeyException("cannot get required digest " + key!!.edDSAParameterSpec.hashAlgo + " for private key.")
                }

            } else
                assert(key!!.edDSAParameterSpec.hashAlgo == digest!!.algorithm) { "Key hash algorithm does not match chosen digest" }
            digestInitSign(privateKey)
        } else {
            throw InvalidKeyException("cannot identify EdDSA private key: " + privateKey.javaClass)
        }
    }

    fun digestInitSign(privKey: EdDSAPrivateKey) {
        // Preparing for hash
        // r = H(h_b,...,h_2b-1,M)
        val b = privKey.edDSAParameterSpec.curve.edDSAFiniteField.b
        digest!!.update(privKey.hashOfTheSeed, b / 8, b / 4 - b / 8)
    }

    @Throws(InvalidKeyException::class)
    override fun engineInitVerify(publicKey: PublicKey) {
        reset()
        if (publicKey is EdDSAPublicKey) {
            key = publicKey

            if (null == digest) {
                // Instantiate the digest from the key parameters
                try {
                    digest = MessageDigest.getInstance(key!!.edDSAParameterSpec.hashAlgo)
                } catch (e: NoSuchAlgorithmException) {
                    throw InvalidKeyException("cannot get required digest " + key!!.edDSAParameterSpec.hashAlgo + " for private key.")
                }

            } else
                assert(key!!.edDSAParameterSpec.hashAlgo == digest!!.algorithm) { "Key hash algorithm does not match chosen digest" }
        } else if (publicKey is X509Key) {
            // X509Certificate will sometimes contain an X509Key rather than the EdDSAPublicKey itself; the contained
            // key is valid but needs to be instanced as an EdDSAPublicKey before it can be used.
            val parsedPublicKey: EdDSAPublicKey
            try {
                parsedPublicKey = EdDSAPublicKey(X509EncodedKeySpec(publicKey.getEncoded()))
            } catch (ex: InvalidKeySpecException) {
                throw InvalidKeyException("cannot handle X.509 EdDSA public key: " + publicKey.getAlgorithm())
            }

            engineInitVerify(parsedPublicKey)
        } else {
            throw InvalidKeyException("cannot identify EdDSA public key: " + publicKey.javaClass)
        }
    }

    /**
     * @throws SignatureException if in one-shot mode
     */
    override fun engineUpdate(b: Byte) {
        assert(!oneShotMode) { "unsupported in one-shot mode" }
        if (null == baos)
            baos = ByteArrayOutputStream(256)
        baos!!.write(b.toInt())
    }

    /**
     * @throws SignatureException if one-shot rules are violated
     */
    @Throws(SignatureException::class)
    override fun engineUpdate(b: ByteArray, off: Int, len: Int) {
        if (oneShotMode) {
            if (null == oneShotBytes) {
                oneShotBytes = b.clone()
                oneShotOffset = off
                oneShotLength = len
            } else
                throw SignatureException("update() already called")
        } else {
            if (null == baos)
                baos = ByteArrayOutputStream(256)
            baos!!.write(b, off, len)
        }
    }

    @Throws(SignatureException::class)
    override fun engineSign(): ByteArray {
        try {
            return x_engineSign()
        } finally {
            reset()
            // must leave the object ready to sign again with
            // the same key, as required by the API
            val privKey = key as EdDSAPrivateKey?
            digestInitSign(privKey!!)
        }
    }

    fun x_engineSign(): ByteArray {
        val curve = key!!.edDSAParameterSpec.curve
        val sc = key!!.edDSAParameterSpec.scalarOps
        val a = (key as EdDSAPrivateKey).privateKey

        val message: ByteArray
        val offset: Int
        val length: Int
        if (oneShotMode) {
            Objects.requireNonNull<ByteArray>(oneShotBytes)
            message = oneShotBytes!!
            offset = oneShotOffset
            length = oneShotLength
        } else {
            message = if (null == baos) EMPTY else baos!!.toByteArray()
            offset = 0
            length = message.size
        }
        // r = H(h_b,...,h_2b-1,M)
        digest!!.update(message, offset, length)
        var r = digest!!.digest()

        // r mod l
        // Reduces r from 64 bytes to 32 bytes
        r = sc.reduce(r)

        // R = rB
        val R = key!!.edDSAParameterSpec.groupElement.scalarMultiply(r)
        val Rbyte = R.toByteArray()

        // S = (r + H(Rbar,Abar,M)*a) mod l
        digest!!.update(Rbyte)
        digest!!.update((key as EdDSAPrivateKey).getaByte())
        digest!!.update(message, offset, length)
        var h = digest!!.digest()
        h = sc.reduce(h)
        val S = sc.multiplyAndAdd(h, a, r)

        // R+S
        val b = curve.edDSAFiniteField.b
        val out = ByteBuffer.allocate(b / 4)
        out.put(Rbyte).put(S)
        return out.array()
    }

    @Throws(SignatureException::class)
    override fun engineVerify(sigBytes: ByteArray): Boolean {
        try {
            return x_engineVerify(sigBytes)
        } finally {
            reset()
        }
    }

    fun x_engineVerify(sigBytes: ByteArray): Boolean {
        val curve = key!!.edDSAParameterSpec.curve
        val b = curve.edDSAFiniteField.b
        assert(sigBytes.size == b / 4) { "signature length is wrong" }

        // R is first b/8 bytes of sigBytes, S is second b/8 bytes
        digest!!.update(sigBytes, 0, b / 8)
        digest!!.update((key as EdDSAPublicKey).getaByte())
        // h = H(Rbar,Abar,M)
        val message: ByteArray
        val offset: Int
        val length: Int
        if (oneShotMode) {
            Objects.requireNonNull<ByteArray>(oneShotBytes)
            message = this!!.oneShotBytes!!
            offset = oneShotOffset
            length = oneShotLength
        } else {
            message = if (null == baos) EMPTY else baos!!.toByteArray()
            offset = 0
            length = message.size
        }
        digest!!.update(message, offset, length)
        var h = digest!!.digest()

        // h mod l
        h = key!!.edDSAParameterSpec.scalarOps.reduce(h)

        val Sbyte = Arrays.copyOfRange(sigBytes, b / 8, b / 4)
        // R = SB - H(Rbar,Abar,M)A
        val R = key!!.edDSAParameterSpec.groupElement.doubleScalarMultiplyVariableTime(
                (key as EdDSAPublicKey).getaNeg(), h, Sbyte)

        // Variable time. This should be okay, because there are no secret
        // values used anywhere in verification.
        val Rcalc = R.toByteArray()
        val bound = Rcalc.size
        return IntStream.range(0, bound).noneMatch { i -> Rcalc[i] != sigBytes[i] }
    }

    /**
     * To efficiently sign all the data in one shot, if it is available,
     * use this method, which will avoid copying the data.
     *
     * Same as:
     * <pre>
     * setParameter(ONE_SHOT_MODE)
     * update(data, off, len)
     * sig = sign()
    </pre> *
     *
     * @param data byte array containing the message to be signed
     * @param off the start of the message inside data
     * @param len the length of the message
     * @return the signature
     * @throws SignatureException if update() already called
     * @see .ONE_SHOT_MODE
     */
    @Throws(SignatureException::class)
    @JvmOverloads
    fun signOneShot(data: ByteArray, off: Int = 0, len: Int = data.size): ByteArray {
        oneShotMode = true
        update(data, off, len)
        return sign()
    }

    /**
     * To efficiently verify all the data in one shot, if it is available,
     * use this method, which will avoid copying the data.
     *
     * Same as:
     * <pre>
     * setParameter(ONE_SHOT_MODE)
     * update(data)
     * ok = verify(signature)
    </pre> *
     *
     * @param data the message that was signed
     * @param signature of the message
     * @return true if the signature is valid, false otherwise
     * @throws SignatureException if update() already called
     * @see .ONE_SHOT_MODE
     */
    @Throws(SignatureException::class)
    fun verifyOneShot(data: ByteArray, signature: ByteArray): Boolean {
        return verifyOneShot(data, 0, data.size, signature, 0, signature.size)
    }

    /**
     * To efficiently verify all the data in one shot, if it is available,
     * use this method, which will avoid copying the data.
     *
     * Same as:
     * <pre>
     * setParameter(ONE_SHOT_MODE)
     * update(data)
     * ok = verify(signature, sigoff, siglen)
    </pre> *
     *
     * @param data the message that was signed
     * @param signature byte array containing the signature
     * @param sigoff the start of the signature
     * @param siglen the length of the signature
     * @return true if the signature is valid, false otherwise
     * @throws SignatureException if update() already called
     * @see .ONE_SHOT_MODE
     */
    @Throws(SignatureException::class)
    fun verifyOneShot(data: ByteArray, signature: ByteArray, sigoff: Int, siglen: Int): Boolean {
        return verifyOneShot(data, 0, data.size, signature, sigoff, siglen)
    }

    /**
     * To efficiently verify all the data in one shot, if it is available,
     * use this method, which will avoid copying the data.
     *
     * Same as:
     * <pre>
     * setParameter(ONE_SHOT_MODE)
     * update(data, off, len)
     * ok = verify(signature, sigoff, siglen)
    </pre> *
     *
     * @param data byte array containing the message that was signed
     * @param off the start of the message inside data
     * @param len the length of the message
     * @param signature byte array containing the signature
     * @param sigoff the start of the signature
     * @param siglen the length of the signature
     * @return true if the signature is valid, false otherwise
     * @throws SignatureException if update() already called
     * @see .ONE_SHOT_MODE
     */
    @Throws(SignatureException::class)
    @JvmOverloads
    fun verifyOneShot(data: ByteArray, off: Int, len: Int, signature: ByteArray, sigoff: Int = 0, siglen: Int = signature.size): Boolean {
        oneShotMode = true
        update(data, off, len)
        return verify(signature, sigoff, siglen)
    }

    /**
     * @throws InvalidAlgorithmParameterException if spec is ONE_SHOT_MODE and update() already called
     * @see .ONE_SHOT_MODE
     */
    @Throws(InvalidAlgorithmParameterException::class)
    override fun engineSetParameter(spec: AlgorithmParameterSpec) {
        if (spec == ONE_SHOT_MODE) {
            assert(null == oneShotBytes && (null == baos || 0 >= baos!!.size())) { "update() already called" }
            oneShotMode = true
        } else {
            super.engineSetParameter(spec)
        }
    }


    @Deprecated("")
    override fun engineSetParameter(param: String, value: Any) {
        throw UnsupportedOperationException("engineSetParameter unsupported")
    }


    @Deprecated("")
    override fun engineGetParameter(param: String): Any {
        throw UnsupportedOperationException("engineSetParameter unsupported")
    }

    companion object {
        val SIGNATURE_ALGORITHM = "NONEwithEdDSA"
        val EMPTY = ByteArray(0)

        /**
         * To efficiently sign or verify data in one shot, pass this to setParameters()
         * after initSign() or initVerify() but BEFORE THE FIRST AND ONLY
         * update(data) or update(data, off, len). The data reference will be saved
         * and then used in sign() or verify() without copying the data.
         * Violate these rules and you will get a SignatureException.
         */
        val ONE_SHOT_MODE: AlgorithmParameterSpec = OneShotSpec()
    }
}
/**
 * To efficiently sign all the data in one shot, if it is available,
 * use this method, which will avoid copying the data.
 *
 * Same as:
 * <pre>
 * setParameter(ONE_SHOT_MODE)
 * update(data)
 * sig = sign()
</pre> *
 *
 * @param data the message to be signed
 * @return the signature
 * @throws SignatureException if update() already called
 * @see .ONE_SHOT_MODE
 */
/**
 * To efficiently verify all the data in one shot, if it is available,
 * use this method, which will avoid copying the data.
 *
 * Same as:
 * <pre>
 * setParameter(ONE_SHOT_MODE)
 * update(data, off, len)
 * ok = verify(signature)
</pre> *
 *
 * @param data byte array containing the message that was signed
 * @param off the start of the message inside data
 * @param len the length of the message
 * @param signature of the message
 * @return true if the signature is valid, false otherwise
 * @throws SignatureException if update() already called
 * @see .ONE_SHOT_MODE
 */
