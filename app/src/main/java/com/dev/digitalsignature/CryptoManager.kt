package com.dev.digitalsignature

import android.util.Base64
import com.dev.digitalsignature.keys.KeysProvider
import com.dev.digitalsignature.model.EncryptedPayload
import java.security.SecureRandom
import java.security.Signature
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec

class CryptoManager constructor(
    private val keysProvider: KeysProvider
){

    companion object {
        private const val GCM_TAG_LENGTH = 128 // bits
        private const val IV_SIZE_BYTES = 12 // bytes
        private const val AES_TRANSFORMATION = "AES/GCM/NoPadding"

        private const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
    }


    fun generateKeysIfNeeded() {
        keysProvider.generateSigningKeyIfNeeded()
        keysProvider.generateAesKeyIfNeeded()
    }


    /*** publicKey.encoded is binary data represented as a [ByteArray].
     * is not safe to send directly in JSON or store in a database.
     * converts those raw bytes into a safe text string
     *
     * This public key is sent to server one time.
     * Server uses it later to verify signatures.
     */
    fun getSigningPublicKeyBase64(): String {
        val publicKey = keysProvider.getSigningPublicKey()

        return Base64.encodeToString(
            publicKey.encoded,
            Base64.NO_WRAP
        )
    }


    /**
     * Encrypt plaintext using AES-GCM.
     */
    fun encryptData(plainText: String): EncryptedPayload {
        val secretKey = keysProvider.getAesKey()

        /** Creates a byte array with size [IV_SIZE_BYTES].
         * At first, the array contains zeros: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
         * SecureRandom().nextBytes(iv)
         * fills that same array with random bytes:
         * [34, -91, 8, 77, 120, -4, 51, 10, 99, -18, 7, 44]
         * */
     //   val iv = ByteArray(IV_SIZE_BYTES)
   //     SecureRandom().nextBytes(iv)

        val cipher = Cipher.getInstance(AES_TRANSFORMATION)

        /** creates the configuration needed for [AES-GCM] encryption/decryption.
         * 1. GCM_TAG_LENGTH = authentication tag size
         * 2. iv             = initialization vector / nonce
         *
         * text
         *   ↓
         * AES-256-GCM encrypt text
         *   ↓
         * iv + ciphertext + tag
         *   ↓
         * SHA256withECDSA sign iv || ciphertext || tag
         *   ↓
         * send to backend
         **/

    //    val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH, iv)

        cipher.init(
            Cipher.ENCRYPT_MODE,
            secretKey,
      //      gcmSpec
        )

        /** plainText.toByteArray(Charsets.UTF_8) -> converts your text into bytes.
         * Example: "hello" → [104, 101, 108, 108, 111]
         * encrypts those bytes using the cipher and returns the encrypted Array of bytes.
         * */
        val cipherText = cipher.doFinal(
            plainText.toByteArray(Charsets.UTF_8)
        )

        // Android Keystore AES-GCM, the recommended fix is: do not create IV yourself.
        // Let Android generate a secure random IV, then read it from cipher.iv.
        val iv = cipher.iv



        return EncryptedPayload(
            cipherTextBase64 = Base64.encodeToString(cipherText, Base64.NO_WRAP),
            ivBase64 = Base64.encodeToString(iv, Base64.NO_WRAP)
        )
    }

    /**
     * Optional local decrypt test.
     */
    fun decryptData(payload: EncryptedPayload): String {
        val secretKey = keysProvider.getAesKey()

        // Decodes ivBase64 strings into byte arrays
        val iv = Base64.decode(payload.ivBase64, Base64.NO_WRAP)
        // Decodes cipherTextBase64 strings into byte arrays
        val cipherText = Base64.decode(payload.cipherTextBase64, Base64.NO_WRAP)

        val cipher = Cipher.getInstance(AES_TRANSFORMATION)
        val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH, iv)

        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec)

        val plainBytes = cipher.doFinal(cipherText)

        return plainBytes.toString(Charsets.UTF_8)
    }



    /**
     * Sign encrypted data, not original plaintext.
     *
     * We sign:
     * iv + "." + ciphertext
     */
    fun signEncryptedPayload(payload: EncryptedPayload): String {
        val privateKey = keysProvider.getSigningPrivateKey()

        val dataToSign = buildDataToSign(payload)

        val signature = Signature.getInstance(SIGNATURE_ALGORITHM)
        signature.initSign(privateKey)
        signature.update(dataToSign.toByteArray(Charsets.UTF_8))

        val signatureBytes = signature.sign()

        return Base64.encodeToString(signatureBytes, Base64.NO_WRAP)
    }



    /**
     * Optional local signature verification.
     */
    fun verifySignatureLocally(
        payload: EncryptedPayload,
        signatureBase64: String
    ): Boolean {
        val publicKey = keysProvider.getSigningPublicKey()

        val dataToVerify = buildDataToSign(payload)

        val signature = Signature.getInstance(SIGNATURE_ALGORITHM)
        signature.initVerify(publicKey)
        signature.update(dataToVerify.toByteArray(Charsets.UTF_8))

        val signatureBytes = Base64.decode(signatureBase64, Base64.NO_WRAP)

        return signature.verify(signatureBytes)
    }





    private fun buildDataToSign(payload: EncryptedPayload): String {
        return payload.ivBase64 + "." + payload.cipherTextBase64
    }
}

/**
 * GCM_TAG_LENGTH is in bits, not bytes.
 * 128 means 16-byte tag.
 * iv is usually 12 bytes for AES-GCM.
 * The IV is not secret, but must be stored/sent with the ciphertext.
 * Never reuse the same IV with the same AES-GCM key.
 * */