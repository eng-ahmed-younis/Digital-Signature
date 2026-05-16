package com.dev.digitalsignature

import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import com.dev.digitalsignature.keys.KeysManger

class MainActivity : ComponentActivity() {

    private val cryptoManager = CryptoManager(
        keysProvider = KeysManger()
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        cryptoManager.generateKeysIfNeeded()

        val publicKey = cryptoManager.getSigningPublicKeyBase64()
        Log.d(TAG, "Send this public key to server: $publicKey")

        val plainText = """
            {
              "message": "hello server",
              "amount": 100
            }
        """.trimIndent()

        val encryptedPayload = cryptoManager.encryptData(plainText)

        val signature = cryptoManager.signEncryptedPayload(encryptedPayload)

        Log.d(TAG, "IV: ${encryptedPayload.ivBase64}")
        Log.d(TAG, "Encrypted data: ${encryptedPayload.cipherTextBase64}")
        Log.d(TAG, "Signature: $signature")

        val isValid = cryptoManager.verifySignatureLocally(
            encryptedPayload,
            signature
        )

        Log.d(TAG, "Signature valid: $isValid")

        val decryptedText = cryptoManager.decryptData(encryptedPayload)

        Log.d(TAG, "Decrypted: $decryptedText")
    }

    companion object {
        private const val TAG = "MainActivity"
    }
}


/***text
↓
AES-256-GCM encrypt text
↓
iv + ciphertext + tag
↓
SHA256withECDSA sign iv || ciphertext || tag
↓
send to backend

Backend:

verify signature
↓
decrypt ciphertext
↓
get original text


 */