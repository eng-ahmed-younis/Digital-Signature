package com.dev.digitalsignature.keys

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.dev.digitalsignature.keys.Keys.AES_KEY_ALIAS
import com.dev.digitalsignature.keys.Keys.ANDROID_KEYSTORE
import com.dev.digitalsignature.keys.Keys.SIGNING_KEY_ALIAS
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

class KeysManger : KeysProvider {

    private val keyStore: KeyStore by lazy {
        KeyStore.getInstance(Keys.ANDROID_KEYSTORE).apply {
            load(null)
        }
    }


    /**
     * Generates an Elliptic Curve (EC) key pair in the Android Keystore if the alias does not exist.
     * The key pair is configured for signing and verification using SHA-256.
     */
    override fun generateSigningKeyIfNeeded() {
        if (keyStore.containsAlias(Keys.SIGNING_KEY_ALIAS)) {
            return
        }

        val keyPairGenerator = KeyPairGenerator.getInstance(
            // Elliptic Curve -> EC to generate a key pair (public and private)
            KeyProperties.KEY_ALGORITHM_EC,
            Keys.ANDROID_KEYSTORE
        )

        /** secp256r1 is the common 256-bit elliptic curve used with KEY_ALGORITHM_EC.
         * It is also known as:
         * 1- NIST P-256
         * 2- prime256v1
         * 3- P-256
         * */
        val keySpec = KeyGenParameterSpec.Builder(
            Keys.SIGNING_KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(false)
            .build()


        keyPairGenerator.initialize(keySpec)
        keyPairGenerator.generateKeyPair()
    }




    /**
     * Generates a 256-bit AES key in the Android Keystore if the alias does not exist.
     * The key is configured for GCM mode with no padding.
     */
    override fun generateAesKeyIfNeeded() {
        if (keyStore.containsAlias(Keys.AES_KEY_ALIAS)) {
            return
        }

        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE
        )

        val keySpec = KeyGenParameterSpec.Builder(
            AES_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(false)
            .build()

        keyGenerator.init(keySpec)
        keyGenerator.generateKey()

    }

    /**
     * Retrieves the private key entry from the Keystore for the signing alias.
     */
    override fun getSigningPrivateKey(): PrivateKey {
        val entry = keyStore.getEntry(
            SIGNING_KEY_ALIAS,
            null
        ) as KeyStore.PrivateKeyEntry

        return entry.privateKey
    }

    /**
     * Retrieves the public key by extracting it from the X.509 certificate stored in the Keystore.
     */
    override fun getSigningPublicKey(): PublicKey {
        /** Android Keystore stores the public key wrapped inside a self-signed X.509 certificate.
         * When you call keyStore.getCertificate(alias), you are retrieving that certificate,
         * and .publicKey extracts the actual key you need to send to your server or use for verification.
         * */
        val certificate = keyStore.getCertificate(SIGNING_KEY_ALIAS)
            ?: throw IllegalStateException("Signing key not found. Did you call generateSigningKeyIfNeeded()?")

        return certificate.publicKey
    }

    /**
     * Retrieves the symmetric AES key from the Keystore.
     */
    override fun getAesKey(): SecretKey {
        return keyStore.getKey(Keys.AES_KEY_ALIAS, null) as SecretKey
    }


}

