package com.dev.digitalsignature.keys

import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.SecretKey

interface KeysProvider {
    /**
     * Generates an Elliptic Curve (EC) key pair for digital signatures if it doesn't already exist.
     */
    fun generateSigningKeyIfNeeded()

    /**
     * Generates a symmetric AES key for encryption/decryption if it doesn't already exist.
     */
    fun generateAesKeyIfNeeded()
    

    /**
     * Retrieves the private key from the Keystore to be used for signing data.
     */
    fun getSigningPrivateKey(): PrivateKey

    /**
     * Retrieves the public key from the Keystore to be used for signature verification.
     */
    fun getSigningPublicKey(): PublicKey
    

    /**
     * Retrieves the symmetric AES key from the Keystore.
     */
    fun getAesKey(): SecretKey

}