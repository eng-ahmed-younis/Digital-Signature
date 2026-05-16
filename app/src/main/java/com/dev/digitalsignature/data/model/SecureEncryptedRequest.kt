package com.dev.digitalsignature.data.model

data class SecureEncryptedRequest(
    val userId: String,
    val deviceId: String,
    val ivBase64: String,
    val cipherTextBase64: String,
    val signatureBase64: String,
    val signatureAlgorithm: String = "SHA256withECDSA",
    val encryptionAlgorithm: String = "AES/GCM/NoPadding"
)