package com.dev.digitalsignature.data.model

data class RegisterPublicKeyRequest(
    val userId: String,
    val deviceId: String,
    val publicKeyBase64: String,
    val signatureAlgorithm: String = "SHA256withECDSA"
)
