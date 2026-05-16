package com.dev.digitalsignature.model


data class EncryptedPayload(
    val cipherTextBase64: String,
    val ivBase64: String
)