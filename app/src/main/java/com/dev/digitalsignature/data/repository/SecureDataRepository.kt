package com.dev.digitalsignature.data.repository

import com.dev.digitalsignature.CryptoManager
import com.dev.digitalsignature.data.model.SecureEncryptedRequest
import com.dev.digitalsignature.data.service.ApiService
import com.dev.digitalsignature.keys.KeysManger

class SecureDataRepository(
    private val apiService: ApiService
) {
    private val cryptoManager = CryptoManager(
        keysProvider = KeysManger()
    )

    suspend fun sendSecureData(
        userId: String,
        deviceId: String,
        plainJson: String
    ) {
        cryptoManager.generateKeysIfNeeded()

        val encryptedPayload = cryptoManager.encryptData(plainJson)

        val signatureBase64 = cryptoManager.signEncryptedPayload(
            encryptedPayload
        )

        val request = SecureEncryptedRequest(
            userId = userId,
            deviceId = deviceId,
            ivBase64 = encryptedPayload.ivBase64,
            cipherTextBase64 = encryptedPayload.cipherTextBase64,
            signatureBase64 = signatureBase64
        )

        apiService.sendEncryptedData(request)
    }
}