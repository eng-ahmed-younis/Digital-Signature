package com.dev.digitalsignature.data.repository

import com.dev.digitalsignature.CryptoManager
import com.dev.digitalsignature.data.model.RegisterPublicKeyRequest
import com.dev.digitalsignature.data.service.ApiService
import com.dev.digitalsignature.keys.KeysManger

class DeviceRegistrationRepository(
    private val apiService: ApiService
) {
    private val cryptoManager = CryptoManager(
        keysProvider = KeysManger()
    )

    suspend fun registerDevice(
        userId: String,
        deviceId: String
    ) {
        cryptoManager.generateKeysIfNeeded()

        val publicKeyBase64 = cryptoManager.getSigningPublicKeyBase64()

        val request = RegisterPublicKeyRequest(
            userId = userId,
            deviceId = deviceId,
            publicKeyBase64 = publicKeyBase64
        )

        apiService.registerPublicKey(request)
    }
}