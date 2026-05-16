package com.dev.digitalsignature.data.service

import com.dev.digitalsignature.data.model.RegisterPublicKeyRequest
import com.dev.digitalsignature.data.model.SecureEncryptedRequest
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.POST

interface ApiService {

    @POST("/api/device/register-public-key")
    suspend fun registerPublicKey(
        @Body request: RegisterPublicKeyRequest
    ): Response<Unit>

    @POST("/api/secure/encrypted-data")
    suspend fun sendEncryptedData(
        @Body request: SecureEncryptedRequest
    ): Response<Unit>
}