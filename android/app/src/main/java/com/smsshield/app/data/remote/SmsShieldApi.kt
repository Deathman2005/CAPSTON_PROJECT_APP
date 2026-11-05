package com.smsshield.app.data.remote

import com.smsshield.domain.model.MessageScanApiRequest
import com.smsshield.domain.model.MessageScanApiResponse
import com.smsshield.domain.model.UrlScanApiRequest
import com.smsshield.domain.model.UrlScanApiResponse
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST

/**
 * Retrofit REST client for the SMS Shield FastAPI AI Backend.
 */
interface SmsShieldApi {

    @POST("api/v1/scan/message")
    suspend fun scanMessage(@Body request: MessageScanApiRequest): MessageScanApiResponse

    @POST("api/v1/scan/url")
    suspend fun scanUrl(@Body request: UrlScanApiRequest): UrlScanApiResponse

    @GET("health")
    suspend fun getHealth(): Map<String, Any>
}

