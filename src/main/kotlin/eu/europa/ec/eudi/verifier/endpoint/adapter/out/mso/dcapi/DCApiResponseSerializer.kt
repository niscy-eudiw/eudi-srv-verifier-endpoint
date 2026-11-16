/*
 * Copyright (c) 2023-2026 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.dcapi

import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.base64UrlNoPadding
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.cbor
import eu.europa.ec.eudi.verifier.endpoint.domain.Iso180137
import eu.europa.ec.eudi.verifier.endpoint.domain.mso.dcapi.DCApiResponse
import eu.europa.ec.eudi.verifier.endpoint.domain.mso.dcapi.EncryptedResponse
import kotlinx.serialization.*
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

object DCApiResponseSerializer : KSerializer<DCApiResponse> {
    private val serializer = DCApiResponseDelegate.serializer()

    override val descriptor: SerialDescriptor
        get() = serializer.descriptor

    override fun serialize(
        encoder: Encoder,
        value: DCApiResponse,
    ) {
        val delegate = DCApiResponseDelegate(value)
        encoder.encodeSerializableValue(serializer, delegate)
    }

    override fun deserialize(decoder: Decoder): DCApiResponse {
        val delegate = decoder.decodeSerializableValue(serializer)
        return DCApiResponse(delegate)
    }
}

@Serializable
private data class DCApiResponseDelegate(
    @Required @SerialName(Iso180137.RESPONSE) val response: String,
) {
    constructor(value: DCApiResponse) : this(base64UrlNoPadding.encode(cbor.encodeToByteArray(value.encryptedResponse)))
}

private fun DCApiResponse(value: DCApiResponseDelegate): DCApiResponse {
    val encryptedResponse =
        cbor.decodeFromByteArray<EncryptedResponse>(
            base64UrlNoPadding.decode(value.response),
        )

    return DCApiResponse(encryptedResponse)
}
