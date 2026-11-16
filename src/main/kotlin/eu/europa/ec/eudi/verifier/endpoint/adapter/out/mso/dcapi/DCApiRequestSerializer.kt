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

import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.EncryptionInfo
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.base64UrlNoPadding
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.cbor
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.toListElement
import eu.europa.ec.eudi.verifier.endpoint.domain.Iso180137
import eu.europa.ec.eudi.verifier.endpoint.domain.mso.dcapi.DCApiRequest
import id.walt.mdoc.dataretrieval.DeviceRequest
import kotlinx.serialization.*
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

object DCApiRequestSerializer : KSerializer<DCApiRequest> {
    private val serializer = DCApiRequestDelegate.serializer()

    override val descriptor: SerialDescriptor
        get() = serializer.descriptor

    override fun serialize(
        encoder: Encoder,
        value: DCApiRequest,
    ) {
        val delegate = DCApiRequestDelegate(value)
        encoder.encodeSerializableValue(serializer, delegate)
    }

    override fun deserialize(decoder: Decoder): DCApiRequest {
        val delegate = decoder.decodeSerializableValue(serializer)
        return DCApiRequest(delegate)
    }
}

@Serializable
private data class DCApiRequestDelegate(
    @Required @SerialName(Iso180137.DEVICE_REQUEST) val deviceRequest: String,
    @Required @SerialName(Iso180137.ENCRYPTION_INFO) val encryptionInfo: String,
) {
    constructor(value: DCApiRequest) : this(
        deviceRequest = base64UrlNoPadding.encode(cbor.encodeToByteArray(value.deviceRequest.toMapElement())),
        encryptionInfo = base64UrlNoPadding.encode(cbor.encodeToByteArray(value.encryptionInfo.toListElement())),
    )
}

private fun DCApiRequest(value: DCApiRequestDelegate): DCApiRequest {
    val deviceRequest =
        cbor.decodeFromByteArray<DeviceRequest>(
            base64UrlNoPadding.decode(value.deviceRequest),
        )
    val encryptionInfo =
        EncryptionInfo(
            cbor.decodeFromByteArray(
                base64UrlNoPadding.decode(value.encryptionInfo),
            ),
        )
    return DCApiRequest(deviceRequest, encryptionInfo)
}
