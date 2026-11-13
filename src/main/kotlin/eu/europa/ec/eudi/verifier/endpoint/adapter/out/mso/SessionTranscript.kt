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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso

import com.eygraber.uri.toURI
import eu.europa.ec.eudi.verifier.endpoint.domain.Iso180137
import eu.europa.ec.eudi.verifier.endpoint.domain.OpenId4VPSpec
import eu.europa.ec.eudi.verifier.endpoint.domain.mso.dcapi.EncryptionInfo
import eu.europa.ec.eudi.verifier.endpoint.domain.mso.dcapi.EncryptionParameters
import id.walt.mdoc.dataelement.EncodedCBORElement
import id.walt.mdoc.dataelement.ListElement
import id.walt.mdoc.dataelement.NullElement
import id.walt.mdoc.dataelement.toDataElement
import kotlinx.serialization.encodeToByteArray
import java.security.MessageDigest

data class SessionTranscript(
    val deviceEngagementBytes: ByteArray?,
    val eReaderKeyBytes: ByteArray?,
    val handover: Handover,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as SessionTranscript

        if (!deviceEngagementBytes.contentEquals(other.deviceEngagementBytes)) return false
        if (!eReaderKeyBytes.contentEquals(other.eReaderKeyBytes)) return false
        if (handover != other.handover) return false

        return true
    }

    override fun hashCode(): Int {
        var result = deviceEngagementBytes.contentHashCode()
        result = 31 * result + eReaderKeyBytes.contentHashCode()
        result = 31 * result + handover.hashCode()
        return result
    }
}

fun SessionTranscript.toDataElement(): ListElement =
    listOf(
        deviceEngagementBytes?.let { EncodedCBORElement(it) } ?: NullElement(),
        eReaderKeyBytes?.let { EncodedCBORElement(it) } ?: NullElement(),
        handover.toDataElement(),
    ).toDataElement()

data class Handover(
    val identifier: String,
    val handoverInfoHash: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Handover

        if (identifier != other.identifier) return false
        if (!handoverInfoHash.contentEquals(other.handoverInfoHash)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = identifier.hashCode()
        result = 31 * result + handoverInfoHash.contentHashCode()
        return result
    }
}

private fun Handover.toDataElement(): ListElement = listOf(identifier.toDataElement(), handoverInfoHash.toDataElement()).toDataElement()

fun HandoverInfo.toHandover(
    sha256: (ByteArray) -> ByteArray = {
        MessageDigest.getInstance("SHA-256").digest(it)
    },
): Handover {
    val (identifier, handoverInfoBytes) =
        when (this) {
            is HandoverInfo.OpenID4VPHandoverInfo -> {
                val element =
                    listOf(
                        clientId.clientId.toDataElement(),
                        nonce.value.toDataElement(),
                        ephemeralEncryptionKey?.computeThumbprint()?.decode()?.toDataElement() ?: NullElement(),
                        responseUri.toExternalForm().toDataElement(),
                    ).toDataElement()
                OpenId4VPSpec.OPENID4VP_HANDOVER_IDENTIFIER to cbor.encodeToByteArray(element)
            }

            is HandoverInfo.OpenID4VPDCAPIHandoverInfo -> {
                val element =
                    listOf(
                        origin.toString().toDataElement(),
                        nonce.value.toDataElement(),
                        ephemeralEncryptionKey?.computeThumbprint()?.decode()?.toDataElement() ?: NullElement(),
                    )
                OpenId4VPSpec.OPENID4VP_DCAPI_HANDOVER_IDENTIFIER to cbor.encodeToByteArray(element)
            }

            is HandoverInfo.ISODCApiHandoverInfo -> {
                val encryptionInfo =
                    EncryptionInfo(
                        EncryptionParameters(
                            nonce,
                            ephemeralEncryptionKey,
                        ),
                    )
                val base64EncryptionInfo = base64UrlNoPadding.encode(cbor.encodeToByteArray(encryptionInfo.toListElement()))
                val dcApiInfo =
                    listOf(
                        base64EncryptionInfo.toDataElement(),
                        origin.toURI().toASCIIString().toDataElement(),
                    ).toDataElement()
                Iso180137.HANDOVER_IDENTIFIER to cbor.encodeToByteArray(dcApiInfo)
            }
        }

    val handoverInfoHash = sha256(handoverInfoBytes)
    return Handover(identifier, handoverInfoHash)
}
