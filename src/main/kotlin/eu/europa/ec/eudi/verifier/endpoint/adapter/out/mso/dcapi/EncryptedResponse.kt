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

import eu.europa.ec.eudi.verifier.endpoint.domain.Iso180137
import eu.europa.ec.eudi.verifier.endpoint.domain.mso.dcapi.EncryptedResponse
import eu.europa.ec.eudi.verifier.endpoint.domain.mso.dcapi.EncryptedResponseData
import id.walt.mdoc.dataelement.ByteStringElement
import id.walt.mdoc.dataelement.ListElement
import id.walt.mdoc.dataelement.MapElement
import id.walt.mdoc.dataelement.MapKey
import id.walt.mdoc.dataelement.toDataElement

fun EncryptedResponse.toListElement(): ListElement =
    listOf(
        Iso180137.ENCRYPTION_PROTOCOL.toDataElement(),
        encryptedResponseData.toMapElement(),
    ).toDataElement()

private fun EncryptedResponseData.toMapElement(): MapElement =
    mapOf(
        MapKey(Iso180137.ENCRYPTED_RESPONSE_DATA_ENC) to enc.toDataElement(),
        MapKey(Iso180137.ENCRYPTED_RESPONSE_DATA_CIPHER_TEXT) to cipherText.toDataElement(),
    ).toDataElement()

fun EncryptedResponse(value: ListElement): EncryptedResponse {
    require(Iso180137.ENCRYPTED_RESPONSE_LIST_SIZE == value.value.size) {
        "EncryptedResponse must be a list that contains exactly ${Iso180137.ENCRYPTED_RESPONSE_LIST_SIZE} data elements"
    }

    val encryptionProtocol = value.value[Iso180137.ENCRYPTED_RESPONSE_ENCRYPTION_PROTOCOL_INDEX]
    require(Iso180137.ENCRYPTION_PROTOCOL.toDataElement() == encryptionProtocol) {
        "Unexpected encryption protocol: $encryptionProtocol"
    }

    val encryptedResponseData = value.value[Iso180137.ENCRYPTED_RESPONSE_ENCRYPTED_DATA_INDEX]
    require(encryptedResponseData is MapElement) {
        "Unexpected structure for encrypted response data: ${encryptedResponseData::class.qualifiedName}"
    }

    return EncryptedResponse(EncryptedResponseData(encryptedResponseData))
}

private fun EncryptedResponseData(value: MapElement): EncryptedResponseData {
    val expectedKeys = setOf(MapKey(Iso180137.ENCRYPTED_RESPONSE_DATA_ENC), MapKey(Iso180137.ENCRYPTED_RESPONSE_DATA_CIPHER_TEXT))
    require(expectedKeys == value.value.keys) {
        "value contains unexpected keys: ${value.value.keys}"
    }

    val enc =
        run {
            val enc = value.value[MapKey(Iso180137.ENCRYPTED_RESPONSE_DATA_ENC)]
            require(enc is ByteStringElement) {
                "${Iso180137.ENCRYPTED_RESPONSE_DATA_ENC} must be a ByteStringElement"
            }
            enc.value
        }

    val cipherText =
        run {
            val cipherText = value.value[MapKey(Iso180137.ENCRYPTED_RESPONSE_DATA_CIPHER_TEXT)]
            require(cipherText is ByteStringElement) {
                "${Iso180137.ENCRYPTED_RESPONSE_DATA_CIPHER_TEXT} must be a ByteStringElement"
            }
            cipherText.value
        }

    return EncryptedResponseData(enc = enc, cipherText = cipherText)
}
