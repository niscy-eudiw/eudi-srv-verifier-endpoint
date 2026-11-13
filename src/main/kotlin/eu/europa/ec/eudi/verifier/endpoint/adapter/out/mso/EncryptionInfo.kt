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

import COSE.OneKey
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.upokecenter.cbor.CBORObject
import eu.europa.ec.eudi.verifier.endpoint.domain.Iso180137
import eu.europa.ec.eudi.verifier.endpoint.domain.Nonce
import eu.europa.ec.eudi.verifier.endpoint.domain.mso.dcapi.EncryptionInfo
import eu.europa.ec.eudi.verifier.endpoint.domain.mso.dcapi.EncryptionParameters
import id.walt.mdoc.dataelement.ByteStringElement
import id.walt.mdoc.dataelement.DataElement
import id.walt.mdoc.dataelement.ListElement
import id.walt.mdoc.dataelement.MapElement
import id.walt.mdoc.dataelement.MapKey
import id.walt.mdoc.dataelement.toDataElement
import kotlinx.serialization.encodeToByteArray
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey

fun EncryptionInfo.toListElement(): ListElement =
    listOf(
        Iso180137.ENCRYPTION_PROTOCOL.toDataElement(),
        encryptionParameters.toMapElement(),
    ).toDataElement()

private fun EncryptionParameters.toMapElement(): MapElement =
    mapOf(
        MapKey(Iso180137.NONCE) to nonce.toByteStringElement(),
        MapKey(Iso180137.RECIPIENT_PUBLIC_KEY) to recipientPublicKey.toMapElement(),
    ).toDataElement()

private fun Nonce.toByteStringElement(): ByteStringElement = value.encodeToByteArray().toDataElement()

private fun ECKey.toMapElement(): MapElement = DataElement.fromCBOR(toOneKey().EncodeToBytes())

private fun ECKey.toOneKey(): OneKey = OneKey(toECPublicKey(), toECPrivateKey())

fun EncryptionInfo(value: ListElement): EncryptionInfo {
    require(Iso180137.ENCRYPTION_INFO_LIST_SIZE == value.value.size) {
        "${Iso180137.ENCRYPTION_INFO} must be a list that contains exactly ${Iso180137.ENCRYPTION_INFO_LIST_SIZE} data elements"
    }

    val encryptionProtocol = value.value[Iso180137.ENCRYPTION_INFO_ENCRYPTION_PROTOCOL_INDEX]
    require(Iso180137.ENCRYPTION_PROTOCOL.toDataElement() == encryptionProtocol) {
        "Unexpected encryption protocol: $encryptionProtocol"
    }

    val encryptionParameters = value.value[Iso180137.ENCRYPTION_INFO_ENCRYPTION_PARAMETERS_INDEX]
    require(encryptionParameters is MapElement) {
        "Unexpected structure for encryption parameters: ${encryptionParameters::class.qualifiedName}"
    }

    return EncryptionInfo(EncryptionParameters(encryptionParameters))
}

private fun EncryptionParameters(value: MapElement): EncryptionParameters {
    val expectedKeys = setOf(MapKey(Iso180137.NONCE), MapKey(Iso180137.RECIPIENT_PUBLIC_KEY))
    require(expectedKeys == value.value.keys) {
        "value contains unexpected keys: ${value.value.keys}"
    }

    val nonce =
        run {
            val value = value.value[MapKey(Iso180137.NONCE)]

            require(value is ByteStringElement) {
                "${Iso180137.NONCE} is not a ByteStringElement"
            }
            Nonce(value.value.decodeToString())
        }

    val recipientPublicKey =
        run {
            val value = value.value[MapKey(Iso180137.RECIPIENT_PUBLIC_KEY)]
            require(value is MapElement) {
                "${Iso180137.RECIPIENT_PUBLIC_KEY} is not a MapElement"
            }
            OneKey(value).toECKey()
        }

    return EncryptionParameters(nonce, recipientPublicKey)
}

private fun OneKey(value: MapElement): OneKey = OneKey(CBORObject.DecodeFromBytes(cbor.encodeToByteArray(value)))

private fun OneKey.toECKey(): ECKey {
    val publicKey = AsPublicKey()
    require(publicKey is ECPublicKey) { "Not an EC Public Key" }

    val privateKey = AsPrivateKey()
    require(null == privateKey || privateKey is ECPrivateKey) { "Not an EC Private Key" }

    return ECKey
        .Builder(Curve.forECParameterSpec(publicKey.params), publicKey)
        .privateKey(privateKey)
        .build()
}
