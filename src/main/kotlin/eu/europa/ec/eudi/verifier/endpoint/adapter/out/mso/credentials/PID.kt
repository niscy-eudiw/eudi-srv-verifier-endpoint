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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.credentials

import id.walt.mdoc.credsdata.MdocCompanion
import id.walt.mdoc.objects.MdocsCborSerializer
import kotlinx.datetime.LocalDate
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.cbor.ByteString

/**
 * Data class for PID according to PID Rulebook v1.5.
 *
 * Companion object implements [id.walt.mdoc.credsdata.MdocCompanion] and registers the necessary serializers, so that MSO MDoc encoded PIDs can be successfully
 * parsed and validated.
 *
 * **Before parsing/validating a PID, make sure to call [registerSerializationTypes].**
 * @see [eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.DeviceResponseValidator]
 * @see [eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.DocumentValidator]
 */
@Serializable
@SerialName("PID-v1.5")
data class PID(
    @Required @SerialName("family_name") val familyName: String,
    @Required @SerialName("given_name")val givenName: String,
    @Required @SerialName("birth_date") val birthDate: LocalDate,
    @Required @SerialName("place_of_birth") val placeOfBirth: BirthPlace,
    @Required @SerialName("nationality") val nationality: List<String>,
    @SerialName("resident_address") val residentAddress: String? = null,
    @SerialName("resident_country") val residentCountry: String? = null,
    @SerialName("resident_state") val residentState: String? = null,
    @SerialName("resident_city") val residentCity: String? = null,
    @SerialName("resident_postal_code") val residentPostalCode: String? = null,
    @SerialName("resident_street") val residentStreet: String? = null,
    @SerialName("resident_house_number") val residentHouseNumber: String? = null,
    @SerialName("personal_administrative_number") val personalAdministrativeNumber: String? = null,
    @SerialName("portrait") @ByteString val portrait: ByteArray? = null,
    @SerialName("family_name_birth") val birthFamilyName: String? = null,
    @SerialName("given_name_birth") val birthGivenName: String? = null,
    @SerialName("sex") val sex: UInt? = null,
    @SerialName("email_address") val emailAddress: UInt? = null,
    @SerialName("mobile_phone_number") val mobilePhoneNumber: String? = null,
    @Required @SerialName("expiry_date") val expiryDate: LocalDate,
    @Required @SerialName("issuing_authority") val issuingAuthority: String,
    @Required @SerialName("issuing_country") val issuingCountry: String,
    @SerialName("document_number") val documentNumber: String? = null,
    @SerialName("issuing_jurisdiction") val issuingJurisdiction: String? = null,
    @SerialName("issuance_date") val issuanceDate: LocalDate? = null,
    @SerialName("trust_anchor") val trustAnchor: String? = null,
    @SerialName("attestation_legal_category") val attestationLegalCategory: String? = null,
) {
    companion object : MdocCompanion {
        override fun registerSerializationTypes() {
            MdocsCborSerializer.register(
                mapOf(
                    "birth_date" to LocalDate.Companion.serializer(),
                    "place_of_birth" to BirthPlace.serializer(),
                    "nationality" to ListSerializer(String.Companion.serializer()),
                    "expiry_date" to LocalDate.Companion.serializer(),
                    "issuance_date" to LocalDate.Companion.serializer(),
                ),
                "eu.europa.ec.eudi.pid.1",
            )
        }
    }

    @Serializable
    data class BirthPlace(
        @SerialName("country") val country: String? = null,
        @SerialName("region") val region: String? = null,
        @SerialName("locality") val locality: String? = null,
    ) {
        init {
            require(null != country || null != region || null != locality)
        }
    }
}
