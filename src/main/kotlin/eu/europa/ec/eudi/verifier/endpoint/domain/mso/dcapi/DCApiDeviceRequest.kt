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
package eu.europa.ec.eudi.verifier.endpoint.domain.mso.dcapi

import com.nimbusds.jose.jwk.ECKey
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.dcapi.DCApiDeviceRequestSerializer
import eu.europa.ec.eudi.verifier.endpoint.domain.Iso180137
import eu.europa.ec.eudi.verifier.endpoint.domain.Nonce
import id.walt.mdoc.dataretrieval.DeviceRequest
import kotlinx.serialization.Serializable

@Serializable(with = DCApiDeviceRequestSerializer::class)
data class DCApiDeviceRequest(
    val deviceRequest: DeviceRequest,
    val encryptionInfo: EncryptionInfo,
)

data class EncryptionInfo(
    val encryptionParameters: EncryptionParameters,
)

data class EncryptionParameters(
    val nonce: Nonce,
    val recipientPublicKey: ECKey,
) {
    init {
        require(nonce.value.encodeToByteArray().size >= Iso180137.ENCRYPTION_PARAMETERS_NONCE_MINIMUM_SIZE) {
            "nonce must be at least ${Iso180137.ENCRYPTION_PARAMETERS_NONCE_MINIMUM_SIZE} bytes"
        }

        require(!recipientPublicKey.isPrivate) {
            "recipientPublicKey must be a public key"
        }
        require(recipientPublicKey.curve.name == Iso180137.ENCRYPTION_PARAMETERS_RECIPIENT_PUBLIC_KEY_CURVE) {
            "recipientPublicKey must use curve ${Iso180137.ENCRYPTION_PARAMETERS_RECIPIENT_PUBLIC_KEY_CURVE}"
        }
    }
}
