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

import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.dcapi.EncryptedResponseSerializer
import kotlinx.serialization.Serializable

@Serializable(with = EncryptedResponseSerializer::class)
data class EncryptedResponse(
    val encryptedResponseData: EncryptedResponseData,
)

data class EncryptedResponseData(
    val enc: ByteArray,
    val cipherText: ByteArray,
) {
    override fun equals(other: Any?): Boolean =
        other is EncryptedResponseData &&
            other.enc.contentEquals(enc) &&
            other.cipherText.contentEquals(cipherText)

    override fun hashCode(): Int = (31 * enc.contentHashCode()) + cipherText.contentHashCode()
}
