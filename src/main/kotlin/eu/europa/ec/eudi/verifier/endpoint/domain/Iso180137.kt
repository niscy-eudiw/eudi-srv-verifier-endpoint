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
package eu.europa.ec.eudi.verifier.endpoint.domain

/**
 * [Personal identification — ISO-compliant driving licence — Part 7: Mobile driving licence (mDL) add-on functions](https://github.com/ISOWG10/ISO-18013/blob/main/Working%20Documents/Working%20Draft%20WG%2010_N2544_18013-7%20second%20edition%20DTS%20candidate%20-%20NTC.pdf)
 */
object Iso180137 {
    const val DCAPI_PROTOCOL = "org.iso.mdoc"
    const val HANDOVER_IDENTIFIER = "dcapi"
    const val ENCRYPTION_PROTOCOL: String = "dcapi"

    //
    // DC-API Request
    //

    const val DEVICE_REQUEST: String = "deviceRequest"
    const val ENCRYPTION_INFO: String = "encryptionInfo"
    const val ENCRYPTION_INFO_LIST_SIZE: Int = 2
    const val ENCRYPTION_INFO_ENCRYPTION_PROTOCOL_INDEX: Int = 0
    const val ENCRYPTION_INFO_ENCRYPTION_PARAMETERS_INDEX: Int = 1

    //
    // Encryption Parameters
    //

    const val NONCE: String = "nonce"

    const val ENCRYPTION_PARAMETERS_NONCE_MINIMUM_SIZE: Int = 16

    const val RECIPIENT_PUBLIC_KEY: String = "recipientPublicKey"

    // KEM = DHKEM_P256
    const val ENCRYPTION_PARAMETERS_RECIPIENT_PUBLIC_KEY_CURVE: String = "P-256"

    //
    // DC Api Response
    //

    const val RESPONSE: String = "Response"

    //
    // Encrypted Response
    //

    const val ENCRYPTED_RESPONSE_LIST_SIZE: Int = 2
    const val ENCRYPTED_RESPONSE_ENCRYPTION_PROTOCOL_INDEX: Int = 0
    const val ENCRYPTED_RESPONSE_ENCRYPTED_DATA_INDEX: Int = 1
    const val ENCRYPTED_RESPONSE_DATA_ENC: String = "enc"
    const val ENCRYPTED_RESPONSE_DATA_CIPHER_TEXT: String = "cipherText"
}
