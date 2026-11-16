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

import arrow.core.raise.catch
import arrow.core.raise.context.raise
import com.nimbusds.jose.jwk.ECKey
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.*
import eu.europa.ec.eudi.verifier.endpoint.domain.PresentationType
import eu.europa.ec.eudi.verifier.endpoint.port.input.WalletResponseValidationError
import eu.europa.ec.eudi.verifier.endpoint.port.out.mso.dcapi.DecryptDeviceResponse
import kotlinx.serialization.encodeToByteArray
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.ec.CustomNamedCurves
import org.bouncycastle.crypto.hpke.HPKE
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters

val DecryptDeviceResponseBouncyCastle: DecryptDeviceResponse =
    DecryptDeviceResponse { presentation, encryptedResponse ->
        catch({
            val presentationType = presentation.presentationType
            check(presentationType is PresentationType.ISO.OverDCApi) {
                "Applicable only to ISO Presentations over DC Api"
            }

            val hpke =
                HPKE(
                    HPKE.mode_base, // Mode = Base
                    HPKE.kem_P256_SHA256, // KEM = DHKEM_P256
                    HPKE.kdf_HKDF_SHA256, // KDF = HKDF_SHA256
                    HPKE.aead_AES_GCM128, // AEAD = AES_128_GCM
                )

            val enc = encryptedResponse.encryptedResponseData.enc // enc = the enc value received from the response structure
            val ct = encryptedResponse.encryptedResponseData.cipherText // ct = the cipherText value from the response structure
            val skR =
                presentationType.responseMode
                    .ephemeralResponseEncryptionKey
                    .toAsymmetricCipherKeyPair() // skR = the reader private key
            val info =
                run {
                    val handoverInfo =
                        HandoverInfo.ISODCApiHandoverInfo(
                            presentation.nonce,
                            presentationType.responseMode.ephemeralResponseEncryptionKey.toPublicJWK(),
                            presentationType.origin,
                        )
                    val handover = handoverInfo.toHandover()
                    val sessionTranscript = SessionTranscript(null, null, handover)
                    cbor.encodeToByteArray(sessionTranscript.toDataElement())
                } // info = cbor encoded SessionTranscript as defined below
            val aad = ByteArray(0) // aad = this is an empty field

            hpke.open(enc, skR, info, aad, ct, null, null, null)
        }) {
            raise(WalletResponseValidationError.DeviceResponseCannotBeDecrypted(it))
        }
    }

private fun ECKey.toAsymmetricCipherKeyPair(): AsymmetricCipherKeyPair {
    val parameters = ECDomainParameters(CustomNamedCurves.getByName(curve.name))
    val x = x.decodeToBigInteger()
    val y = y.decodeToBigInteger()
    val q = parameters.curve.createPoint(x, y)

    val publicParams = ECPublicKeyParameters(q, parameters)
    val privateParams =
        if (isPrivate) {
            val d = d.decodeToBigInteger()
            ECPrivateKeyParameters(d, parameters)
        } else {
            null
        }

    return AsymmetricCipherKeyPair(publicParams, privateParams)
}
