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

import COSE.AlgorithmID
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.Handover
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.HandoverInfo
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.SessionTranscript
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.toDataElement
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.toHandover
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.x509.dropRootCAIfPresent
import eu.europa.ec.eudi.verifier.endpoint.domain.AccessCertificate
import eu.europa.ec.eudi.verifier.endpoint.domain.Iso180135
import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation
import eu.europa.ec.eudi.verifier.endpoint.domain.PresentationType
import eu.europa.ec.eudi.verifier.endpoint.domain.VerifierConfig
import eu.europa.ec.eudi.verifier.endpoint.domain.VerifierId
import eu.europa.ec.eudi.verifier.endpoint.domain.mso.dcapi.DCApiRequest
import eu.europa.ec.eudi.verifier.endpoint.domain.mso.dcapi.EncryptionInfo
import eu.europa.ec.eudi.verifier.endpoint.domain.mso.dcapi.EncryptionParameters
import eu.europa.ec.eudi.verifier.endpoint.domain.mso.intentToRetainOrDefault
import eu.europa.ec.eudi.verifier.endpoint.port.out.mso.dcapi.CreateDCApiRequest
import id.walt.mdoc.COSECryptoProviderKeyInfo
import id.walt.mdoc.SimpleCOSECryptoProvider
import id.walt.mdoc.cose.COSECryptoProvider
import id.walt.mdoc.dataretrieval.DeviceRequest
import id.walt.mdoc.docrequest.MDocRequestBuilder

class CreateDCApiRequestWaltID(
    private val verifierId: VerifierId,
) : CreateDCApiRequest {
    init {
        val accessCertificate = verifierId.accessCertificate
        require(accessCertificate.key is ECKey) {
            "Cannot sign DeviceRequest with non EC Key AccessCertificate"
        }
        require(accessCertificate.key.curve.name in Iso180135.READER_AUTHENTICATION_KEY_PAIR_SUPPORTED_CURVES) {
            "AccessCertificate EC Key does not use a supported Curve: ${accessCertificate.key.curve.name}"
        }
    }

    override suspend fun invoke(presentation: Presentation.RequestObjectRetrieved): DCApiRequest {
        val presentationType = presentation.presentationType
        require(presentationType is PresentationType.ISO.OverDCApi)

        val documentRequests =
            presentationType.documentRequests.map { documentRequest ->
                MDocRequestBuilder(documentRequest.docType.value)
                    .apply {
                        documentRequest.dataElements.forEach { (nameSpace, dataElementRequests) ->
                            dataElementRequests.forEach { dataElementRequest ->
                                addDataElementRequest(
                                    nameSpace,
                                    dataElementRequest.identifier,
                                    dataElementRequest.intentToRetainOrDefault,
                                )
                            }
                        }
                    }.run {
                        val handoverInfo =
                            HandoverInfo.ISODCApiHandoverInfo(
                                presentation.nonce,
                                presentationType.responseMode.ephemeralResponseEncryptionKey.toPublicJWK(),
                                presentationType.origin,
                            )
                        val handover = handoverInfo.toHandover()
                        val sessionTranscript = SessionTranscript(null, null, handover)
                        val coseCryptoProvider = verifierId.accessCertificate.toCOSECryptoProvider(READER_AUTHENTICATION_KEY_ID)
                        sign(sessionTranscript.toDataElement(), coseCryptoProvider, READER_AUTHENTICATION_KEY_ID)
                    }
            }

        val encryptionInfo =
            EncryptionInfo(
                EncryptionParameters(
                    presentation.nonce,
                    presentationType.responseMode.ephemeralResponseEncryptionKey.toPublicJWK(),
                ),
            )

        return DCApiRequest(DeviceRequest(documentRequests), encryptionInfo)
    }

    companion object {
        private const val READER_AUTHENTICATION_KEY_ID = "reader_authentication"
    }
}

private fun AccessCertificate.toCOSECryptoProvider(keyId: String): COSECryptoProvider =
    SimpleCOSECryptoProvider(
        listOf(
            key.toECKey().toCOSECryptoProviderKeyInfo(keyId),
        ),
    )

private fun ECKey.toCOSECryptoProviderKeyInfo(keyId: String): COSECryptoProviderKeyInfo =
    COSECryptoProviderKeyInfo(
        keyId,
        algorithmId,
        toECPublicKey(),
        toECPrivateKey(),
        parsedX509CertChain.dropRootCAIfPresent(),
        emptyList(),
    )

private val ECKey.algorithmId: AlgorithmID
    get() =
        when (curve) {
            Curve.P_256 -> AlgorithmID.ECDSA_256
            Curve.P_384 -> AlgorithmID.ECDSA_384
            Curve.P_521 -> AlgorithmID.ECDSA_512
            else -> error("Unsupported ECKey Curve '${curve.name}'")
        }
