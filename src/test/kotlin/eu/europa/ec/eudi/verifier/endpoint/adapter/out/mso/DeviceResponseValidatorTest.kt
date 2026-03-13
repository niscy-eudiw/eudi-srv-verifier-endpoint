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

import arrow.core.NonEmptyList
import arrow.core.getOrElse
import arrow.core.nonEmptyListOf
import com.nimbusds.jose.util.X509CertUtils
import eu.europa.ec.eudi.etsi1196x2.consultation.IsChainTrustedForAttestation
import eu.europa.ec.eudi.etsi1196x2.consultation.IsChainTrustedForContextF
import eu.europa.ec.eudi.etsi1196x2.consultation.VerificationContext
import eu.europa.ec.eudi.verifier.endpoint.TestContext
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.consultation.Ignored
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.consultation.usingTrustAnchors
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.jsonSupport
import eu.europa.ec.eudi.verifier.endpoint.domain.AttestationClassifications
import eu.europa.ec.eudi.verifier.endpoint.domain.Clock
import eu.europa.ec.eudi.verifier.endpoint.domain.Nonce
import eu.europa.ec.eudi.verifier.endpoint.domain.VerifierId
import eu.europa.ec.eudi.verifier.endpoint.domain.toJavaDate
import eu.europa.ec.eudi.verifier.endpoint.toConsultationAttestationClassifications
import kotlinx.coroutines.test.runTest
import kotlinx.datetime.LocalDateTime
import kotlinx.datetime.toInstant
import org.junit.jupiter.api.Nested
import org.slf4j.LoggerFactory
import java.net.URL
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import kotlin.test.*
import eu.europa.ec.eudi.etsi1196x2.consultation.AttestationClassifications as ConsultationAttestationClassifications

private object Data {

    /**
     * Contains three documents,
     *
     * The first and the second are valid
     * The 3d has expired validity info
     */
    val ThreeDocumentVP = Data::class.java.getResource("/deviceresponsevalidator/ThreeDocumentDeviceResponse.txt")!!.readText()

    /**
     * An mDL
     */
    val MdlVP = Data::class.java.getResource("/deviceresponsevalidator/mDL-deviceresponse.txt")!!.readText()

    /**
     * An mDL with Key Authorizations and Device Signed Items
     */
    val VPWithDeviceSignedItems = Data::class.java.getResource(
        "/deviceresponsevalidator/vp-withauthorizationdevicedsigned.txt",
    )!!.readText()

    /**
     * An mDL with Unauthorized Device Signed Items
     */
    val VPWithUnauthorizedDeviceSignedItems = Data::class.java.getResource(
        "/deviceresponsevalidator/vp-withunauthorizaeddevicesigned.txt",
    )!!.readText()

    // Trust anchors for ThreeDocumentVP and MdlVP
    val firstIssuer =
        nonEmptyListOf(
            X509CertUtils.parse(
                Data::class.java.getResource("/deviceresponsevalidator/pid-issuer.local.pem")!!.readText(),
            ),
        )

    val secondIssuer =
        nonEmptyListOf(
            X509CertUtils.parse(
                Data::class.java.getResource("/deviceresponsevalidator/dev.issuer-backend.eudiw.dev.pem")!!.readText(),
            ),
        )

    val attestationClassifications = jsonSupport.decodeFromString<AttestationClassifications>(
        Data::class.java.getResource("/deviceresponsevalidator/attestationclassifications.json")!!.readText(),
    ).toConsultationAttestationClassifications()

    val attestationsToValidate =
        nonEmptyListOf(
            "/deviceresponsevalidator/kotlin-issuer-pid.txt",
            "/deviceresponsevalidator/kotlin-issuer-mdl.txt",
        )
}

private val log = LoggerFactory.getLogger(DeviceResponseValidatorTest::class.java)

class DeviceResponseValidatorTest {

    private val clock = run {
        val testDate = LocalDateTime(2026, 1, 22, 0, 0, 0, 0)
        Clock.fixed(
            testDate.toInstant(kotlinx.datetime.TimeZone.of("Europe/Athens")),
            kotlinx.datetime.TimeZone.of("Europe/Athens"),
        )
    }

    @Test
    fun `a vp_token where the 3d document has an invalid validity info should fail`() = runTest {
        val invalidDocument = run {
            val isChainTrusted = IsChainTrustedForContextF.usingTrustAnchors(Data.firstIssuer) {
                isRevocationEnabled = false
                date = clock.now().toJavaDate()
            }
            val validator = deviceResponseValidator(isChainTrusted, ValidityInfoShouldBe.NotExpired, Data.attestationClassifications, clock)
            val validated = validator.ensureValid(Data.ThreeDocumentVP)
            val invalidDocuments =
                assertIs<DeviceResponseError.InvalidDocuments>(validated.leftOrNull())
                    .invalidDocuments
            assertEquals(1, invalidDocuments.size)
            invalidDocuments.head
        }

        assertEquals(2, invalidDocument.index)
        val documentError = run {
            assertEquals(1, invalidDocument.errors.size)
            invalidDocument.errors.head
        }
        assertIs<DocumentError.ExpiredValidityInfo>(documentError)
    }

    @Test
    fun `a vp_token where the 3d document has an invalid validity info should not fail when skip`() = runTest {
        val validDocuments = run {
            val isChainTrusted = IsChainTrustedForContextF.usingTrustAnchors(Data.firstIssuer) {
                isRevocationEnabled = false
                date = clock.now().toJavaDate()
            }
            val validator = deviceResponseValidator(isChainTrusted, ValidityInfoShouldBe.Ignored, Data.attestationClassifications, clock)
            val validated = validator.ensureValid(Data.ThreeDocumentVP)
            assertNotNull(validated.getOrNull())
        }

        assertEquals(3, validDocuments.size)
    }

    @Test
    fun `a vp_token having a single document with invalid chain should fail`() = runTest {
        val invalidDocument = run {
            val isChainTrusted = IsChainTrustedForContextF.usingTrustAnchors(Data.secondIssuer) {
                isRevocationEnabled = false
                date = clock.now().toJavaDate()
            }
            val validator = deviceResponseValidator(isChainTrusted, ValidityInfoShouldBe.NotExpired, Data.attestationClassifications, clock)
            val validated = validator.ensureValid(Data.MdlVP)
            val invalidDocuments = assertIs<DeviceResponseError.InvalidDocuments>(validated.leftOrNull()).invalidDocuments
            assertEquals(1, invalidDocuments.size)
            invalidDocuments.head
        }
        assertEquals(0, invalidDocument.index)
        val documentError = run {
            assertEquals(1, invalidDocument.errors.size)
            invalidDocument.errors.head
        }
        assertIs<DocumentError.X5CNotTrusted>(documentError)
    }

    @Test
    fun `a vp_token having a single document skipping chain validation should be valid`() = runTest {
        val validDocuments = run {
            val validator =
                deviceResponseValidator(
                    IsChainTrustedForContextF.Ignored,
                    ValidityInfoShouldBe.NotExpired,
                    Data.attestationClassifications,
                    clock,
                )
            val validated = validator.ensureValid(Data.MdlVP)
            assertNotNull(validated.getOrNull())
        }

        assertEquals(1, validDocuments.size)
    }

    @Test
    fun `ensure all mso mdoc attestations issued by kotlin and python issuer can be validated`() = runTest {
        val validator =
            deviceResponseValidator(
                IsChainTrustedForContextF.Ignored,
                ValidityInfoShouldBe.Ignored,
                Data.attestationClassifications,
                Clock.System,
            )
        Data.attestationsToValidate.forEach {
            log.info("Checking $it")
            val vpToken = Data::class.java.getResource(it)!!.readText()
            val validated = validator.ensureValid(vpToken)
            val documents = validated.getOrElse { error -> fail("Failed to validated $it, error: $error") }
            assertEquals(1, documents.size)
        }
    }

    @Nested
    inner class KeyAuthorizationTest {

        @Test
        fun `device signed items in an authorized namespace are accepted`() = runTest {
            val validDocuments = run {
                val vpValidator =
                    deviceResponseValidator(
                        IsChainTrustedForContextF.Ignored,
                        ValidityInfoShouldBe.NotExpired,
                        Data.attestationClassifications,
                        clock,
                    )
                val handoverInfo = deviceSignedHandoverInfo()

                val validated = vpValidator.ensureValid(Data.VPWithDeviceSignedItems, handoverInfo = handoverInfo)
                validated.getOrElse { error -> error("Validation failed: $error") }
            }

            assertEquals(1, validDocuments.size)
        }

        @Test
        fun `device signed items in an unauthorized namespace should fail`() = runTest {
            val invalidDocument = run {
                val vpValidator =
                    deviceResponseValidator(
                        IsChainTrustedForContextF.Ignored,
                        ValidityInfoShouldBe.NotExpired,
                        Data.attestationClassifications,
                        clock,
                    )
                val handoverInfo = deviceSignedHandoverInfo()

                val validated = vpValidator.ensureValid(Data.VPWithUnauthorizedDeviceSignedItems, handoverInfo = handoverInfo)
                val invalidDocuments =
                    assertIs<DeviceResponseError.InvalidDocuments>(validated.leftOrNull()).invalidDocuments
                assertEquals(1, invalidDocuments.size)
                invalidDocuments.head
            }

            assertEquals(0, invalidDocument.index)
            val documentError = run {
                assertEquals(1, invalidDocument.errors.size)
                invalidDocument.errors.head
            }
            assertIs<DocumentError.DeviceKeyNotAuthorizedToSignItems>(documentError)
        }

        private fun deviceSignedHandoverInfo(): HandoverInfo {
            val verifierId = VerifierId.PreRegistered(
                originalClientId = "client_id",
                accessCertificate = TestContext.verifierId.accessCertificate,
            )

            return HandoverInfo.OpenID4VPHandoverInfo(
                clientId = verifierId,
                nonce = Nonce("nonce"),
                ephemeralEncryptionKey = null,
                responseUri = URL("https://example.com/direct_post"),
            )
        }
    }
}

private fun deviceResponseValidator(
    isChainTrusted: IsChainTrustedForContextF<NonEmptyList<X509Certificate>, VerificationContext, TrustAnchor>,
    validityInfo: ValidityInfoShouldBe,
    attestationClassifications: ConsultationAttestationClassifications,
    clock: Clock,
): DeviceResponseValidator {
    val documentValidator = DocumentValidator(
        clock,
        validityInfo,
        IssuerSignedItemsShouldBe.Verified,
        isChainTrustedForAttestation = IsChainTrustedForAttestation(isChainTrusted, attestationClassifications),
        statusListTokenValidator = null,
    )
    return DeviceResponseValidator(documentValidator)
}
