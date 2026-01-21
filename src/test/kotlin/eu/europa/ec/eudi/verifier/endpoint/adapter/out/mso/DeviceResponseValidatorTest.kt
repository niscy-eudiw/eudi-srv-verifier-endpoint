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
import arrow.core.nonEmptyListOf
import com.nimbusds.jose.util.X509CertUtils
import eu.europa.ec.eudi.etsi1196x2.consultation.AttestationClassifications
import eu.europa.ec.eudi.etsi1196x2.consultation.AttestationIdentifierPredicate
import eu.europa.ec.eudi.etsi1196x2.consultation.IsChainTrustedForAttestation
import eu.europa.ec.eudi.etsi1196x2.consultation.IsChainTrustedForContextF
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.consultation.Ignored
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.consultation.usingTrustAnchors
import eu.europa.ec.eudi.verifier.endpoint.domain.Clock
import eu.europa.ec.eudi.verifier.endpoint.domain.toJavaDate
import kotlinx.coroutines.test.runTest
import kotlinx.datetime.LocalDateTime
import kotlinx.datetime.toInstant
import java.security.cert.X509Certificate
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull

private object Data {

    /**
     * Contains three documents,
     *
     * The first and the second are valid
     * The 3d has expired validity info
     */
    val ThreeDocumentVP = Data::class.java.getResource("/ThreeDocumentDeviceResponse.txt")!!.readText()

    /**
     * An mDL
     */
    val MdlVP = Data::class.java.getResource("/mDL-deviceresponse.txt")!!.readText()

    // Trust anchors for ThreeDocumentVP and MdlVP
    val firstIssuer: NonEmptyList<X509Certificate> by lazy {
        nonEmptyListOf(
            X509CertUtils.parse(Data::class.java.getResource("/pid-issuer.local.pem")!!.readText()),
        )
    }

    val secondIssuer: NonEmptyList<X509Certificate> by lazy {
        nonEmptyListOf(
            X509CertUtils.parse(Data::class.java.getResource("/dev.issuer-backend.eudiw.dev.pem")!!.readText()),
        )
    }
}

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
            val validator = deviceResponseValidator(Data.firstIssuer, clock)
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
            val docV = DocumentValidator(
                clock = clock,
                validityInfoShouldBe = ValidityInfoShouldBe.Ignored,
                isChainTrustedForAttestation = IsChainTrustedForAttestation(
                    IsChainTrustedForContextF.usingTrustAnchors(Data.firstIssuer) {
                        isRevocationEnabled = false
                        date = clock.now().toJavaDate()
                    },
                    AttestationClassifications(
                        pids = AttestationIdentifierPredicate.mdocMatching("^eu\\.europa\\.ec\\.eudi\\.pid\\.1$".toRegex()),
                        eaAs = mapOf(
                            "mDL" to AttestationIdentifierPredicate.mdocMatching("^org\\.iso\\.18013\\.5\\.1\\.mDL$".toRegex()),
                        ),
                    ),
                ),
                statusListTokenValidator = null,
            )
            val vpValidator = DeviceResponseValidator(docV)
            val validated = vpValidator.ensureValid(Data.ThreeDocumentVP)
            assertNotNull(validated.getOrNull())
        }

        assertEquals(3, validDocuments.size)
    }

    @Test
    fun `a vp_token having a single document with invalid chain should fail`() = runTest {
        val invalidDocument = run {
            val validated = deviceResponseValidator(Data.secondIssuer, clock).ensureValid(Data.MdlVP)
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
            val docV =
                DocumentValidator(
                    isChainTrustedForAttestation = IsChainTrustedForAttestation(
                        IsChainTrustedForContextF.Ignored,
                        AttestationClassifications(
                            pids = AttestationIdentifierPredicate.mdocMatching("^eu\\.europa\\.ec\\.eudi\\.pid\\.1$".toRegex()),
                            eaAs = mapOf(
                                "mDL" to AttestationIdentifierPredicate.mdocMatching("^org\\.iso\\.18013\\.5\\.1\\.mDL$".toRegex()),
                            ),
                        ),
                    ),
                    clock = clock,
                    statusListTokenValidator = null,
                )
            val vpValidator = DeviceResponseValidator(docV)
            val validated = vpValidator.ensureValid(Data.MdlVP)
            assertNotNull(validated.getOrNull())
        }

        assertEquals(1, validDocuments.size)
    }
}

private fun deviceResponseValidator(caCerts: NonEmptyList<X509Certificate>, clock: Clock): DeviceResponseValidator {
    val documentValidator = DocumentValidator(
        clock,
        ValidityInfoShouldBe.NotExpired,
        IssuerSignedItemsShouldBe.Verified,
        isChainTrustedForAttestation = IsChainTrustedForAttestation(
            IsChainTrustedForContextF.usingTrustAnchors(caCerts) {
                isRevocationEnabled = false
                date = clock.now().toJavaDate()
            },
            AttestationClassifications(
                pids = AttestationIdentifierPredicate.mdocMatching("^eu\\.europa\\.ec\\.eudi\\.pid\\.1$".toRegex()),
                eaAs = mapOf(
                    "mDL" to AttestationIdentifierPredicate.mdocMatching("^org\\.iso\\.18013\\.5\\.1\\.mDL$".toRegex()),
                ),
            ),
        ),
        statusListTokenValidator = null,
    )
    return DeviceResponseValidator(documentValidator)
}
