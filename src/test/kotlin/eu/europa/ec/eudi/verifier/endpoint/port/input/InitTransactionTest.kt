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
@file:Suppress("invisible_reference", "invisible_member")

package eu.europa.ec.eudi.verifier.endpoint.port.input

import arrow.core.getOrElse
import arrow.core.left
import arrow.core.raise.either
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.verifier.endpoint.TestContext
import eu.europa.ec.eudi.verifier.endpoint.adapter.input.web.TestUtils
import eu.europa.ec.eudi.verifier.endpoint.adapter.input.web.VerifierApiClient
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.encoding.base64UrlNoPadding
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.CreateQueryWalletResponseRedirectUri
import kotlinx.coroutines.test.runTest
import kotlinx.io.bytestring.decodeToByteString
import kotlinx.io.bytestring.decodeToString
import kotlinx.serialization.json.*
import java.net.URI
import kotlin.test.*
import kotlin.time.Duration.Companion.days

class InitTransactionTest {
    private val testTransactionId = TestContext.testTransactionId

    private val uri = URI.create("https://foo").toURL()
    private val verifierConfig =
        VerifierConfig(
            verifierId = TestContext.verifierId,
            requestJarOption = EmbedOption.ByValue,
            responseUriBuilder = { _ -> uri },
            defaultHttpResponseModeOption = HttpResponseModeOption.DirectPostJwt,
            maxAge = 3.days,
            clientMetaData = TestContext.clientMetaData,
            transactionDataHashAlgorithm = HashAlgorithm.SHA_256,
            requestUriMethod = RequestUriMethod.Get,
            authorizationRequestUri = UnresolvedAuthorizationRequestUri.fromUri("haip-vp://").getOrThrow(),
            intendedUses =
                listOf(
                    IntendedUse.create(
                        description = "test",
                        registrationCertificate = TestUtils.loadResource("wrprc.jwt"),
                        id = "1",
                    ),
                ),
        )

    @Test
    fun `when request option is embed by value, request should be present and presentation should be RequestObjectRetrieved`() =
        runTest {
            val input =
                InitOpenId4VPOverRedirectsTransactionTO(
                    dcqlQuery(),
                    "nonce",
                    intendedUseId = "1",
                )

            val useCase: InitTransaction =
                TestContext.initTransaction(
                    verifierConfig,
                    EmbedOption.byReference { _ -> uri },
                )

            val jwtSecuredAuthorizationRequest =
                assertIs<InitOpenId4VPOverRedirectsTransactionResponse.JwtSecuredAuthorizationRequestTO>(
                    either { useCase(input) }.getOrElse { fail("Unexpected $it") },
                )
            assertEquals(jwtSecuredAuthorizationRequest.clientId, verifierConfig.verifierId.clientId)
            assertNotNull(jwtSecuredAuthorizationRequest.request)
            assertTrue {
                loadPresentationById(testTransactionId)?.let { it is Presentation.RequestObjectRetrieved } ?: false
            }
        }

    @Test
    fun `when request option is embed by ref, request_uri should be present and presentation should be Requested`() =
        runTest {
            val uri = URI.create("https://foo").toURL()
            val wrprc = TestUtils.loadResource("wrprc.jwt")
            val verifierConfig =
                VerifierConfig(
                    verifierId = TestContext.verifierId,
                    requestJarOption = EmbedOption.ByReference { _ -> uri },
                    responseUriBuilder = { _ -> URI.create("https://foo").toURL() },
                    defaultHttpResponseModeOption = HttpResponseModeOption.DirectPostJwt,
                    maxAge = 3.days,
                    clientMetaData = TestContext.clientMetaData,
                    transactionDataHashAlgorithm = HashAlgorithm.SHA_256,
                    requestUriMethod = RequestUriMethod.Get,
                    authorizationRequestUri = UnresolvedAuthorizationRequestUri.fromUri("haip-vp://").getOrThrow(),
                    intendedUses =
                        listOf(
                            IntendedUse.create(
                                description = "test",
                                registrationCertificate = wrprc,
                                id = "1",
                            ),
                        ),
                )

            val input =
                InitOpenId4VPOverRedirectsTransactionTO(
                    dcqlQuery(),
                    nonce = "nonce",
                    intendedUseId = "1",
                )

            val useCase =
                TestContext.initTransaction(
                    verifierConfig,
                    EmbedOption.byReference { _ -> uri },
                )

            val jwtSecuredAuthorizationRequest =
                assertIs<InitOpenId4VPOverRedirectsTransactionResponse.JwtSecuredAuthorizationRequestTO>(
                    either { useCase(input) }.getOrElse { fail("Unexpected $it") },
                )
            assertEquals(jwtSecuredAuthorizationRequest.clientId, verifierConfig.verifierId.clientId)
            assertEquals(uri.toExternalForm(), jwtSecuredAuthorizationRequest.requestUri)
            assertTrue {
                loadPresentationById(testTransactionId)?.let { it is Presentation.Requested } ?: false
            }
        }

    @Test
    fun `when input misses DCQL validation error is raised`() =
        runTest {
            // Input is invalid.
            //  Misses DCQL
            val input =
                InitOpenId4VPOverRedirectsTransactionTO(
                    dcqlQuery = null,
                    nonce = "nonce",
                    intendedUseId = "1",
                )
            testWithInvalidInput(input, ValidationError.MissingPresentationQuery)
        }

    @Test
    fun `when input misses nonce validation error is raised`() =
        runTest {
            // Input is invalid.
            val input =
                InitOpenId4VPOverRedirectsTransactionTO(
                    dcqlQuery(),
                    nonce = null,
                    intendedUseId = "1",
                )
            testWithInvalidInput(input, ValidationError.MissingNonce)
        }

    /**
     * Verifies [InitOpenId4VPOverRedirectsTransactionTO.responseMode] takes precedence over [VerifierConfig.defaultHttpResponseModeOption].
     */
    @Test
    fun `when response_mode is provided this must take precedence over what is configured in VerifierConfig`() =
        runTest {
            val input =
                InitOpenId4VPOverRedirectsTransactionTO(
                    dcqlQuery(),
                    nonce = "nonce",
                    responseMode = InitOpenId4VPOverRedirectsTransactionTO.ResponseModeTO.DirectPost,
                    intendedUseId = "1",
                )

            val useCase: InitTransaction =
                TestContext.initTransaction(
                    verifierConfig,
                    EmbedOption.byReference { _ -> uri },
                )

            val jwtSecuredAuthorizationRequest =
                assertIs<InitOpenId4VPOverRedirectsTransactionResponse.JwtSecuredAuthorizationRequestTO>(
                    either { useCase(input) }.getOrElse { fail("Unexpected $it") },
                )
            assertEquals(jwtSecuredAuthorizationRequest.clientId, verifierConfig.verifierId.clientId)
            assertNotNull(jwtSecuredAuthorizationRequest.request)
            val presentation = loadPresentationById(testTransactionId)
            val requestObjectRetrieved =
                assertIs<Presentation.RequestObjectRetrieved<PresentationType.OpenId4VP.OverRedirects, WalletResponse.OpenId4VP>>(
                    presentation,
                )
            assertEquals(ResponseModeType.DirectPost, requestObjectRetrieved.presentationType.responseMode.type)
        }

    /**
     * Verifies [InitOpenId4VPOverRedirectsTransactionTO.jarMode] takes precedence over [VerifierConfig.requestJarOption].
     */
    @Test
    fun `when jar_mode is provided this must take precedence over what is configured in VerifierConfig`() =
        runTest {
            val input =
                InitOpenId4VPOverRedirectsTransactionTO(
                    dcqlQuery = dcqlQuery(),
                    nonce = "nonce",
                    jarMode = EmbedModeTO.ByReference,
                    intendedUseId = "1",
                )

            val useCase: InitTransaction =
                TestContext.initTransaction(
                    verifierConfig,
                    EmbedOption.byReference { _ -> uri },
                )

            // we expect the Authorization Request to contain a request_uri
            // and the Presentation to be in state Requested
            val jwtSecuredAuthorizationRequest =
                assertIs<InitOpenId4VPOverRedirectsTransactionResponse.JwtSecuredAuthorizationRequestTO>(
                    either { useCase(input) }.getOrElse { fail("Unexpected $it") },
                )
            assertEquals(jwtSecuredAuthorizationRequest.clientId, verifierConfig.verifierId.clientId)
            assertNull(jwtSecuredAuthorizationRequest.request)
            assertNotNull(jwtSecuredAuthorizationRequest.requestUri)
            val presentation = loadPresentationById(testTransactionId)
            assertIs<Presentation.Requested>(presentation)
        }

    @Test
    fun `when wallet_response_redirect_uri_template is invalid, validation error InvalidWalletResponseTemplate should be raised`() =
        runTest {
            val useCase: InitTransaction =
                TestContext.initTransaction(
                    verifierConfig,
                    EmbedOption.byReference { _ -> uri },
                )

            val invalidPlaceHolderInput =
                InitOpenId4VPOverRedirectsTransactionTO(
                    dcqlQuery = dcqlQuery(),
                    "nonce",
                    redirectUriTemplate = "https://client.example.org/cb#response_code=#CODE#",
                    intendedUseId = "1",
                )

            either { useCase(invalidPlaceHolderInput) }
                .onLeft {
                    assertTrue(
                        "Should fail with ValidationError.InvalidWalletResponseTemplate",
                    ) { it == ValidationError.InvalidWalletResponseTemplate }
                }.onRight {
                    fail("Should fail with ValidationError.InvalidWalletResponseTemplate")
                }

            val invalidUrlInput =
                InitOpenId4VPOverRedirectsTransactionTO(
                    dcqlQuery = dcqlQuery(),
                    "nonce",
                    redirectUriTemplate =
                        "hts:/client.example.org/cb%response_code=${CreateQueryWalletResponseRedirectUri.RESPONSE_CODE_PLACE_HOLDER}",
                    intendedUseId = "1",
                )

            either { useCase(invalidUrlInput) }
                .onLeft {
                    assertTrue(
                        "Should fail with ValidationError.InvalidWalletResponseTemplate",
                    ) { it == ValidationError.InvalidWalletResponseTemplate }
                }.onRight {
                    fail("Should fail with ValidationError.InvalidWalletResponseTemplate")
                }
        }

    @Test
    fun `when wallet_response_redirect_uri_template is valid, then get wallet response method should be REDIRECT`() =
        runTest {
            val input =
                InitOpenId4VPOverRedirectsTransactionTO(
                    dcqlQuery(),
                    "nonce",
                    redirectUriTemplate =
                        "https://client.example.org/cb#response_code=${CreateQueryWalletResponseRedirectUri.RESPONSE_CODE_PLACE_HOLDER}",
                    intendedUseId = "1",
                )

            val useCase: InitTransaction =
                TestContext.initTransaction(
                    verifierConfig,
                    EmbedOption.byReference { _ -> uri },
                )

            assertIs<InitOpenId4VPOverRedirectsTransactionResponse.JwtSecuredAuthorizationRequestTO>(
                either { useCase(input) }.getOrElse { fail("Unexpected $it") },
            )
            val presentation = loadPresentationById(testTransactionId)
            assertIs<Presentation.RequestObjectRetrieved<PresentationType.OpenId4VP.OverRedirects, WalletResponse.OpenId4VP>>(presentation)
            assertIs<GetWalletResponseMethod.Redirect>(presentation.presentationType.getWalletResponseMethod)
        }

    @Test
    fun `when wallet_response_redirect_uri_template is not passed, then get wallet response method should be POLL`() =
        runTest {
            val input =
                InitOpenId4VPOverRedirectsTransactionTO(
                    dcqlQuery(),
                    "nonce",
                    intendedUseId = "1",
                )

            val useCase: InitTransaction =
                TestContext.initTransaction(
                    verifierConfig,
                    EmbedOption.byReference { _ -> uri },
                )

            assertIs<InitOpenId4VPOverRedirectsTransactionResponse.JwtSecuredAuthorizationRequestTO>(
                either { useCase(input) }.getOrElse { fail("Unexpected $it") },
            )
            val presentation = loadPresentationById(testTransactionId)
            assertIs<Presentation.RequestObjectRetrieved<PresentationType.OpenId4VP.OverRedirects, WalletResponse.OpenId4VP>>(presentation)
            assertIs<GetWalletResponseMethod.Poll>(presentation.presentationType.getWalletResponseMethod)
        }

    @Test
    fun `when transaction_data contains jsonobjects without required properties, inittransaction fails`() =
        runTest {
            val useCase: InitTransaction =
                TestContext.initTransaction(
                    verifierConfig,
                    EmbedOption.byReference { _ -> uri },
                )

            suspend fun test(transactionData: JsonObject) {
                val input =
                    VerifierApiClient
                        .loadInitTransactionTO(
                            "00-dcql.json",
                        ).copy(transactionData = listOf(transactionData))

                val result = either { useCase(input) }
                assertEquals(ValidationError.InvalidTransactionData.left(), result)
            }

            val withoutType = JsonObject(emptyMap())
            val withoutCredentialIds =
                buildJsonObject {
                    put(OpenId4VPSpec.TRANSACTION_DATA_TYPE, "foo.bar")
                }

            test(withoutType)
            test(withoutCredentialIds)
        }

    @Test
    fun `when transaction_data contains jsonobjects with invalid credential ids, inittransaction fails`() =
        runTest {
            val useCase: InitTransaction =
                TestContext.initTransaction(
                    verifierConfig,
                    EmbedOption.byReference { _ -> uri },
                )

            suspend fun test(
                baseInput: String,
                credentialId: String,
            ) {
                val transactionData =
                    buildJsonObject {
                        put(OpenId4VPSpec.TRANSACTION_DATA_TYPE, "foo.bar")
                        putJsonArray(OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS) {
                            add(credentialId)
                        }
                    }

                val input =
                    VerifierApiClient
                        .loadInitTransactionTO(
                            baseInput,
                        ).copy(transactionData = listOf(transactionData))

                val result = either { useCase(input) }.leftOrNull()
                assertEquals(ValidationError.InvalidTransactionData, result)
            }

            test("00-dcql.json", "_foo_wa_driver_license")
            test("04-dcql.json", "_foo_employment_input")
        }

    @Test
    fun `when transaction_data contains jsonobjects with valid credential ids, inittransaction succeeds`() =
        runTest {
            val useCase: InitTransaction =
                TestContext.initTransaction(
                    verifierConfig,
                    EmbedOption.byReference { _ -> uri },
                )

            suspend fun test(
                baseInput: String,
                credentialId: String,
            ) {
                val transactionData =
                    buildJsonObject {
                        put(OpenId4VPSpec.TRANSACTION_DATA_TYPE, "foo.bar")
                        putJsonArray(OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS) {
                            add(credentialId)
                        }
                    }

                val input =
                    VerifierApiClient
                        .loadInitTransactionTO(
                            baseInput,
                        ).copy(transactionData = listOf(transactionData))

                val result = either { useCase(input) }
                val response =
                    assertNotNull(
                        assertIs<InitOpenId4VPOverRedirectsTransactionResponse.JwtSecuredAuthorizationRequestTO>(result.getOrNull()),
                    )
                val jar =
                    assertNotNull(response.request).let {
                        SignedJWT.parse(it).jwtClaimsSet
                    }
                val jarTransactionData =
                    run {
                        val jarTransactionDataList =
                            assertNotNull(jar.getStringListClaim(OpenId4VPSpec.TRANSACTION_DATA))
                        assertEquals(1, jarTransactionDataList.size)
                        val encodedJarTransactionData = jarTransactionDataList.first()
                        val decodedJarTransactionData = base64UrlNoPadding.decodeToByteString(encodedJarTransactionData)
                        Json.decodeFromString<JsonObject>(decodedJarTransactionData.decodeToString())
                    }
                val expectedJarTransactionData =
                    run {
                        val hashAlgorithms =
                            buildJsonArray {
                                add(verifierConfig.transactionDataHashAlgorithm.ianaName)
                            }
                        JsonObject(transactionData + (OpenId4VPSpec.TRANSACTION_DATA_HASH_ALGORITHMS to hashAlgorithms))
                    }
                assertEquals(expectedJarTransactionData, jarTransactionData)
            }

            test("00-dcql.json", "wa_driver_license")
            test("04-dcql.json", "employment_input")
        }

    private fun testWithInvalidInput(
        input: InitOpenId4VPOverRedirectsTransactionTO,
        expectedError: ValidationError,
    ) = either {
        context(verifierConfig.transactionDataHashAlgorithm, verifierConfig.clientMetaData.vpFormatsSupported) {
            validate(
                input.dcqlQuery,
                input.nonce,
                input.transactionData,
            )
        }
    }.fold(
        ifRight = { fail("Invalid input accepted") },
        ifLeft = { error -> assertEquals(expectedError, error) },
    )

    private suspend fun loadPresentationById(id: TransactionId) = TestContext.loadPresentationById(id)

    private fun dcqlQuery() = VerifierApiClient.loadInitTransactionTO("00-dcql.json").dcqlQuery!!
}
