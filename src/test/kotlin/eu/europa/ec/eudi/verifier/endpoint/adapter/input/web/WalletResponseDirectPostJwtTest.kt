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
package eu.europa.ec.eudi.verifier.endpoint.adapter.input.web

import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEEncrypter
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import eu.europa.ec.eudi.verifier.endpoint.VerifierApplicationTest
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.tokenstatuslist.StatusListTokenValidator
import eu.europa.ec.eudi.verifier.endpoint.domain.Clock
import eu.europa.ec.eudi.verifier.endpoint.domain.RequestId
import eu.europa.ec.eudi.verifier.endpoint.domain.TransactionId
import eu.europa.ec.eudi.verifier.endpoint.domain.VerifierConfig
import eu.europa.ec.eudi.verifier.endpoint.port.input.InitOpenId4VPOverRedirectsTransactionResponse
import eu.europa.ec.eudi.verifier.endpoint.port.input.InitOpenId4VPOverRedirectsTransactionTO
import eu.europa.ec.eudi.verifier.endpoint.port.input.WalletResponseTO
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.GenerateRequestId
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.GenerateEphemeralEncryptionKeyPair
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PublishPresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.presentation.ValidateVerifiablePresentation
import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.http.*
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.datetime.toKotlinFixedOffsetTimeZone
import kotlinx.serialization.json.*
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation
import org.junit.jupiter.api.Order
import org.junit.jupiter.api.TestMethodOrder
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.TestConfiguration
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Primary
import org.springframework.http.MediaType
import org.springframework.test.annotation.DirtiesContext
import org.springframework.test.context.TestPropertySource
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.test.web.reactive.server.expectBody
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap
import org.springframework.web.reactive.function.BodyInserters
import java.time.ZoneOffset
import kotlin.test.*
import kotlin.time.Instant

@VerifierApplicationTest([WalletResponseDirectPostJwtValidationsDisabledTest.Config::class])
@TestPropertySource(
    properties = [
        "verifier.maxAge=PT6400M",
        "verifier.defaultHttpResponseMode=DirectPostJwt",
        "verifier.clientMetadata.responseEncryption.algorithm=ECDH-ES",
        "verifier.clientMetadata.responseEncryption.method=A128GCM",
        "verifier.jwk.embed=ByValue",
    ],
)
@TestMethodOrder(OrderAnnotation::class)
internal class WalletResponseDirectPostJwtValidationsDisabledTest {
    private val log: Logger = LoggerFactory.getLogger(WalletResponseDirectPostJwtValidationsDisabledTest::class.java)

    @Autowired
    private lateinit var client: WebTestClient

    @Autowired
    private lateinit var config: VerifierConfig

    @TestConfiguration
    internal class Config {
        @Bean
        @Primary
        fun validateVerifiablePresentation(): ValidateVerifiablePresentation = ValidateVerifiablePresentation.NoOp
    }

    /**
     * Unit test of flow:
     * - verifier to verifier backend, to post DCQL query
     * - wallet to verifier backend, to post wallet response, an idToken
     * - verifier to verifier backend, to get wallet response
     *
     * @see: <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-response-mode-direct_postjw">OpenId4vp Response Mode "direct_post.jwt"</a>
     */
    @Test
    @Order(value = 1)
    fun `direct_post_jwt vp_token end to end`() =
        runTest {
            fun test(
                query: String,
                vpToken: String,
                asserter: (WalletResponseTO) -> Unit,
            ) {
                // given
                val initTransaction = VerifierApiClient.loadInitTransactionTO(query)
                val transactionInitialized =
                    assertIs<InitOpenId4VPOverRedirectsTransactionResponse.JwtSecuredAuthorizationRequestTO>(
                        VerifierApiClient.initTransaction(client, initTransaction),
                    )
                val requestId =
                    RequestId(transactionInitialized.requestUri?.removePrefix("http://localhost:0/wallet/request.jwt/")!!)
                val requestObjectJsonResponse: JsonObject =
                    WalletApiClient.retrieveRequestObjectResponse(client, transactionInitialized.requestUri)
                val transactionId = TransactionId(transactionInitialized.transactionId)

                val supportedEncryptionMethods = assertNotNull(requestObjectJsonResponse.supportedEncryptionMethods())
                assertEquals(config.clientMetaData.responseEncryptionOption.encryptionMethods, supportedEncryptionMethods)

                val ecKey = requestObjectJsonResponse.ecKey()
                assertNotNull(ecKey)
                assertNotNull(ecKey.algorithm)
                val supportedAlgorithm = JWEAlgorithm.parse(ecKey.algorithm.name)
                assertEquals(config.clientMetaData.responseEncryptionOption.algorithm, supportedAlgorithm)

                // (wallet) generate JWT with claims
                val jwtClaims: JWTClaimsSet =
                    buildJsonObject {
                        put("state", requestId.value)
                        put("vp_token", Json.decodeFromString(TestUtils.loadResource(vpToken)))
                    }.run { JWTClaimsSet.parse(Json.encodeToString(this)) }

                log.info("plaintextJwtClaims: ${jwtClaims.toJSONObject()}")

                // Request JWT encrypted with ECDH-ES
                val jweHeader =
                    JWEHeader
                        .Builder(supportedAlgorithm, supportedEncryptionMethods.first())
                        .agreementPartyVInfo(Base64URL.encode(initTransaction.nonce!!))
                        .build()
                log.info("header = ${jweHeader.toJSONObject()}")

                // Create the encrypted JWT object
                val encryptedJWT = EncryptedJWT(jweHeader, jwtClaims)

                // Create an encrypter with the specified public EC key
                val encrypter: JWEEncrypter = ECDHEncrypter(ecKey)

                // Do the actual encryption
                encryptedJWT.encrypt(encrypter)

                // Serialise to JWT compact form
                val jwtString: String = encryptedJWT.serialize()
                log.info("jwtString = $jwtString")

                // create a post form url encoded body
                val formEncodedBody: MultiValueMap<String, Any> = LinkedMultiValueMap()
                formEncodedBody.add("response", jwtString)

                // send the wallet response
                WalletApiClient.directPostJwt(client, requestId, formEncodedBody)

                // when
                val response = VerifierApiClient.getWalletResponse(client, transactionId)
                // then
                assertNotNull(response, "response is null")
                asserter(response)
            }

            // Test with single Verifiable Presentation -- single JsonObject
            test("02-dcql.json", "02-vpToken.json") {
                val vpToken = assertNotNull(it.vpToken)

                val waDriverLicence = assertIs<JsonArray>(vpToken["wa_driver_license"])
                assertEquals(1, waDriverLicence.size)
                assertIs<JsonObject>(waDriverLicence[0])
            }

            // Test with multiple Verifiable Presentation -- single JsonArray that contains one JsonPrimitive and one JsonObject
            test("03-dcql.json", "03-vpToken.json") {
                val vpToken = assertNotNull(it.vpToken)

                val employmentInput = assertIs<JsonArray>(vpToken["employment_input"])
                assertEquals(1, employmentInput.size)
                assertIs<JsonPrimitive>(employmentInput[0])

                val employmentInput2 = assertIs<JsonArray>(vpToken["employment_input_2"])
                assertEquals(1, employmentInput2.size)
                assertIs<JsonObject>(employmentInput2[0])
            }
        }

    /**
     * Verifies that a Transaction expecting a direct_post.jwt Wallet response, doesn't accept a direct_post Wallet response.
     */
    @Test
    @Order(value = 2)
    fun `with response_mode direct_post_jwt, direct_post wallet responses are rejected`(): Unit =
        runBlocking {
            // given
            val initTransaction =
                VerifierApiClient
                    .loadInitTransactionTO(
                        "02-dcql.json",
                    ).copy(responseMode = InitOpenId4VPOverRedirectsTransactionTO.ResponseModeTO.DirectPostJwt)
            val transactionInitialized =
                assertIs<InitOpenId4VPOverRedirectsTransactionResponse.JwtSecuredAuthorizationRequestTO>(
                    VerifierApiClient.initTransaction(
                        client,
                        initTransaction,
                    ),
                )
            val requestId =
                RequestId(transactionInitialized.requestUri?.removePrefix("http://localhost:0/wallet/request.jwt/")!!)
            val requestObjectJsonResponse =
                WalletApiClient.retrieveRequestObjectResponse(client, transactionInitialized.requestUri)

            val supportedEncryptionMethods = assertNotNull(requestObjectJsonResponse.supportedEncryptionMethods())
            assertEquals(config.clientMetaData.responseEncryptionOption.encryptionMethods, supportedEncryptionMethods)

            val ecKey = requestObjectJsonResponse.ecKey()
            assertNotNull(ecKey)
            val supportedAlgorithm = JWEAlgorithm.parse(ecKey.algorithm.name)
            assertEquals(config.clientMetaData.responseEncryptionOption.algorithm, supportedAlgorithm)

            // (wallet)
            // create a post form url encoded body
            val formEncodedBody: MultiValueMap<String, Any> = LinkedMultiValueMap()
            formEncodedBody.add("state", requestId.value)
            formEncodedBody.add("vp_token", TestUtils.loadResource("02-vpToken.json"))

            // send the wallet response
            // we expect the response submission to fail
            try {
                WalletApiClient.directPost(client, requestId, formEncodedBody)
                fail("Expected direct_post submission to fail for direct_post.jwt Presentation")
            } catch (error: AssertionError) {
                assertEquals("Status expected:<200 OK> but was:<400 BAD_REQUEST>", error.message)
            }
        }
}

@VerifierApplicationTest
@TestPropertySource(
    properties = [
        "verifier.maxAge=PT6400M",
        "verifier.defaultHttpResponseMode=DirectPostJwt",
        "verifier.clientMetadata.responseEncryption.algorithm=ECDH-ES",
        "verifier.clientMetadata.responseEncryption.method=A128GCM",
        "verifier.jwk.embed=ByValue",
    ],
)
internal class WalletResponseDirectPostJwtValidationsEnabledTest {
    @Autowired
    private lateinit var client: WebTestClient

    @Autowired
    private lateinit var config: VerifierConfig

    @Test
    fun `verifier accepts unencrypted error responses even when direct_post_jwt is expected`() =
        runTest {
            val initTransaction = VerifierApiClient.loadInitTransactionTO("06-pidPlusMdl-dcql.json")

            val transactionDetails =
                assertIs<InitOpenId4VPOverRedirectsTransactionResponse.JwtSecuredAuthorizationRequestTO>(
                    VerifierApiClient.initTransaction(client, initTransaction),
                )
            WalletApiClient.retrieveRequestObjectResponse(client, transactionDetails.requestUri!!)

            val requestId = RequestId(transactionDetails.requestUri.removePrefix("http://localhost:0/wallet/request.jwt/"))

            val walletResponse =
                LinkedMultiValueMap<String, Any>()
                    .apply {
                        add("state", requestId.value)
                        add("error", "error")
                    }

            WalletApiClient.directPost(client, requestId, walletResponse)

            val expectedWalletResponseTO =
                WalletResponseTO(
                    error = "error",
                )
            assertEquals(
                expectedWalletResponseTO,
                VerifierApiClient.getWalletResponse(client, TransactionId(transactionDetails.transactionId)),
            )
        }
}

/**
 * Status List checks of SD-JWT VC presentations.
 *
 * `08-validStatusList-vpToken.json` and `08-invalidStatusList-vpToken.json` answer the Credential Query of
 * `08-invalidStatusList-dcql.json`. Both are signed by an X.509 certified Issuer (`x5c`), carry the same claims,
 * and contain a Key Binding JWT bound to the `nonce` of the Transaction and the `client_id` of the Verifier,
 * issued at the time of [Config.clock]. They differ only in their `status.status_list.uri`:
 * - `08-validStatusList-vpToken.json` references a `VALID` entry of the Status List Token in `08-statusList.jwt`,
 *   served by [Config.statusListTokenValidatorServingTestStatusList]
 * - `08-invalidStatusList-vpToken.json` references a Status List that cannot be retrieved
 */
@VerifierApplicationTest([SdJwtVcStatusListValidationTest.Config::class])
@TestPropertySource(
    properties = [
        "verifier.maxAge=PT6400M",
        "verifier.defaultHttpResponseMode=DirectPostJwt",
        "verifier.clientMetadata.responseEncryption.algorithm=ECDH-ES",
        "verifier.clientMetadata.responseEncryption.method=A128GCM",
        "verifier.jwk.embed=ByValue",
        "verifier.validation.statusCheck.enabled=true",
        "verifier.attestation-classifications.eaa[0].use-case=sample",
        "verifier.attestation-classifications.eaa[0].vcts=urn:credential:sample",
    ],
)
internal class SdJwtVcStatusListValidationTest {
    @TestConfiguration
    class Config {
        @Bean
        @Primary
        fun clock(): Clock =
            Clock.fixed(
                now = Instant.fromEpochSeconds(1791936000L),
                timeZone = ZoneOffset.UTC.toKotlinFixedOffsetTimeZone(),
            )

        @Bean
        @Primary
        fun statusListTokenValidatorServingTestStatusList(
            clock: Clock,
            publishPresentationEvent: PublishPresentationEvent,
        ): StatusListTokenValidator {
            val httpClient =
                HttpClient(
                    MockEngine { request ->
                        if (STATUS_LIST_URI == request.url.toString()) {
                            respond(
                                content = TestUtils.loadResource("08-statusList.jwt"),
                                status = HttpStatusCode.OK,
                                headers = headersOf(HttpHeaders.ContentType, "application/statuslist+jwt"),
                            )
                        } else {
                            respondError(HttpStatusCode.NotFound)
                        }
                    },
                )
            return StatusListTokenValidator(httpClient, clock, publishPresentationEvent)
        }

        companion object {
            const val STATUS_LIST_URI = "https://issuer.example.com/status-lists/1"
        }
    }

    @Autowired
    private lateinit var client: WebTestClient

    @Autowired
    private lateinit var config: VerifierConfig

    @Test
    fun `when wallet posts sd-jwt-vc with valid status list details, post succeeds`() =
        runTest {
            val (initTransaction, transactionDetails) = initTransaction()
            val requestId = requestId(transactionDetails)

            WalletApiClient.directPostJwt(
                client,
                requestId,
                walletResponse(initTransaction, transactionDetails, "08-validStatusList-vpToken.json"),
            )

            val walletResponse =
                assertNotNull(VerifierApiClient.getWalletResponse(client, TransactionId(transactionDetails.transactionId)))
            val vpToken = assertNotNull(walletResponse.vpToken)
            val sampleCredential = assertIs<JsonArray>(vpToken["sample_credential"])
            assertEquals(1, sampleCredential.size)
        }

    @Test
    fun `when wallet posts sd-jwt-vc with invalid status list details, post fails`() =
        runTest {
            val (initTransaction, transactionDetails) = initTransaction()
            val requestId = requestId(transactionDetails)

            val error =
                client
                    .post()
                    .uri { builder -> builder.path(WalletApi.WALLET_RESPONSE_PATH).build(requestId.value) }
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .accept(MediaType.APPLICATION_JSON)
                    .body(
                        BodyInserters.fromValue(
                            walletResponse(initTransaction, transactionDetails, "08-invalidStatusList-vpToken.json"),
                        ),
                    ).exchange()
                    .expectStatus()
                    .isBadRequest()
                    .expectBody<String>()
                    .returnResult()
                    .responseBody
                    .let { Json.decodeFromString<JsonObject>(assertNotNull(it)) }

            // The only reason the presentation is rejected must be the failed Status List check
            assertEquals("InvalidVpToken", error["error"]?.jsonPrimitive?.content, "$error")
            val validationErrors =
                assertNotNull(
                    runCatching {
                        Json.decodeFromString<JsonArray>(assertNotNull(error["description"]).jsonPrimitive.content)
                    }.getOrNull(),
                    "Expected the SD-JWT VC validation errors, but got: $error",
                )
            assertEquals(
                listOf("StatusCheckFailed"),
                validationErrors.map { it.jsonObject["error"]?.jsonPrimitive?.content },
                "$error",
            )
        }

    private fun initTransaction():
        Pair<InitOpenId4VPOverRedirectsTransactionTO, InitOpenId4VPOverRedirectsTransactionResponse.JwtSecuredAuthorizationRequestTO> {
        val initTransaction = VerifierApiClient.loadInitTransactionTO("08-invalidStatusList-dcql.json")
        val transactionDetails =
            assertIs<InitOpenId4VPOverRedirectsTransactionResponse.JwtSecuredAuthorizationRequestTO>(
                VerifierApiClient.initTransaction(client, initTransaction),
            )
        return initTransaction to transactionDetails
    }

    private fun requestId(transactionDetails: InitOpenId4VPOverRedirectsTransactionResponse.JwtSecuredAuthorizationRequestTO): RequestId =
        RequestId(assertNotNull(transactionDetails.requestUri).removePrefix("http://localhost:0/wallet/request.jwt/"))

    private fun walletResponse(
        initTransaction: InitOpenId4VPOverRedirectsTransactionTO,
        transactionDetails: InitOpenId4VPOverRedirectsTransactionResponse.JwtSecuredAuthorizationRequestTO,
        vpToken: String,
    ): MultiValueMap<String, Any> {
        val requestObjectJsonResponse =
            WalletApiClient.retrieveRequestObjectResponse(client, assertNotNull(transactionDetails.requestUri))

        val supportedEncryptionMethods = assertNotNull(requestObjectJsonResponse.supportedEncryptionMethods())
        assertEquals(config.clientMetaData.responseEncryptionOption.encryptionMethods, supportedEncryptionMethods)

        val ecKey = assertNotNull(requestObjectJsonResponse.ecKey())
        assertNotNull(ecKey.algorithm)
        val supportedAlgorithm = JWEAlgorithm.parse(ecKey.algorithm.name)

        val encryptedJwt =
            run {
                val jwtClaims: JWTClaimsSet =
                    buildJsonObject {
                        put("state", requestId(transactionDetails).value)
                        put("vp_token", Json.decodeFromString(TestUtils.loadResource(vpToken)))
                    }.run { JWTClaimsSet.parse(Json.encodeToString(this)) }

                val jweHeader =
                    JWEHeader
                        .Builder(supportedAlgorithm, supportedEncryptionMethods.first())
                        .agreementPartyVInfo(Base64URL.encode(initTransaction.nonce!!))
                        .build()

                EncryptedJWT(jweHeader, jwtClaims)
            }.apply { encrypt(ECDHEncrypter(ecKey)) }

        return LinkedMultiValueMap<String, Any>().apply { add("response", encryptedJwt.serialize()) }
    }
}

@VerifierApplicationTest([DeviceResponseValidationTest.Config::class])
@TestPropertySource(
    properties = [
        "verifier.maxAge=PT6400M",
        "verifier.defaultHttpResponseMode=DirectPostJwt",
        "verifier.clientMetadata.responseEncryption.algorithm=ECDH-ES",
        "verifier.clientMetadata.responseEncryption.method=A128GCM",
        "verifier.jwk.embed=ByValue",
        "verifier.validation.statusCheck.enabled=false",
        "verifier.attestation-classifications.eaa[0].use-case=mDL",
        "verifier.attestation-classifications.eaa[0].doc-types=org.iso.18013.5.1.mDL",
        "verifier.wrprc[0].intended-use-id=1",
        "verifier.wrprc[0].description=test",
        "verifier.wrprc[0].registration-certificate=eyJ4NWMiOlsiTUlJQmNUQ0NBUmlnQXdJQkFnSUdBWjlHbC9yaU1Bb0dDQ3FHU000OUJBTUNNRUF4UGpBOEJnTlZCQU1NTlZSbGMzUWdTWE56ZFdWeUlFbHVabThnWXpKa056VmtNMll0TVRWbFpDMDBNemszTFdJeU5HRXRabVk0WkdWbFlUTXlZekJpTUI0WERUSTJNRGN3T1RFeE1UWXpNMW9YRFRJM01EY3dPVEV4TVRZek0xb3dRREUrTUR3R0ExVUVBd3cxVkdWemRDQkpjM04xWlhJZ1NXNW1ieUJqTW1RM05XUXpaaTB4TldWa0xUUXpPVGN0WWpJMFlTMW1aamhrWldWaE16SmpNR0l3V1RBVEJnY3Foa2pPUFFJQkJnZ3Foa2pPUFFNQkJ3TkNBQVNYNEJjd2JCS2hvVVdqNHhDc2tVZWZPRGczdEhoak5WZjUwZGFmTWpCTkg1SEhyK3UyUXpyZkluNE9KWlc5UEVkbFF3b1ZhSVNRc09odlg5dmxWVW5YTUFvR0NDcUdTTTQ5QkFNQ0EwY0FNRVFDSUd1clFZSmhNcTdGTnZPS3dPZG5Na2UwSExrU2pkY3RJV2hoSGl2U3l3YnJBaUFLdnpzZDgzci9IU3E3aTdRUHJ4dHJvbUEvZ1grMEc5SWFtRjFLdDZ6Ky93PT0iXSwia2lkIjoiYzYzNjgzZjItN2RmMy00M2ZmLWI1MzktZDA3MTk0NDViMGJlIiwidHlwIjoiSldUIiwiYWxnIjoiRVMyNTYifQ.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwic3ViIjoiaXNzdWVyLWluZm8iLCJpYXQiOjE3ODM1OTU3OTJ9.Ai4XydxG__EASIOboGWcPzK2hMTIrHSvGrnT3UhInc8UkXBiCacPgEurYQ9fO6J1fhhX2eRe6t7xRcbT-Rzy-g",
    ],
)
internal class DeviceResponseValidationTest {
    @TestConfiguration
    class Config {
        @Bean
        @Primary
        fun clock(): Clock =
            Clock.fixed(
                now = Instant.fromEpochSeconds(1766135977L),
                timeZone = ZoneOffset.ofHours(3).toKotlinFixedOffsetTimeZone(),
            )

        @Bean
        @Primary
        fun generateRequestId(): GenerateRequestId = GenerateRequestId.fixed(requestId)

        @Bean
        @Primary
        fun generateEphemeralEncryptionKeyPair(): GenerateEphemeralEncryptionKeyPair =
            GenerateEphemeralEncryptionKeyPair { ephemeralEncryptionKey }

        companion object {
            val requestId: RequestId = RequestId("1234567890")
            val ephemeralEncryptionKey: ECKey =
                ECKey.parse(
                    """
                    {
                        "kty": "EC",
                        "d": "RD5iTzNDQpt7KeOM1AfMV1Un27-LY9QZSABS2ETfBc4",
                        "use": "enc",
                        "crv": "P-256",
                        "kid": "de7eb521-eb6a-403d-a83f-a74333b936e5",
                        "x": "rQARUEPijpGzfTIaZUv8G9h-09spX-J9mGXuEFyu06g",
                        "y": "PEFq_diAbJH2aUV57z0f9ngrbWikTCN7Pczg-VkQBXE",
                        "alg": "ECDH-ES"
                    }
                    """.trimIndent(),
                )
        }
    }

    @Autowired
    private lateinit var client: WebTestClient

    @Autowired
    private lateinit var config: VerifierConfig

    @Test
    @DirtiesContext
    fun `when wallet responds with a deviceresponse that contains valid deviceauthentication, validations succeeds`() =
        runTest {
            val initTransaction = VerifierApiClient.loadInitTransactionTO("07-mdl-dcql.json")
            val transactionDetails =
                assertIs<InitOpenId4VPOverRedirectsTransactionResponse.JwtSecuredAuthorizationRequestTO>(
                    VerifierApiClient.initTransaction(client, initTransaction),
                )
            WalletApiClient.retrieveRequestObjectResponse(client, transactionDetails.requestUri!!)

            val encryptedJwt =
                run {
                    val jwtClaims: JWTClaimsSet =
                        buildJsonObject {
                            put("state", Config.requestId.value)
                            put("vp_token", Json.decodeFromString(TestUtils.loadResource("07-mdl-vpToken.json")))
                        }.run { JWTClaimsSet.parse(Json.encodeToString(this)) }

                    val jweHeader =
                        JWEHeader
                            .Builder(
                                JWEAlgorithm(Config.ephemeralEncryptionKey.algorithm.name),
                                config.clientMetaData.responseEncryptionOption.encryptionMethods
                                    .first(),
                            ).agreementPartyVInfo(Base64URL.encode(initTransaction.nonce!!))
                            .build()

                    EncryptedJWT(jweHeader, jwtClaims)
                }.apply { encrypt(ECDHEncrypter(Config.ephemeralEncryptionKey)) }

            val walletResponse =
                LinkedMultiValueMap<String, Any>()
                    .apply {
                        add("response", encryptedJwt.serialize())
                    }

            WalletApiClient.directPostJwt(client, Config.requestId, walletResponse)

            val transactionResponse =
                assertNotNull(
                    VerifierApiClient.getWalletResponse(
                        client,
                        TransactionId(transactionDetails.transactionId),
                    ),
                )

            val vpToken = assertNotNull(transactionResponse.vpToken)
            assertEquals(1, vpToken.size)

            val mDL = assertIs<JsonArray>(vpToken["query_0"])
            assertEquals(1, mDL.size)
            assertIs<JsonPrimitive>(mDL[0])
        }

    @Test
    @DirtiesContext
    fun `when wallet responds with a deviceresponse that contains invalid deviceauthentication, validations fail`() =
        runTest {
            // Set a different Nonce that what is included in OpenID4VPHandoverInfo, to cause a validation failure
            val initTransaction = VerifierApiClient.loadInitTransactionTO("07-mdl-dcql.json").copy(nonce = "nonce")
            val transactionDetails =
                assertIs<InitOpenId4VPOverRedirectsTransactionResponse.JwtSecuredAuthorizationRequestTO>(
                    VerifierApiClient.initTransaction(client, initTransaction),
                )
            WalletApiClient.retrieveRequestObjectResponse(client, transactionDetails.requestUri!!)

            val encryptedJwt =
                run {
                    val jwtClaims: JWTClaimsSet =
                        buildJsonObject {
                            put("state", Config.requestId.value)
                            put("vp_token", Json.decodeFromString(TestUtils.loadResource("07-mdl-vpToken.json")))
                        }.run { JWTClaimsSet.parse(Json.encodeToString(this)) }

                    val jweHeader =
                        JWEHeader
                            .Builder(
                                JWEAlgorithm(Config.ephemeralEncryptionKey.algorithm.name),
                                config.clientMetaData.responseEncryptionOption.encryptionMethods
                                    .first(),
                            ).agreementPartyVInfo(Base64URL.encode(initTransaction.nonce!!))
                            .build()

                    EncryptedJWT(jweHeader, jwtClaims)
                }.apply { encrypt(ECDHEncrypter(Config.ephemeralEncryptionKey)) }

            val walletResponse =
                LinkedMultiValueMap<String, Any>()
                    .apply {
                        add("response", encryptedJwt.serialize())
                    }

            try {
                WalletApiClient.directPostJwt(client, Config.requestId, walletResponse)
                fail("Expected to fail but didn't")
            } catch (error: AssertionError) {
                assertEquals("Status expected:<200 OK> but was:<400 BAD_REQUEST>", error.message)
            }
        }
}
