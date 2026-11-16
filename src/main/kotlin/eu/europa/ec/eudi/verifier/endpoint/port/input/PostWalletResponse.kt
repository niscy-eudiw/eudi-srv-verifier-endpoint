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
package eu.europa.ec.eudi.verifier.endpoint.port.input

import arrow.core.NonEmptyList
import arrow.core.raise.Raise
import arrow.core.raise.context.bind
import arrow.core.raise.context.ensure
import arrow.core.raise.context.ensureNotNull
import arrow.core.raise.context.raise
import arrow.core.raise.context.withError
import arrow.core.raise.effect
import arrow.core.raise.either
import arrow.core.raise.recover
import arrow.core.toNonEmptyListOrNull
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.DeviceResponseError
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.DeviceResponseValidator
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.HandoverInfo
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.utils.getOrThrow
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation.RequestObjectRetrieved
import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation.Submitted
import eu.europa.ec.eudi.verifier.endpoint.domain.mso.dcapi.DCApiResponse
import eu.europa.ec.eudi.verifier.endpoint.domain.mso.dcapi.EncryptedResponse
import eu.europa.ec.eudi.verifier.endpoint.port.input.WalletResponseValidationError.*
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.CreateQueryWalletResponseRedirectUri
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.GenerateResponseCode
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.VerifyEncryptedResponse
import eu.europa.ec.eudi.verifier.endpoint.port.out.mso.dcapi.DecryptDeviceResponse
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationById
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationByRequestId
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PublishPresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.StorePresentation
import eu.europa.ec.eudi.verifier.endpoint.port.out.presentation.ValidateVerifiablePresentation
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.security.cert.X509Certificate
import kotlin.reflect.KClass

/**
 * Represent the Authorization Response placed by wallet
 */
data class AuthorisationResponseTO(
    val state: String?, // this is the request_id
    val error: String? = null,
    val errorDescription: String? = null,
    val vpToken: JsonObject? = null,
)

sealed interface AuthorisationResponse {
    sealed interface OpenId4VP : AuthorisationResponse {
        sealed interface OverRedirects : OpenId4VP {
            data class DirectPost(
                val response: AuthorisationResponseTO,
            ) : OverRedirects

            data class DirectPostJwt(
                val encryptedResponse: Jwt,
            ) : OverRedirects
        }

        sealed interface OverDCApi : OpenId4VP {
            data class DCApi(
                val response: AuthorisationResponseTO,
            ) : OverDCApi

            data class DCApiJwt(
                val encryptedResponse: Jwt,
            ) : OverDCApi
        }
    }

    sealed interface ISO : AuthorisationResponse {
        data class OverDCApi(
            val response: DCApiResponse,
        ) : ISO
    }
}

private fun AuthorisationResponse.OpenId4VP.OverRedirects.DirectPost.isErrorResponse(): Boolean = null != response.error

private fun AuthorisationResponse.OpenId4VP.OverDCApi.DCApi.isErrorResponse(): Boolean = null != response.error

sealed interface WalletResponseValidationError {
    data object PresentationNotFound : WalletResponseValidationError

    data class UnexpectedResponseMode(
        val requestId: RequestId?,
        val expected: ResponseModeType,
        val actual: ResponseModeType,
    ) : WalletResponseValidationError

    data object PresentationNotInExpectedState : WalletResponseValidationError

    data object IncorrectState : WalletResponseValidationError

    data class InvalidVpToken(
        val message: String,
        val cause: Throwable? = null,
    ) : WalletResponseValidationError

    data object MissingVpToken : WalletResponseValidationError

    data object RequiredCredentialSetNotSatisfied : WalletResponseValidationError

    data class InvalidEncryptedResponse(
        val error: Exception,
    ) : WalletResponseValidationError

    sealed interface HAIPValidationError : WalletResponseValidationError {
        data object DeviceResponseContainsMoreThanOneMDoc : HAIPValidationError

        data class UnsupportedMsoRevocationMechanism(
            val used: Set<String>,
            val allowed: Set<String>,
        ) : HAIPValidationError

        data object SdJwtVcMustUseTokenStatusList : HAIPValidationError
    }

    class DeviceResponseCannotBeDecrypted(
        val cause: Throwable,
    ) : WalletResponseValidationError

    class InvalidDeviceResponse(
        val message: String,
        val cause: Throwable? = null,
    ) : WalletResponseValidationError
}

context(_: Raise<WalletResponseValidationError>)
private suspend fun AuthorisationResponseTO.toDomain(
    presentation: RequestObjectRetrieved,
    validateVerifiablePresentation: ValidateVerifiablePresentation,
    vpFormatsSupported: VpFormatsSupported,
): WalletResponse.OpenId4VP {
    suspend fun requiredVerifiablePresentations(): VerifiablePresentations =
        verifiablePresentations(
            presentation,
            validateVerifiablePresentation,
            vpFormatsSupported,
        )

    val maybeError: WalletResponse.OpenId4VP.Error? = error?.let { WalletResponse.OpenId4VP.Error(it, errorDescription) }
    return maybeError ?: WalletResponse.OpenId4VP.VpToken(requiredVerifiablePresentations())
}

context(_: Raise<WalletResponseValidationError>)
private suspend fun AuthorisationResponseTO.verifiablePresentations(
    presentation: RequestObjectRetrieved,
    validateVerifiablePresentation: ValidateVerifiablePresentation,
    vpFormatsSupported: VpFormatsSupported,
): VerifiablePresentations {
    ensureNotNull(vpToken) { MissingVpToken }
    val presentationType = presentation.presentationType
    check(presentationType is PresentationType.OpenId4VP)

    suspend fun JsonObject.toVerifiablePresentations(): Map<QueryId, List<VerifiablePresentation>> {
        val vpToken =
            try {
                Json.decodeFromJsonElement<Map<QueryId, List<JsonElement>>>(this)
            } catch (e: Exception) {
                raise(InvalidVpToken("Failed to decode vp_token", e))
            }

        val credentialQueries =
            presentationType.query.credentials.value
                .associateBy { it.id }
        return vpToken.mapValues { (queryId, value) ->
            val format =
                credentialQueries[queryId]?.format
                    ?: raise(
                        InvalidVpToken(
                            "vp_token references non-existing Credential Query",
                            null,
                        ),
                    )
            val unvalidatedVerifiablePresentations = value.map { it.toVerifiablePresentation(format) }
            val applicableTransactionData =
                presentationType.transactionData
                    ?.filter { queryId.value in it.credentialIds }
                    ?.toNonEmptyListOrNull()
            ensure(vpFormatsSupported.supports(format)) {
                InvalidVpToken(
                    "vp_token contains a Verifiable Presentation in an unsupported format",
                    null,
                )
            }
            unvalidatedVerifiablePresentations.map {
                validateVerifiablePresentation(
                    presentation,
                    it,
                    applicableTransactionData,
                )
            }
        }
    }

    val verifiablePresentations = vpToken.toVerifiablePresentations()
    ensure(presentationType.query.satisfiedBy(verifiablePresentations)) {
        RequiredCredentialSetNotSatisfied
    }

    return VerifiablePresentations(verifiablePresentations)
}

context(_: Raise<WalletResponseValidationError>)
private fun JsonElement.toVerifiablePresentation(format: Format): VerifiablePresentation {
    fun JsonElement.asString(): VerifiablePresentation.Str {
        val element = this@asString
        ensure(element is JsonPrimitive && element.isString) {
            InvalidVpToken("vp_token contains a non-string element", null)
        }
        return VerifiablePresentation.Str(element.content, format)
    }

    fun JsonElement.asStringOrObject(): VerifiablePresentation =
        when (val element = this@asStringOrObject) {
            is JsonPrimitive -> {
                ensure(
                    element.isString,
                ) { InvalidVpToken("vp_token contains a non-string element", null) }
                VerifiablePresentation.Str(element.content, format)
            }

            is JsonObject -> {
                VerifiablePresentation.Json(element, format)
            }

            else -> {
                raise(
                    InvalidVpToken(
                        "vp_token must contain either json strings, or json objects",
                        null,
                    ),
                )
            }
        }

    val element = this@toVerifiablePresentation
    return when (format) {
        Format.MsoMdoc -> element.asString()
        Format.SdJwtVc -> element.asStringOrObject()
        else -> element.asStringOrObject()
    }
}

@Serializable
data class WalletResponseAcceptedTO(
    @SerialName(OpenId4VPSpec.REDIRECT_URI) val redirectUri: String,
)

/**
 * Identifies a [Presentation] to be looked up when posting a wallet response.
 *
 * Use [ByRequestId] when the caller has a [RequestId] (e.g. WalletApi direct-post flow).
 * Use [ByTransactionId] when the caller has a [TransactionId] (e.g. VerifierApi DC API flow).
 */
sealed interface PresentationLookup {
    @JvmInline
    value class ByRequestId(
        val requestId: RequestId,
    ) : PresentationLookup

    @JvmInline
    value class ByTransactionId(
        val transactionId: TransactionId,
    ) : PresentationLookup
}

/**
 * This is use-case 12 of the [Presentation] process.
 *
 * The caller (wallet) may POST the [AuthorisationResponseTO] to the verifier back-end
 */
interface PostWalletResponse {
    context(_: Raise<WalletResponseValidationError>)
    suspend operator fun invoke(
        lookup: PresentationLookup,
        walletResponse: AuthorisationResponse.OpenId4VP,
    ): WalletResponseAcceptedTO?

    context(_: Raise<WalletResponseValidationError>)
    suspend operator fun invoke(
        lookup: PresentationLookup.ByTransactionId,
        walletResponse: AuthorisationResponse.ISO.OverDCApi,
    )
}

private val log = LoggerFactory.getLogger(PostWalletResponse::class.java)

class PostWalletResponseLive(
    private val loadPresentationById: LoadPresentationById,
    private val loadPresentationByRequestId: LoadPresentationByRequestId,
    private val storePresentation: StorePresentation,
    private val verifyEncryptedResponse: VerifyEncryptedResponse,
    private val clock: Clock,
    private val verifierConfig: VerifierConfig,
    private val generateResponseCode: GenerateResponseCode,
    private val createQueryWalletResponseRedirectUri: CreateQueryWalletResponseRedirectUri,
    private val publishPresentationEvent: PublishPresentationEvent,
    private val validateVerifiablePresentation: ValidateVerifiablePresentation,
    private val decryptDeviceResponse: DecryptDeviceResponse,
    private val deviceResponseValidatorFactory: (NonEmptyList<X509Certificate>?) -> DeviceResponseValidator,
) : PostWalletResponse {
    context(_: Raise<WalletResponseValidationError>)
    override suspend operator fun invoke(
        lookup: PresentationLookup,
        walletResponse: AuthorisationResponse.OpenId4VP,
    ): WalletResponseAcceptedTO? {
        log.debug(lookup, walletResponse)

        val presentation = loadPresentation(lookup)
        ensure(presentation is RequestObjectRetrieved) {
            PresentationNotInExpectedState
        }
        log.debug(presentation, walletResponse)

        val presentationType = presentation.presentationType
        check(presentationType is PresentationType.OpenId4VP) {
            "Expected OpenId4VP Presentation for OpenId4VP Authorisation Response"
        }

        val responseObject = responseObject(walletResponse, presentationType, presentation.nonce)
        log.info(presentation.id, responseObject)

        return effect {
            val (submitted, accepted) = submit(presentation, responseObject)
            logWalletResponsePosted(submitted, accepted)
            accepted
        }.recover { cause ->
            logFailure(presentation, responseObject, cause)
            raise(cause)
        }.bind()
    }

    context(_: Raise<WalletResponseValidationError>)
    override suspend operator fun invoke(
        lookup: PresentationLookup.ByTransactionId,
        walletResponse: AuthorisationResponse.ISO.OverDCApi,
    ) {
        log.debug(lookup, walletResponse)

        val presentation = loadPresentation(lookup)
        ensure(presentation is RequestObjectRetrieved) {
            PresentationNotInExpectedState
        }
        log.debug(presentation, walletResponse)

        val presentationType = presentation.presentationType
        check(presentationType is PresentationType.ISO.OverDCApi) {
            "Expected ISO Presentation for ISO DC API Authorisation Response"
        }

        effect {
            val serialized =
                decryptDeviceResponse(
                    presentation,
                    walletResponse.response.encryptedResponse,
                )

            val deviceResponseValidator = deviceResponseValidatorFactory(presentation.issuerChain)
            val deviceResponse =
                withError({ InvalidDeviceResponse(it) }) {
                    deviceResponseValidator.ensureValid(
                        serialized,
                        presentation.id,
                        HandoverInfo.ISODCApiHandoverInfo(
                            presentation.nonce,
                            presentationType.responseMode.ephemeralResponseEncryptionKey.toPublicJWK(),
                            presentationType.origin,
                        ),
                    )
                }

            val submitted = presentation.submit(clock, WalletResponse.ISO(deviceResponse))
            storePresentation(submitted)
            logWalletResponsePosted(submitted, null)
        }.recover {
            logFailure(presentation, null, it)
            raise(it)
        }
    }

    context(_: Raise<WalletResponseValidationError>)
    private suspend fun submit(
        presentation: RequestObjectRetrieved,
        responseObject: AuthorisationResponseTO,
    ): Pair<Submitted, WalletResponseAcceptedTO?> {
        // Submit the response
        val submitted =
            doSubmit(presentation, responseObject).also { storePresentation(it) }

        val presentationType = presentation.presentationType
        check(presentationType is PresentationType.OpenId4VP) {
            "Not applicable to ISO presentations"
        }

        val accepted =
            when (presentationType) {
                is PresentationType.OpenId4VP.OverRedirects -> {
                    when (val getWalletResponseMethod = presentationType.getWalletResponseMethod) {
                        is GetWalletResponseMethod.Redirect -> {
                            with(createQueryWalletResponseRedirectUri) {
                                requireNotNull(submitted.responseCode) { "ResponseCode expected in Submitted state but not found" }
                                val redirectUri = getWalletResponseMethod.redirectUri(submitted.responseCode)
                                WalletResponseAcceptedTO(redirectUri.toString())
                            }
                        }

                        GetWalletResponseMethod.Poll -> {
                            null
                        }
                    }
                }

                is PresentationType.OpenId4VP.OverDCApi -> {
                    null
                }
            }
        return submitted to accepted
    }

    context(_: Raise<WalletResponseValidationError>)
    private suspend fun loadPresentation(lookup: PresentationLookup): Presentation {
        val presentation =
            when (lookup) {
                is PresentationLookup.ByRequestId -> loadPresentationByRequestId(lookup.requestId)
                is PresentationLookup.ByTransactionId -> loadPresentationById(lookup.transactionId)
            }
        return ensureNotNull(presentation) { PresentationNotFound }
    }

    context(_: Raise<WalletResponseValidationError>)
    private suspend fun responseObject(
        walletResponse: AuthorisationResponse.OpenId4VP,
        presentationType: PresentationType.OpenId4VP,
        nonce: Nonce,
    ): AuthorisationResponseTO =
        when (presentationType) {
            is PresentationType.OpenId4VP.OverRedirects -> {
                when (val responseMode = presentationType.responseMode) {
                    ResponseMode.OpenId4VP.OverRedirects.DirectPost -> {
                        ensure(walletResponse is AuthorisationResponse.OpenId4VP.OverRedirects.DirectPost) {
                            UnexpectedResponseMode(
                                presentationType.requestId,
                                expected = ResponseModeType.DirectPost,
                                actual = walletResponse.responseModeType,
                            )
                        }
                        walletResponse.response
                    }

                    is ResponseMode.OpenId4VP.OverRedirects.DirectPostJwt -> {
                        when (walletResponse) {
                            is AuthorisationResponse.OpenId4VP.OverRedirects.DirectPost -> {
                                ensure(walletResponse.isErrorResponse()) {
                                    UnexpectedResponseMode(
                                        presentationType.requestId,
                                        expected = ResponseModeType.DirectPostJwt,
                                        actual = ResponseModeType.DirectPost,
                                    )
                                }
                                walletResponse.response
                            }

                            is AuthorisationResponse.OpenId4VP.OverRedirects.DirectPostJwt -> {
                                verifyEncryptedResponse(
                                    ephemeralResponseEncryptionKey = responseMode.ephemeralResponseEncryptionKey,
                                    encryptedResponse = walletResponse.encryptedResponse,
                                    apv = nonce,
                                )
                            }

                            else -> {
                                raise(
                                    UnexpectedResponseMode(
                                        presentationType.requestId,
                                        expected = ResponseModeType.DirectPostJwt,
                                        actual = walletResponse.responseModeType,
                                    ),
                                )
                            }
                        }
                    }
                }
            }

            is PresentationType.OpenId4VP.OverDCApi -> {
                when (val responseMode = presentationType.responseMode) {
                    is ResponseMode.OpenId4VP.OverDCApi.DCApiJwt -> {
                        when (walletResponse) {
                            is AuthorisationResponse.OpenId4VP.OverDCApi.DCApi -> {
                                ensure(walletResponse.isErrorResponse()) {
                                    UnexpectedResponseMode(
                                        null,
                                        expected = ResponseModeType.DCApiJwt,
                                        actual = ResponseModeType.DCApi,
                                    )
                                }
                                walletResponse.response
                            }

                            is AuthorisationResponse.OpenId4VP.OverDCApi.DCApiJwt -> {
                                verifyEncryptedResponse(
                                    ephemeralResponseEncryptionKey = responseMode.ephemeralResponseEncryptionKey,
                                    encryptedResponse = walletResponse.encryptedResponse,
                                    apv = nonce,
                                )
                            }

                            else -> {
                                raise(
                                    UnexpectedResponseMode(
                                        null,
                                        expected = ResponseModeType.DCApiJwt,
                                        actual = walletResponse.responseModeType,
                                    ),
                                )
                            }
                        }
                    }
                }
            }
        }

    context(_: Raise<WalletResponseValidationError>)
    private suspend fun doSubmit(
        presentation: RequestObjectRetrieved,
        responseObject: AuthorisationResponseTO,
    ): Submitted {
        // add the wallet response to the presentation
        val walletResponse =
            responseObject.toDomain(
                presentation,
                validateVerifiablePresentation,
                verifierConfig.clientMetaData.vpFormatsSupported,
            )

        val presentationType = presentation.presentationType
        check(presentationType is PresentationType.OpenId4VP) {
            "Not applicable to ISO Presentations"
        }

        val responseCode =
            when (presentationType) {
                is PresentationType.OpenId4VP.OverDCApi -> {
                    null
                }

                is PresentationType.OpenId4VP.OverRedirects -> {
                    // Verify response `state` is RequestId
                    ensure(presentation.presentationType.requestId.value == responseObject.state) { IncorrectState }
                    when (presentationType.getWalletResponseMethod) {
                        GetWalletResponseMethod.Poll -> null
                        is GetWalletResponseMethod.Redirect -> generateResponseCode()
                    }
                }
            }

        return presentation.submit(clock, walletResponse, responseCode)
    }

    private suspend fun logWalletResponsePosted(
        p: Submitted,
        accepted: WalletResponseAcceptedTO?,
    ) {
        val event =
            PresentationEvent.WalletResponsePosted(p.id, p.submittedAt, p.walletResponse.toTO(), accepted)
        publishPresentationEvent(event)
    }

    private suspend fun logFailure(
        presentation: RequestObjectRetrieved,
        responseObject: AuthorisationResponseTO?,
        cause: WalletResponseValidationError,
    ) {
        val event =
            PresentationEvent.WalletFailedToPostResponse(
                presentation.id,
                clock.now(),
                cause,
                responseObject?.vpToken,
            )
        publishPresentationEvent(event)
    }
}

private fun DCQL.satisfiedBy(response: Map<QueryId, List<VerifiablePresentation>>): Boolean =
    credentialSets
        ?.value
        ?.filter { credentialSet -> credentialSet.requiredOrDefault }
        ?.map { credentialSet -> credentialSet.options.any { option -> response.keys.containsAll(option.value) } }
        ?.fold(true, Boolean::and)
        ?: response.keys.containsAll(credentials.ids)

private val AuthorisationResponse.OpenId4VP.responseModeType: ResponseModeType
    get() =
        when (this) {
            is AuthorisationResponse.OpenId4VP.OverRedirects.DirectPost -> ResponseModeType.DirectPost
            is AuthorisationResponse.OpenId4VP.OverRedirects.DirectPostJwt -> ResponseModeType.DirectPostJwt
            is AuthorisationResponse.OpenId4VP.OverDCApi.DCApi -> ResponseModeType.DCApi
            is AuthorisationResponse.OpenId4VP.OverDCApi.DCApiJwt -> ResponseModeType.DCApiJwt
        }
private val AuthorisationResponse.OpenId4VP.encryptedResponseOrNull: Jwt?
    get() =
        when (this) {
            is AuthorisationResponse.OpenId4VP.OverRedirects.DirectPost -> null
            is AuthorisationResponse.OpenId4VP.OverRedirects.DirectPostJwt -> encryptedResponse
            is AuthorisationResponse.OpenId4VP.OverDCApi.DCApi -> null
            is AuthorisationResponse.OpenId4VP.OverDCApi.DCApiJwt -> encryptedResponse
        }

private val AuthorisationResponse.OpenId4VP.vpTokenOrNull: JsonObject?
    get() =
        when (this) {
            is AuthorisationResponse.OpenId4VP.OverRedirects.DirectPost -> response.vpToken
            is AuthorisationResponse.OpenId4VP.OverRedirects.DirectPostJwt -> null
            is AuthorisationResponse.OpenId4VP.OverDCApi.DCApi -> response.vpToken
            is AuthorisationResponse.OpenId4VP.OverDCApi.DCApiJwt -> null
        }

private val RequestObjectRetrieved.ephemeralResponseEncryptionKeyOrNull: JWK?
    get() =
        when (val presentationType = this.presentationType) {
            is PresentationType.OpenId4VP.OverRedirects -> {
                when (val responseMode = presentationType.responseMode) {
                    ResponseMode.OpenId4VP.OverRedirects.DirectPost -> null
                    is ResponseMode.OpenId4VP.OverRedirects.DirectPostJwt -> responseMode.ephemeralResponseEncryptionKey
                }
            }

            is PresentationType.OpenId4VP.OverDCApi -> {
                when (val responseMode = presentationType.responseMode) {
                    is ResponseMode.OpenId4VP.OverDCApi.DCApiJwt -> responseMode.ephemeralResponseEncryptionKey
                }
            }

            is PresentationType.ISO.OverDCApi -> {
                when (val responseMode = presentationType.responseMode) {
                    is ResponseMode.ISO.OverDCApi.DCApi -> responseMode.ephemeralResponseEncryptionKey
                }
            }
        }

private fun Logger.debug(
    lookup: PresentationLookup,
    walletResponse: AuthorisationResponse.OpenId4VP,
) {
    when (lookup) {
        is PresentationLookup.ByRequestId -> {
            debug(
                "RequestId({}):: Wallet posted response. \nEncrypted response: '{}', \nVP Token: '{}'",
                lookup.requestId.value,
                walletResponse.encryptedResponseOrNull,
                walletResponse.vpTokenOrNull,
            )
        }

        is PresentationLookup.ByTransactionId -> {
            debug(
                "TransactionId({}):: Wallet posted response. \nEncrypted response: '{}', \nVP Token: '{}'",
                lookup.transactionId.value,
                walletResponse.encryptedResponseOrNull,
                walletResponse.vpTokenOrNull,
            )
        }
    }
}

private fun Logger.debug(
    lookup: PresentationLookup.ByTransactionId,
    walletResponse: AuthorisationResponse.ISO.OverDCApi,
) {
    debug(
        "TransactionId({}):: Wallet posted response. \nEncrypted response: '{}'",
        lookup.transactionId.value,
        walletResponse.response.encryptedResponse,
    )
}

private fun Logger.debug(
    presentation: RequestObjectRetrieved,
    walletResponse: AuthorisationResponse.OpenId4VP,
) {
    debug(
        "TransactionId({}):: Wallet posted response. \nEncrypted response: '{}', \nDecryption Key: '{}', \nVP Token: '{}'",
        presentation.id.value,
        walletResponse.encryptedResponseOrNull,
        presentation.ephemeralResponseEncryptionKeyOrNull?.toJSONString(),
        walletResponse.vpTokenOrNull,
    )
}

private fun Logger.debug(
    presentation: RequestObjectRetrieved,
    walletResponse: AuthorisationResponse.ISO.OverDCApi,
) {
    debug(
        "TransactionId({}):: Wallet posted response. \nEncrypted response: '{}', \nDecryption Key: '{}'",
        presentation.id.value,
        walletResponse.response.encryptedResponse,
        presentation.ephemeralResponseEncryptionKeyOrNull?.toJSONString(),
    )
}

private fun Logger.info(
    transactionId: TransactionId,
    authorizationResponse: AuthorisationResponseTO,
) {
    info(
        "TransactionId({}):: Wallet posted response. \nVP Token: '{}'",
        transactionId.value,
        authorizationResponse.vpToken,
    )
}

private fun InvalidDeviceResponse(error: DeviceResponseError): InvalidDeviceResponse {
    val error =
        when (error) {
            DeviceResponseError.CannotBeDecoded -> {
                "DeviceResponse cannot be decoded"
            }

            is DeviceResponseError.InvalidDocuments -> {
                val deviceResponseErrors =
                    error.invalidDocuments.joinToString { invalidDocument ->
                        val documentErrors = invalidDocument.errors.joinToString()
                        "Document at index '${invalidDocument.index}' with docType '${invalidDocument.documentType}' " +
                            "contains the following errors: '$documentErrors'"
                    }

                "DeviceResponse contains invalid documents: $deviceResponseErrors"
            }

            is DeviceResponseError.NotOkDeviceResponseStatus -> {
                "Unexpected DeviceResponse status: '${error.status}'"
            }
        }

    return InvalidDeviceResponse(error)
}
