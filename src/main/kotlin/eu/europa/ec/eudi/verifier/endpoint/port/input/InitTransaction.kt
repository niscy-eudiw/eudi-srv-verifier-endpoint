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
@file:UseSerializers(NonEmptyListSerializer::class)

package eu.europa.ec.eudi.verifier.endpoint.port.input

import arrow.core.*
import arrow.core.raise.Raise
import arrow.core.raise.catch
import arrow.core.raise.context.ensure
import arrow.core.raise.context.ensureNotNull
import arrow.core.raise.context.raise
import arrow.core.serialization.NonEmptyListSerializer
import com.eygraber.uri.Uri
import com.eygraber.uri.Url
import com.eygraber.uri.toURI
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.oauth2.sdk.id.Audience
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.decodeAs
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.x509.isSelfSigned
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.domain.EmbedOption
import eu.europa.ec.eudi.verifier.endpoint.domain.EncryptionRequirement
import eu.europa.ec.eudi.verifier.endpoint.domain.mso.DocumentRequest
import eu.europa.ec.eudi.verifier.endpoint.domain.mso.dcapi.DCApiRequest
import eu.europa.ec.eudi.verifier.endpoint.domain.rqes.QesApproval
import eu.europa.ec.eudi.verifier.endpoint.domain.rqes.QesRequest
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.CreateQueryWalletResponseRedirectUri
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.GenerateRequestId
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.GenerateTransactionId
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.CreateJar
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.GenerateEphemeralEncryptionKeyPair
import eu.europa.ec.eudi.verifier.endpoint.port.out.mso.dcapi.CreateDCApiRequest
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PublishPresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.StorePresentation
import eu.europa.ec.eudi.verifier.endpoint.port.out.qrcode.GenerateQrCode
import eu.europa.ec.eudi.verifier.endpoint.port.out.qrcode.Pixels.Companion.pixels
import eu.europa.ec.eudi.verifier.endpoint.port.out.qrcode.by
import eu.europa.ec.eudi.verifier.endpoint.port.out.x509.ParsePemEncodedX509Certificates
import kotlinx.serialization.*
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import java.net.URI
import java.net.URL
import java.security.cert.X509Certificate

/**
 * Specifies request_uri_method for a request
 */
@Serializable
enum class RequestUriMethodTO {
    @SerialName(OpenId4VPSpec.REQUEST_URI_METHOD_GET)
    Get,

    @SerialName(OpenId4VPSpec.REQUEST_URI_METHOD_POST)
    Post,

    @SerialName("post_get")
    PostOrGet,
}

/**
 * Specifies whether a property of a request will be provided by value or by reference.
 */
@Serializable
enum class EmbedModeTO {
    @SerialName("by_value")
    ByValue,

    @SerialName("by_reference")
    ByReference,
}

/**
 * The Profile to activate for a Transaction.
 */
@Serializable
enum class ProfileTO {
    /**
     * Initialize a Transaction per OpenId4VP. No constraints are enforced.
     */
    @SerialName("openid4vp")
    OpenId4VP,

    /**
     * Initialize a Transaction per HAIP. Extra constraints are enforced.
     */
    @SerialName("haip")
    HAIP,
}

@Serializable
data class InitOpenId4VPOverRedirectsTransactionTO(
    @SerialName(OpenId4VPSpec.DCQL_QUERY) val dcqlQuery: DCQL? = null,
    @SerialName(OpenId4VPSpec.NONCE) val nonce: String? = null,
    @SerialName(RFC6749.RESPONSE_MODE) val responseMode: ResponseModeTO? = null,
    @SerialName("jar_mode") val jarMode: EmbedModeTO? = null,
    @SerialName(OpenId4VPSpec.REQUEST_URI_METHOD) val requestUriMethod: RequestUriMethodTO? = null,
    @SerialName("wallet_response_redirect_uri_template") val redirectUriTemplate: String? = null,
    @SerialName(OpenId4VPSpec.TRANSACTION_DATA) val transactionData: List<JsonObject>? = null,
    @SerialName("issuer_chain") val issuerChain: String? = null,
    @SerialName("authorization_request_scheme") val authorizationRequestScheme: String? = null,
    @SerialName("authorization_request_uri") val authorizationRequestUri: String? = null,
    @SerialName("profile") val profile: ProfileTO? = ProfileTO.OpenId4VP,
    @SerialName("intended_use_id") val intendedUseId: String? = null,
    @SerialName("registration_certificate") val registrationCertificate: String? = null,
    @Transient val output: Output = Output.Json,
) {
    /**
     * Specifies the response_mode for a request
     */
    @Serializable
    enum class ResponseModeTO {
        @SerialName(OpenId4VPSpec.RESPONSE_MODE_DIRECT_POST)
        DirectPost,

        @SerialName(OpenId4VPSpec.RESPONSE_MODE_DIRECT_POST_JWT)
        DirectPostJwt,
    }
}

private val InitOpenId4VPOverRedirectsTransactionTO.profileOrDefault: ProfileTO
    get() = profile ?: ProfileTO.OpenId4VP

/**
 * Possible validation errors of caller's input
 */
sealed interface ValidationError {
    data object MissingPresentationQuery : ValidationError

    data object MissingNonce : ValidationError

    data object InvalidWalletResponseTemplate : ValidationError

    data object InvalidTransactionData : ValidationError

    data object UnsupportedFormat : ValidationError

    data object InvalidIssuerChain : ValidationError

    data object OnlyRegistrationCertificateOrIntendedUseIdMustBeProvided : ValidationError

    data object MissingRegistrationCertificate : ValidationError

    data object InvalidRegistrationCertificate : ValidationError

    data object UnknownIntendedUseId : ValidationError

    data object ContainsBothAuthorizationRequestUriAndAuthorizationRequestScheme : ValidationError

    data object InvalidAuthorizationRequestUri : ValidationError

    data object InvalidAuthorizationRequestScheme : ValidationError

    sealed interface HaipNotSupported : ValidationError {
        data object SdJwtVcOrMsoMdocMustBeSupported : HaipNotSupported

        data object JwsAlgorithmES256MustBeSupported : HaipNotSupported

        data object ClientIdPrefixX509HashMustBeUsed : HaipNotSupported

        data object SelfSignedCertificateMustNotBeUsed : HaipNotSupported

        data object EncryptionAlgorithmECDHESMustBeSupported : HaipNotSupported

        data object EncryptionMethodsA128GCMAndA256GCMMustBeSupported : HaipNotSupported

        data object ResponseModeDirectPostJwtMustBeUsed : HaipNotSupported

        data object AuthorizationRequestMustBeProvidedByReference : HaipNotSupported
    }

    data object InsufficientNonceEntropy : ValidationError
}

enum class Output {
    Json,
    QrCode,
}

sealed interface InitOpenId4VPOverRedirectsTransactionResponse {
    /**
     * The return value of successfully [initializing][InitTransaction] a [Presentation] as a QR Code
     *
     */
    data class QrCode(
        val qrCode: ByteArray,
        val transactionId: TransactionId,
        val authorizationRequestUri: String,
    ) : InitOpenId4VPOverRedirectsTransactionResponse {
        override fun equals(other: Any?): Boolean =
            other is QrCode &&
                qrCode.contentEquals(other.qrCode) &&
                transactionId == other.transactionId &&
                authorizationRequestUri == other.authorizationRequestUri

        override fun hashCode(): Int {
            var result = qrCode.contentHashCode()
            result = 31 * result + transactionId.hashCode()
            result = 31 * result + authorizationRequestUri.hashCode()
            return result
        }
    }

    /**
     * The return value of successfully [initializing][InitTransaction] a [Presentation] as a JSON
     *
     */
    @Serializable
    data class JwtSecuredAuthorizationRequestTO(
        @Required @SerialName("transaction_id") val transactionId: TransactionId,
        @Required @SerialName(RFC6749.CLIENT_ID) val clientId: ClientId,
        @SerialName(RFC9101.REQUEST) val request: String?,
        @SerialName(RFC9101.REQUEST_URI) val requestUri: String?,
        @SerialName(OpenId4VPSpec.REQUEST_URI_METHOD) val requestUriMethod: RequestUriMethodTO?,
        @SerialName("authorization_request_uri") val authorizationRequestUri: String,
    ) : InitOpenId4VPOverRedirectsTransactionResponse {
        companion object {
            fun byValue(
                transactionId: TransactionId,
                clientId: ClientId,
                request: String,
                authorizationRequestUri: URI,
            ): JwtSecuredAuthorizationRequestTO =
                JwtSecuredAuthorizationRequestTO(
                    transactionId,
                    clientId,
                    request,
                    null,
                    null,
                    authorizationRequestUri.toString(),
                )

            fun byReference(
                transactionId: TransactionId,
                clientId: ClientId,
                requestUri: URL,
                requestUriMethod: RequestUriMethodTO,
                authorizationRequestUri: URI,
            ): JwtSecuredAuthorizationRequestTO =
                JwtSecuredAuthorizationRequestTO(
                    transactionId,
                    clientId,
                    null,
                    requestUri.toExternalForm(),
                    requestUriMethod,
                    authorizationRequestUri.toString(),
                )
        }
    }
}

/**
 * This is a use case that initializes the [Presentation] process.
 *
 * Use case will initialize a [Presentation] process
 */
interface InitTransaction {
    context(_: Raise<ValidationError>)
    suspend operator fun invoke(data: InitOpenId4VPOverRedirectsTransactionTO): InitOpenId4VPOverRedirectsTransactionResponse

    context(_: Raise<ValidationError>)
    suspend operator fun invoke(data: InitOpenId4VPOverDCApiTransactionTO): InitOpenId4VPOverDCApiTransactionResponseTO

    context(_: Raise<ValidationError>)
    suspend operator fun invoke(data: InitISOOverDCApiTransactionTO): InitISOOverDCApiTransactionResponseTO
}

/**
 * The default implementation of the use case
 */
class InitTransactionLive(
    private val generateTransactionId: GenerateTransactionId,
    private val generateRequestId: GenerateRequestId,
    private val storePresentation: StorePresentation,
    private val createJar: CreateJar,
    private val verifierConfig: VerifierConfig,
    private val clock: Clock,
    private val generateEphemeralEncryptionKeyPair: GenerateEphemeralEncryptionKeyPair,
    private val requestJarByReference: EmbedOption.ByReference<RequestId>,
    private val createQueryWalletResponseRedirectUri: CreateQueryWalletResponseRedirectUri,
    private val publishPresentationEvent: PublishPresentationEvent,
    private val parsePemEncodedX509CertificateChain: ParsePemEncodedX509Certificates,
    private val generateQrCode: GenerateQrCode,
    private val createDCApiRequest: CreateDCApiRequest,
) : InitTransaction {
    context(_: Raise<ValidationError>)
    override suspend fun invoke(data: InitOpenId4VPOverRedirectsTransactionTO): InitOpenId4VPOverRedirectsTransactionResponse {
        // validate input
        val (nonce, type) =
            context(verifierConfig.transactionDataHashAlgorithm, verifierConfig.clientMetaData.vpFormatsSupported) {
                validate(
                    data.dcqlQuery,
                    data.nonce,
                    data.transactionData,
                )
            }

        val presentationType =
            PresentationType.OpenId4VP.OverRedirects(
                responseMode = responseMode(data.responseMode),
                query = type.query,
                requestUriMethod = requestUriMethod(data.requestUriMethod),
                getWalletResponseMethod = getWalletResponseMethod(data.redirectUriTemplate),
                requestId = generateRequestId(),
                transactionData = type.transactionData,
                profile = data.profileOrDefault.toProfile(),
                registrationCertificate =
                    context(verifierConfig) {
                        resolveRegistrationCertificate(data.intendedUseId, data.registrationCertificate)
                    },
            )

        val issuerChain = issuerChain(data.issuerChain)
        val jarMode = jarMode(data)

        // validate according to the selected profile
        with(presentationType.profile.validator) {
            context(verifierConfig) {
                validate(presentationType, jarMode)
            }
        }

        // create the request, which may update the presentation
        val unresolvedAuthorizationRequestUri =
            with(verifierConfig) {
                authorizationRequestUri(
                    data.authorizationRequestUri,
                    data.authorizationRequestScheme,
                )
            }

        // Initialize presentation
        val (presentation, authorizationRequest) =
            createPresentationAndAuthorizationRequest(
                jarMode,
                nonce,
                issuerChain,
                presentationType,
                unresolvedAuthorizationRequestUri,
            )
        val response = data.output.createResponse(authorizationRequest)

        storePresentation(presentation)
        logTransactionInitialized(presentation, authorizationRequest, presentationType.profile)

        return response
    }

    context(_: Raise<ValidationError>)
    override suspend fun invoke(data: InitOpenId4VPOverDCApiTransactionTO): InitOpenId4VPOverDCApiTransactionResponseTO {
        // validate input
        val (nonce, type) =
            context(verifierConfig.transactionDataHashAlgorithm, verifierConfig.clientMetaData.vpFormatsSupported) {
                validate(
                    data.dcqlQuery,
                    data.nonce,
                    data.transactionData,
                )
            }

        val issuerChain = issuerChain(data.issuerChain)
        val origin = data.origin
        val expectedOrigins = data.expectedOrigins ?: nonEmptyListOf(origin)

        val presentationType =
            PresentationType.OpenId4VP.OverDCApi(
                ResponseMode.OpenId4VP.OverDCApi.DCApiJwt(
                    generateEphemeralEncryptionKeyPair(),
                ),
                type.query,
                origin,
                expectedOrigins,
                type.transactionData,
                context(verifierConfig) {
                    resolveRegistrationCertificate(data.intendedUseId, data.registrationCertificate)
                },
            )

        // validate according to the selected profile
        with(Profile.ETSI119472Part2.validator) {
            context(verifierConfig) {
                validate(presentationType, EmbedOption.ByValue)
            }
        }

        // Initialize presentation
        val presentation =
            Presentation.RequestObjectRetrieved(
                id = generateTransactionId(),
                initiatedAt = clock.now(),
                presentationType = presentationType,
                requestObjectRetrievedAt = clock.now(),
                nonce = nonce,
                issuerChain = issuerChain,
            )

        val jar =
            createJar(
                clock.now(),
                presentationType,
                presentation.nonce,
                null,
                Audience("https://self-issued.me/v2"),
                EncryptionRequirement.NotRequired,
            )

        storePresentation(presentation)
        logTransactionInitialized(presentation, jar)

        return InitOpenId4VPOverDCApiTransactionResponseTO(
            jar,
            presentation.id,
        )
    }

    context(_: Raise<ValidationError>)
    override suspend fun invoke(data: InitISOOverDCApiTransactionTO): InitISOOverDCApiTransactionResponseTO {
        val ephemeralResponseEncryptionKey =
            ECKeyGenerator(
                Curve.parse(Iso180137.ENCRYPTION_PARAMETERS_RECIPIENT_PUBLIC_KEY_CURVE),
            ).generate()
        val responseMode = ResponseMode.ISO.OverDCApi.DCApi(ephemeralResponseEncryptionKey)
        val presentationType =
            PresentationType.ISO.OverDCApi(
                responseMode,
                data.documentRequests,
                data.origin,
            )

        val nonce = Nonce.iso180137(data.nonce) { ValidationError.InsufficientNonceEntropy }
        val issuerChain = issuerChain(data.issuerChain)

        val initiatedAt = clock.now()
        val presentation =
            Presentation.RequestObjectRetrieved(
                generateTransactionId(),
                initiatedAt,
                presentationType,
                initiatedAt,
                nonce,
                issuerChain,
            )

        val dcApiRequest = createDCApiRequest(presentation)

        storePresentation(presentation)
        logTransactionInitialized(presentation, dcApiRequest)

        return InitISOOverDCApiTransactionResponseTO(presentation.id, dcApiRequest)
    }

    private suspend fun createPresentationAndAuthorizationRequest(
        jarMode: EmbedOption<RequestId>,
        nonce: Nonce,
        issuerChain: NonEmptyList<X509Certificate>?,
        presentationType: PresentationType.OpenId4VP.OverRedirects,
        unresolvedAuthorizationRequestUri: UnresolvedAuthorizationRequestUri,
    ): Pair<Presentation, InitOpenId4VPOverRedirectsTransactionResponse.JwtSecuredAuthorizationRequestTO> =
        when (jarMode) {
            is EmbedOption.ByReference -> {
                val presentation =
                    Presentation.Requested(
                        id = generateTransactionId(),
                        initiatedAt = clock.now(),
                        nonce = nonce,
                        issuerChain = issuerChain,
                        presentationType = presentationType,
                    )

                val requestUri = jarMode.buildUrl(presentation.presentationType.requestId)
                val authorizationRequest =
                    InitOpenId4VPOverRedirectsTransactionResponse.JwtSecuredAuthorizationRequestTO.byReference(
                        presentation.id,
                        verifierConfig.verifierId.clientId,
                        requestUri,
                        presentation.presentationType.requestUriMethod.toTO(),
                        unresolvedAuthorizationRequestUri
                            .resolve(
                                verifierConfig.verifierId,
                                Uri.parse(requestUri.toString()),
                                presentation.presentationType.requestUriMethod,
                            ).toURI(),
                    )
                presentation to authorizationRequest
            }

            EmbedOption.ByValue -> {
                val presentation =
                    Presentation.RequestObjectRetrieved(
                        id = generateTransactionId(),
                        initiatedAt = clock.now(),
                        presentationType = presentationType,
                        requestObjectRetrievedAt = clock.now(),
                        nonce = nonce,
                        issuerChain = issuerChain,
                    )

                val jar =
                    createJar(
                        clock.now(),
                        presentationType,
                        presentation.nonce,
                        null,
                        Audience("https://self-issued.me/v2"),
                        EncryptionRequirement.NotRequired,
                    )
                val authorizationRequest =
                    InitOpenId4VPOverRedirectsTransactionResponse.JwtSecuredAuthorizationRequestTO.byValue(
                        presentation.id,
                        verifierConfig.verifierId.clientId,
                        jar,
                        unresolvedAuthorizationRequestUri.resolve(verifierConfig.verifierId, jar).toURI(),
                    )
                presentation to authorizationRequest
            }
        }

    private suspend fun Output.createResponse(
        authorizationRequest: InitOpenId4VPOverRedirectsTransactionResponse.JwtSecuredAuthorizationRequestTO,
    ): InitOpenId4VPOverRedirectsTransactionResponse =
        when (this) {
            Output.Json -> {
                authorizationRequest
            }

            Output.QrCode -> {
                InitOpenId4VPOverRedirectsTransactionResponse.QrCode(
                    generateQrCode(authorizationRequest.authorizationRequestUri, size = (250.pixels by 250.pixels)),
                    authorizationRequest.transactionId,
                    authorizationRequest.authorizationRequestUri,
                )
            }
        }

    /**
     * Gets the JAR [RequestUriMethod] for the provided [InitOpenId4VPOverRedirectsTransactionTO].
     * If none has been provided, falls back to [VerifierConfig.requestUriMethod].
     */
    private fun requestUriMethod(requestUriMethod: RequestUriMethodTO?): RequestUriMethod =
        when (requestUriMethod) {
            RequestUriMethodTO.Get -> RequestUriMethod.Get
            RequestUriMethodTO.Post -> RequestUriMethod.Post
            RequestUriMethodTO.PostOrGet -> RequestUriMethod.PostOrGet
            null -> verifierConfig.requestUriMethod
        }

    context(_: Raise<ValidationError>)
    private fun getWalletResponseMethod(redirectUriTemplate: String?): GetWalletResponseMethod =
        redirectUriTemplate
            ?.let { template ->
                with(createQueryWalletResponseRedirectUri) {
                    ensure(template.validTemplate()) { ValidationError.InvalidWalletResponseTemplate }
                }
                GetWalletResponseMethod.Redirect(template)
            } ?: GetWalletResponseMethod.Poll

    /**
     * Gets the [ResponseMode] for the provided [InitOpenId4VPOverRedirectsTransactionTO].
     */
    private suspend fun responseMode(
        responseMode: InitOpenId4VPOverRedirectsTransactionTO.ResponseModeTO?,
    ): ResponseMode.OpenId4VP.OverRedirects {
        val httpResponseModeOption =
            when (responseMode) {
                InitOpenId4VPOverRedirectsTransactionTO.ResponseModeTO.DirectPost -> HttpResponseModeOption.DirectPost
                InitOpenId4VPOverRedirectsTransactionTO.ResponseModeTO.DirectPostJwt -> HttpResponseModeOption.DirectPostJwt
                null -> verifierConfig.defaultHttpResponseModeOption
            }

        return when (httpResponseModeOption) {
            HttpResponseModeOption.DirectPost -> {
                ResponseMode.OpenId4VP.OverRedirects.DirectPost
            }

            HttpResponseModeOption.DirectPostJwt -> {
                val responseEncryptionKey = generateEphemeralEncryptionKeyPair()
                ResponseMode.OpenId4VP.OverRedirects.DirectPostJwt(responseEncryptionKey)
            }
        }
    }

    /**
     * Gets the JAR [EmbedOption] for the provided [InitOpenId4VPOverRedirectsTransactionTO].
     * If none has been provided, falls back to [VerifierConfig.requestJarOption].
     */
    private fun jarMode(initTransaction: InitOpenId4VPOverRedirectsTransactionTO): EmbedOption<RequestId> =
        when (initTransaction.jarMode) {
            EmbedModeTO.ByValue -> EmbedOption.ByValue
            EmbedModeTO.ByReference -> requestJarByReference
            null -> verifierConfig.requestJarOption
        }

    private suspend fun logTransactionInitialized(
        presentation: Presentation,
        request: InitOpenId4VPOverRedirectsTransactionResponse.JwtSecuredAuthorizationRequestTO,
        profile: Profile,
    ) {
        val event =
            PresentationEvent.TransactionInitialized(
                presentation.id,
                presentation.initiatedAt,
                request,
                profile,
            )
        publishPresentationEvent(event)
    }

    private suspend fun logTransactionInitialized(
        presentation: Presentation.RequestObjectRetrieved,
        request: Jwt,
    ) {
        val event =
            PresentationEvent.DcApiTransactionInitialized(
                presentation.id,
                presentation.initiatedAt,
                request,
                Profile.ETSI119472Part2,
            )
        publishPresentationEvent(event)
    }

    private suspend fun logTransactionInitialized(
        presentation: Presentation.RequestObjectRetrieved,
        dcApiRequest: DCApiRequest,
    ) {
        val event =
            PresentationEvent.ISODCApiTransactionInitialized(
                presentation.id,
                presentation.initiatedAt,
                dcApiRequest,
            )
        publishPresentationEvent(event)
    }

    context(_: Raise<ValidationError.InvalidIssuerChain>)
    private fun issuerChain(issuerChain: String?): NonEmptyList<X509Certificate>? =
        catch(
            block = { issuerChain?.let { parsePemEncodedX509CertificateChain(it) } },
            catch = { raise(ValidationError.InvalidIssuerChain) },
        )
}

/**
 * Gets the [UnresolvedAuthorizationRequestUri] for the provided [authorizationRequestUri] and [authorizationRequestScheme].
 * If none has been provided, falls back to [VerifierConfig.authorizationRequestUri].
 *
 * This method considers both [authorizationRequestUri] and [authorizationRequestScheme].
 */
context(_: Raise<ValidationError>, verifierConfig: VerifierConfig)
private fun authorizationRequestUri(
    authorizationRequestUri: String?,
    authorizationRequestScheme: String?,
): UnresolvedAuthorizationRequestUri =
    when {
        null != authorizationRequestUri && null != authorizationRequestScheme -> {
            raise(ValidationError.ContainsBothAuthorizationRequestUriAndAuthorizationRequestScheme)
        }

        null != authorizationRequestUri -> {
            UnresolvedAuthorizationRequestUri.fromUri(authorizationRequestUri).getOrElse {
                raise(ValidationError.InvalidAuthorizationRequestUri)
            }
        }

        null != authorizationRequestScheme -> {
            UnresolvedAuthorizationRequestUri.fromScheme(authorizationRequestScheme).getOrElse {
                raise(ValidationError.InvalidAuthorizationRequestScheme)
            }
        }

        else -> {
            verifierConfig.authorizationRequestUri
        }
    }

context(_: Raise<ValidationError>, transactionDataHashAlgorithm: HashAlgorithm, vpFormatsSupported: VpFormatsSupported)
internal fun validate(
    dcqlQuery: DCQL?,
    nonce: String?,
    transactionData: List<JsonObject>?,
): Pair<Nonce, VpTokenRequest> {
    fun requiredQuery(): DCQL {
        ensureNotNull(dcqlQuery) { ValidationError.MissingPresentationQuery }
        ensure(
            dcqlQuery.credentials.value.all {
                val format = it.format
                vpFormatsSupported.supports(format)
            },
        ) { ValidationError.UnsupportedFormat }

        return dcqlQuery
    }

    fun requiredNonce(): Nonce {
        ensure(!nonce.isNullOrBlank()) { ValidationError.MissingNonce }
        return Nonce(nonce)
    }

    fun optionalTransactionData(query: DCQL): NonEmptyList<TransactionData>? {
        val credentialIds: List<String> by lazy {
            query.credentials.ids.map { it.value }
        }

        val hashAlgorithms: JsonArray by lazy {
            buildJsonArray {
                add(transactionDataHashAlgorithm.ianaName)
            }
        }

        return transactionData
            ?.map {
                TransactionData
                    .validate(
                        JsonObject(it + (OpenId4VPSpec.TRANSACTION_DATA_HASH_ALGORITHMS to hashAlgorithms)),
                        credentialIds,
                    ).flatMap { transactionData ->
                        Either.catch {
                            when (transactionData.type) {
                                QesApproval.TYPE -> QesApproval.serializer()
                                QesRequest.TYPE -> QesRequest.serializer()
                                else -> null
                            }?.let { deserializer -> it.decodeAs(deserializer) }
                            transactionData
                        }
                    }.getOrElse { raise(ValidationError.InvalidTransactionData) }
            }?.toNonEmptyListOrNull()
    }

    val query = requiredQuery()
    val presentationType = VpTokenRequest(query, optionalTransactionData(query))
    val nonce = requiredNonce()

    return nonce to presentationType
}

private fun RequestUriMethod.toTO(): RequestUriMethodTO =
    when (this) {
        RequestUriMethod.Get -> RequestUriMethodTO.Get
        RequestUriMethod.Post -> RequestUriMethodTO.Post
        RequestUriMethod.PostOrGet -> RequestUriMethodTO.PostOrGet
    }

private fun <T : Any, U : T> Collection<T>.containsAny(
    first: U,
    vararg rest: U,
): Boolean = first in this || rest.any { it in this }

private fun interface ProfileValidator {
    context(_: Raise<ValidationError>, config: VerifierConfig)
    suspend fun validate(
        presentationType: PresentationType.OpenId4VP,
        jarMode: EmbedOption<RequestId>,
    )

    companion object {
        val OpenId4VP = ProfileValidator { _, _ -> }
        val HAIP =
            ProfileValidator { presentationType, jarMode ->
                val config = contextOf<VerifierConfig>()
                with(config.clientMetaData.vpFormatsSupported) {
                    ensure(null != sdJwtVc || null != msoMdoc) {
                        ValidationError.HaipNotSupported.SdJwtVcOrMsoMdocMustBeSupported
                    }

                    if (null != sdJwtVc) {
                        ensure(null == sdJwtVc.sdJwtAlgorithms || JWSAlgorithm.ES256 in sdJwtVc.sdJwtAlgorithms) {
                            ValidationError.HaipNotSupported.JwsAlgorithmES256MustBeSupported
                        }
                        ensure(null == sdJwtVc.kbJwtAlgorithms || JWSAlgorithm.ES256 in sdJwtVc.kbJwtAlgorithms) {
                            ValidationError.HaipNotSupported.JwsAlgorithmES256MustBeSupported
                        }
                    }

                    if (null != msoMdoc) {
                        ensure(
                            null == msoMdoc.issuerAuthAlgorithms ||
                                msoMdoc.issuerAuthAlgorithms.containsAny(CoseAlgorithm(-7), CoseAlgorithm(-9)),
                        ) {
                            ValidationError.HaipNotSupported.JwsAlgorithmES256MustBeSupported
                        }

                        ensure(
                            null == msoMdoc.deviceAuthAlgorithms ||
                                msoMdoc.deviceAuthAlgorithms.containsAny(CoseAlgorithm(-7), CoseAlgorithm(-9)),
                        ) {
                            ValidationError.HaipNotSupported.JwsAlgorithmES256MustBeSupported
                        }
                    }
                }

                with(config.clientMetaData.responseEncryptionOption) {
                    ensure(JWEAlgorithm.ECDH_ES == algorithm) {
                        ValidationError.HaipNotSupported.EncryptionAlgorithmECDHESMustBeSupported
                    }

                    ensure(encryptionMethods.containsAll(listOf(EncryptionMethod.A128GCM, EncryptionMethod.A256GCM))) {
                        ValidationError.HaipNotSupported.EncryptionMethodsA128GCMAndA256GCMMustBeSupported
                    }
                }

                ensure(config.verifierId is VerifierId.X509Hash) {
                    ValidationError.HaipNotSupported.ClientIdPrefixX509HashMustBeUsed
                }
                ensure(
                    !config.verifierId.accessCertificate.certificate
                        .isSelfSigned(),
                ) {
                    ValidationError.HaipNotSupported.SelfSignedCertificateMustNotBeUsed
                }
                when (presentationType) {
                    is PresentationType.OpenId4VP.OverDCApi -> {
                        ensure(jarMode is EmbedOption.ByValue) {
                            ValidationError.HaipNotSupported.AuthorizationRequestMustBeProvidedByReference
                        }
                    }

                    is PresentationType.OpenId4VP.OverRedirects -> {
                        ensure(presentationType.responseMode is ResponseMode.OpenId4VP.OverRedirects.DirectPostJwt) {
                            ValidationError.HaipNotSupported.ResponseModeDirectPostJwtMustBeUsed
                        }
                        ensure(jarMode is EmbedOption.ByReference) {
                            ValidationError.HaipNotSupported.AuthorizationRequestMustBeProvidedByReference
                        }
                    }
                }
            }

        val ETSI119472Part2 =
            ProfileValidator { presentationType, jarMode ->
                HAIP.validate(presentationType, jarMode)
            }
    }
}

private fun ProfileTO.toProfile(): Profile =
    when (this) {
        ProfileTO.OpenId4VP -> Profile.OpenId4VP
        ProfileTO.HAIP -> Profile.HAIP
    }

private val Profile.validator: ProfileValidator
    get() =
        when (this) {
            Profile.OpenId4VP -> ProfileValidator.OpenId4VP
            Profile.HAIP -> ProfileValidator.HAIP
            Profile.ETSI119472Part2 -> ProfileValidator.ETSI119472Part2
        }

context(_: Raise<ValidationError>, verifierConfig: VerifierConfig)
private fun resolveRegistrationCertificate(
    intendedUseId: String? = null,
    registrationCertificate: String? = null,
): RegistrationCertificate =
    Ior
        .fromNullables(intendedUseId, registrationCertificate)
        ?.fold(
            fa = { intendedUseId ->
                ensureNotNull(verifierConfig.intendedUses.find { it.id == intendedUseId }?.registrationCertificate) {
                    ValidationError.UnknownIntendedUseId
                }
            },
            fb = { registrationCertificate ->
                catch({
                    RegistrationCertificate.parse(registrationCertificate)
                }) {
                    raise(ValidationError.InvalidRegistrationCertificate)
                }
            },
            fab = { _, _ ->
                raise(ValidationError.OnlyRegistrationCertificateOrIntendedUseIdMustBeProvided)
            },
        ) ?: raise(ValidationError.MissingRegistrationCertificate)

@Serializable
data class InitOpenId4VPOverDCApiTransactionTO(
    @Required @SerialName(OpenId4VPSpec.DCQL_QUERY) val dcqlQuery: DCQL,
    @Required @SerialName(OpenId4VPSpec.NONCE) val nonce: String,
    @SerialName(OpenId4VPSpec.TRANSACTION_DATA) val transactionData: List<JsonObject>? = null,
    @SerialName("issuer_chain") val issuerChain: String? = null,
    @Required @SerialName("origin") val origin: Url,
    @SerialName("expected_origins") val expectedOrigins: NonEmptyList<Url>? = null,
    @SerialName("intended_use_id") val intendedUseId: String? = null,
    @SerialName("registration_certificate") val registrationCertificate: String? = null,
)

@Serializable
data class InitISOOverDCApiTransactionTO(
    @Required @SerialName("documentRequests") val documentRequests: NonEmptyList<DocumentRequest>,
    @Required @SerialName("nonce") val nonce: String,
    @SerialName("issuer_chain") val issuerChain: String? = null,
    @Required @SerialName("origin") val origin: Url,
)

context(_: Raise<T>)
private fun <T : Any> Nonce.Companion.iso180137(
    value: String,
    onError: () -> T,
): Nonce {
    ensure(value.isNotBlank()) {
        onError()
    }
    ensure(value.encodeToByteArray().size >= Iso180137.ENCRYPTION_PARAMETERS_NONCE_MINIMUM_SIZE) {
        onError()
    }

    return Nonce(value)
}

@Serializable
data class InitISOOverDCApiTransactionResponseTO(
    @Required @SerialName("transaction_id") val transactionId: TransactionId,
    @Required @SerialName("dc_api_request") val dcApiRequest: DCApiRequest,
)
