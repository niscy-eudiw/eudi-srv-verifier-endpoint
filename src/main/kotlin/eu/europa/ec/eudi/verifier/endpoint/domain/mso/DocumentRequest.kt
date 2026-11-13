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

package eu.europa.ec.eudi.verifier.endpoint.domain.mso

import arrow.core.NonEmptyList
import arrow.core.serialization.NonEmptyListSerializer
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.DataElementIdentifier
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.NameSpace
import eu.europa.ec.eudi.verifier.endpoint.domain.MsoMdocDocType
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.UseSerializers

@Serializable
data class DocumentRequest(
    @Required @SerialName("doc_type") val docType: MsoMdocDocType,
    @Required @SerialName("data_elements") val dataElements: Map<NameSpace, NonEmptyList<DataElementRequest>>,
) {
    init {
        require(dataElements.isNotEmpty()) {
            "dataElements must not be empty"
        }
    }
}

@Serializable
data class DataElementRequest(
    @Required val identifier: DataElementIdentifier,
    @SerialName("intent_to_retain") val intentToRetain: Boolean? = null,
)

val DataElementRequest.intentToRetainOrDefault: Boolean
    get() = intentToRetain ?: false
