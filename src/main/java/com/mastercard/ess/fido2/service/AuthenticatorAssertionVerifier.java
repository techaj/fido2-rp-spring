/*
 * Copyright (c) 2018 Mastercard
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and limitations under the License.
 */

package com.mastercard.ess.fido2.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.mastercard.ess.fido2.database.FIDO2AuthenticationEntity;
import com.mastercard.ess.fido2.database.FIDO2RegistrationEntity;
import com.mastercard.ess.fido2.service.processors.AssertionFormatProcessor;
import com.mastercard.ess.fido2.service.processors.AssertionProcessorFactory;
import java.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

@Service
public class AuthenticatorAssertionVerifier {
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticatorAssertionVerifier.class);

    @Autowired
    @Qualifier("base64Decoder")
    private Base64.Decoder base64Decoder;


    @Autowired
    AssertionProcessorFactory assertionProcessorFactory;


    public void verifyAuthenticatorAssertionResponse(JsonNode response, FIDO2RegistrationEntity registration, FIDO2AuthenticationEntity authenticationEntity) {
        JsonNode authenticatorResponse = response;
        String base64AuthenticatorData = authenticatorResponse.get("authenticatorData").asText();
        String clientDataJson = authenticatorResponse.get("clientDataJSON").asText();
        String signature = authenticatorResponse.get("signature").asText();

        LOGGER.info("Authenticator data {}", base64AuthenticatorData);
        AssertionFormatProcessor assertionProcessor = assertionProcessorFactory.getCommandProcessor(registration.getAttestationType());
        assertionProcessor.process(base64AuthenticatorData, signature, clientDataJson, registration, authenticationEntity);
    }
}
