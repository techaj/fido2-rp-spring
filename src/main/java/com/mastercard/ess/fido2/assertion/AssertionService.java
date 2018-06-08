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

package com.mastercard.ess.fido2.assertion;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mastercard.ess.fido2.database.FIDO2AuthenticationEntity;
import com.mastercard.ess.fido2.database.FIDO2AuthenticationRepository;
import com.mastercard.ess.fido2.database.FIDO2RegistrationEntity;
import com.mastercard.ess.fido2.database.FIDO2RegistrationRepository;
import com.mastercard.ess.fido2.service.AuthenticatorAssertionVerifier;
import com.mastercard.ess.fido2.service.ChallengeVerifier;
import com.mastercard.ess.fido2.service.DomainVerifier;
import com.mastercard.ess.fido2.service.Fido2RPRuntimeException;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;

@Service
class AssertionService {
    private static final Logger LOGGER = LoggerFactory.getLogger(AssertionService.class);
    @Autowired
    ChallengeVerifier challengeVerifier;
    @Autowired
    DomainVerifier domainVerifier;
    @Autowired
    FIDO2RegistrationRepository registrationsRepository;
    @Autowired
    FIDO2AuthenticationRepository authenticationsRepository;
    @Autowired
    AuthenticatorAssertionVerifier authenticatorAuthorizationVerifier;
    @Autowired
    private ObjectMapper om;
    @Autowired
    @Qualifier("base64UrlEncoder")
    private Base64.Encoder base64UrlEncoder;
    @Autowired
    @Qualifier("base64UrlDecoder")
    private Base64.Decoder base64UrlDecoder;

    JsonNode verify(@RequestBody JsonNode params) {
        LOGGER.info("authenticateResponse {}", params);
        JsonNode request = params.get("request");
        JsonNode response = params.get("response");
        String challenge = request.get("challenge").asText();
        String username = request.get("user").get("name").asText();
        String domain = params.get("request").get("rp").get("id").asText();

        JsonNode clientDataJSONNode;
        try {
            clientDataJSONNode = om.readTree(new String(base64UrlDecoder.decode(params.get("response").get("response").get("clientDataJSON").asText()), Charset.forName("UTF-8")));
        } catch (IOException e) {
            throw new Fido2RPRuntimeException("Can't parse message");
        } catch (Exception e) {
            throw new Fido2RPRuntimeException("Invalid assertion data");
        }


        FIDO2AuthenticationEntity authenticationEntity = authenticationsRepository.findByChallenge(challenge).orElseThrow(() -> new Fido2RPRuntimeException("Can't find matching request"));

        String clientDataChallenge = clientDataJSONNode.get("challenge").asText();
        String clientDataOrigin = clientDataJSONNode.get("origin").asText();

        challengeVerifier.verifyChallenge(authenticationEntity.getChallenge(), challenge, clientDataChallenge);
        domainVerifier.verifyDomain(authenticationEntity.getDomain(), clientDataOrigin);

        String keyId = response.get("id").asText();
        FIDO2RegistrationEntity registration = registrationsRepository.findByPublicKeyId(keyId).orElseThrow(() -> new Fido2RPRuntimeException("Couldn't find the key"));
        authenticatorAuthorizationVerifier.verifyAuthenticatorAssertionResponse(response, registration);

        authenticationEntity.setW3cAuthenticatorAssertionResponse(response.toString());
        authenticationsRepository.save(authenticationEntity);
        return params;
    }

}
