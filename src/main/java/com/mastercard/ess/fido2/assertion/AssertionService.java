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
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mastercard.ess.fido2.database.FIDO2AuthenticationEntity;
import com.mastercard.ess.fido2.database.FIDO2AuthenticationRepository;
import com.mastercard.ess.fido2.database.FIDO2RegistrationEntity;
import com.mastercard.ess.fido2.database.FIDO2RegistrationRepository;
import com.mastercard.ess.fido2.service.AuthenticatorAssertionVerifier;
import com.mastercard.ess.fido2.service.ChallengeGenerator;
import com.mastercard.ess.fido2.service.ChallengeVerifier;
import com.mastercard.ess.fido2.service.CommonVerifiers;
import com.mastercard.ess.fido2.service.DomainVerifier;
import com.mastercard.ess.fido2.service.Fido2RPRuntimeException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.Base64;
import java.util.List;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
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
    ChallengeGenerator challengeGenerator;
    @Autowired
    private ObjectMapper om;
    @Autowired
    @Qualifier("base64UrlEncoder")
    private Base64.Encoder base64UrlEncoder;
    @Autowired
    @Qualifier("base64UrlDecoder")
    private Base64.Decoder base64UrlDecoder;
    @Autowired
    CommonVerifiers commonVerifiers;

    @Value("${rp.domain}")
    private String rpDomain;

    JsonNode options(@RequestBody JsonNode params) {
        LOGGER.info("options {}", params);
        return assertionOptions(params);
    }


    JsonNode verify(@RequestBody JsonNode params) {
        LOGGER.info("authenticateResponse {}", params);
        ObjectNode authenticateResponseNode = om.createObjectNode();
        JsonNode response = params.get("response");

        commonVerifiers.verifyBasicPayload(params);
        String keyId = commonVerifiers.verifyThatString(params.get("id"));
        commonVerifiers.verifyThatString(params.get("rawId"));

        JsonNode clientDataJSONNode;
        try {
            clientDataJSONNode = om.readTree(new String(base64UrlDecoder.decode(params.get("response").get("clientDataJSON").asText()), Charset.forName("UTF-8")));
        } catch (IOException e) {
            throw new Fido2RPRuntimeException("Can't parse message");
        } catch (Exception e) {
            throw new Fido2RPRuntimeException("Invalid assertion data");
        }

        commonVerifiers.verifyClientJSON(clientDataJSONNode);
        commonVerifiers.verifyClientJSONTypeIsGet(clientDataJSONNode);

        String clientDataChallenge = clientDataJSONNode.get("challenge").asText();
        String clientDataOrigin = clientDataJSONNode.get("origin").asText();

        FIDO2AuthenticationEntity authenticationEntity = authenticationsRepository.findByChallenge(clientDataChallenge).orElseThrow(() -> new Fido2RPRuntimeException("Can't find matching request"));

        //challengeVerifier.verifyChallenge(authenticationEntity.getChallenge(), challenge, clientDataChallenge);
        domainVerifier.verifyDomain(authenticationEntity.getDomain(), clientDataOrigin);


        FIDO2RegistrationEntity registration = registrationsRepository.findByPublicKeyId(keyId).orElseThrow(() -> new Fido2RPRuntimeException("Couldn't find the key"));
        authenticatorAuthorizationVerifier.verifyAuthenticatorAssertionResponse(response, registration, authenticationEntity);


        authenticationEntity.setW3cAuthenticatorAssertionResponse(response.toString());
        authenticationsRepository.save(authenticationEntity);
        registrationsRepository.save(registration);
        authenticateResponseNode.put("status", "ok");
        authenticateResponseNode.put("errorMessage", "");
        return authenticateResponseNode;
    }


    private JsonNode assertionOptions(JsonNode params) {
        LOGGER.info("assertionOptions {}", params);
        String username = params.get("username").asText();
        String userVerification = "required";
        if (params.hasNonNull("userVerification")) {
            userVerification = commonVerifiers.verifyUserVerification(params.get("userVerification"));
        }

        LOGGER.info("Options {} ", username);

        ObjectNode assertionOptionsResponseNode = om.createObjectNode();
        List<FIDO2RegistrationEntity> registrations = registrationsRepository.findAllByUsername(username);


        String challenge = challengeGenerator.getChallenge();
        assertionOptionsResponseNode.put("challenge", challenge);

        ObjectNode credentialUserEntityNode = assertionOptionsResponseNode.putObject("user");
        credentialUserEntityNode.put("name", username);

        ObjectNode publicKeyCredentialRpEntityNode = assertionOptionsResponseNode.putObject("rp");
        publicKeyCredentialRpEntityNode.put("name", "ACME Dawid");
        publicKeyCredentialRpEntityNode.put("id", rpDomain);
        ArrayNode publicKeyCredentialDescriptors = assertionOptionsResponseNode.putArray("allowCredentials");

        for (FIDO2RegistrationEntity registration : registrations) {
            if (StringUtils.isEmpty(registration.getPublicKeyId())) {
                throw new Fido2RPRuntimeException("Can't find associated key. Have you registered");
            }
            ObjectNode publicKeyCredentialDescriptorNode = publicKeyCredentialDescriptors.addObject();
            publicKeyCredentialDescriptorNode.put("type", "public-key");
            ArrayNode authenticatorTransportNode = publicKeyCredentialDescriptorNode.putArray("transports");
            authenticatorTransportNode.add("usb").add("ble").add("nfc");
            publicKeyCredentialDescriptorNode.put("id", registration.getPublicKeyId());
        }


        assertionOptionsResponseNode.put("status", "ok");
        assertionOptionsResponseNode.put("userVerification", userVerification);

        String host;
        try {
            host = new URL(rpDomain).getHost();
        } catch (MalformedURLException e) {
            host = rpDomain;
        }

        FIDO2AuthenticationEntity entity = new FIDO2AuthenticationEntity();
        entity.setUsername(username);
        entity.setChallenge(challenge);
        entity.setDomain(host);
        entity.setW3cCredentialRequestOptions(assertionOptionsResponseNode.toString());

        authenticationsRepository.save(entity);
        assertionOptionsResponseNode.put("status", "ok");
        assertionOptionsResponseNode.put("errorMessage", "");
        return assertionOptionsResponseNode;
    }
}


