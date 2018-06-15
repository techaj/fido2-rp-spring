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
import com.mastercard.ess.fido2.service.ChallengeVerifier;
import com.mastercard.ess.fido2.service.DomainVerifier;
import com.mastercard.ess.fido2.service.Fido2RPRuntimeException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.SecureRandom;
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
    private ObjectMapper om;
    @Autowired
    @Qualifier("base64UrlEncoder")
    private Base64.Encoder base64UrlEncoder;
    @Autowired
    @Qualifier("base64UrlDecoder")
    private Base64.Decoder base64UrlDecoder;

    @Value("${rp.domain}")
    private String rpDomain;

    JsonNode options(@RequestBody JsonNode params) {
        LOGGER.info("options {}", params);
        return retrieveRegistration(params);
    }


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


    private JsonNode retrieveRegistration(JsonNode params) {
        LOGGER.info("authenticate {}", params);
        String username = params.get("username").asText();

        LOGGER.info("Options {} {}", username);

        ObjectNode credentialRequestOptionsNode = om.createObjectNode();
        List<FIDO2RegistrationEntity> registrations = registrationsRepository.findAllByUsername(username);

        byte buffer[] = new byte[32];
        new SecureRandom().nextBytes(buffer);

        String challenge = base64UrlEncoder.encodeToString(buffer);
        credentialRequestOptionsNode.put("challenge", challenge);

        ObjectNode credentialUserEntityNode = credentialRequestOptionsNode.putObject("user");
        credentialUserEntityNode.put("name", username);

        ObjectNode publicKeyCredentialRpEntityNode = credentialRequestOptionsNode.putObject("rp");
        publicKeyCredentialRpEntityNode.put("name", "ACME Dawid");
        publicKeyCredentialRpEntityNode.put("id", rpDomain);
        ArrayNode publicKeyCredentialDescriptors = credentialRequestOptionsNode.putArray("allowCredentials");

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

        credentialRequestOptionsNode.put("status", "ok");
        credentialRequestOptionsNode.put("userVerification", "required");

        String host;
        try {
            host = new URL(rpDomain).getHost();
        } catch (MalformedURLException e) {
            throw new Fido2RPRuntimeException(e.getMessage());
        }

        FIDO2AuthenticationEntity entity = new FIDO2AuthenticationEntity();
        entity.setUsername(username);
        entity.setChallenge(challenge);
        entity.setDomain(host);
        entity.setW3cCredentialRequestOptions(credentialRequestOptionsNode.toString());

        authenticationsRepository.save(entity);
        credentialRequestOptionsNode.put("status", "ok");
        credentialRequestOptionsNode.put("errorMessage", "");
        return credentialRequestOptionsNode;
    }
}