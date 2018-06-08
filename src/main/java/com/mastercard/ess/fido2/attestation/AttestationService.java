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

package com.mastercard.ess.fido2.attestation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mastercard.ess.fido2.database.FIDO2AuthenticationEntity;
import com.mastercard.ess.fido2.database.FIDO2AuthenticationRepository;
import com.mastercard.ess.fido2.database.FIDO2RegistrationEntity;
import com.mastercard.ess.fido2.database.FIDO2RegistrationRepository;
import com.mastercard.ess.fido2.database.RegistrationStatus;
import com.mastercard.ess.fido2.service.AuthenticatorAttestationVerifier;
import com.mastercard.ess.fido2.service.ChallengeVerifier;
import com.mastercard.ess.fido2.service.CredAndCounterData;
import com.mastercard.ess.fido2.service.DomainVerifier;
import com.mastercard.ess.fido2.service.Fido2RPRuntimeException;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;

@Service
class AttestationService {
    private static final Logger LOGGER = LoggerFactory.getLogger(AttestationService.class);
    @Autowired
    FIDO2AuthenticationRepository authenticationsRepository;
    @Autowired
    FIDO2RegistrationRepository registrationsRepository;
    @Autowired
    AuthenticatorAttestationVerifier authenticatorAttestationVerifier;
    @Autowired
    ChallengeVerifier challengeVerifier;
    @Autowired
    DomainVerifier domainVerifier;
    @Autowired
    private ObjectMapper om;
    @Autowired
    @Qualifier("base64UrlEncoder")
    private Base64.Encoder base64UrlEncoder;
    @Autowired
    @Qualifier("base64UrlDecoder")
    private Base64.Decoder base64UrlDecoder;

    JsonNode options(@RequestBody JsonNode params) {
        LOGGER.info("options {}", params);
        if (!params.has("displayName")) {
            // we want to retrieve registration only
            return retrieveRegistration(params);
        } else {
            return createNewRegistration(params);

        }

    }

    JsonNode verify(@RequestBody JsonNode params) {
        LOGGER.info("registerResponse {}", params);
        JsonNode request = params.get("request");
        JsonNode response = params.get("response");
        String userId = request.get("user").get("id").asText();
        String challenge = request.get("challenge").asText();
        JsonNode clientDataJSONNode = null;

        try {
            clientDataJSONNode = om.readTree(new String(base64UrlDecoder.decode(params.get("response").get("response").get("clientDataJSON").asText()), Charset.forName("UTF-8")));
        } catch (IOException e) {
            new Fido2RPRuntimeException("Can't parse message");
        }
        String keyId = response.get("id").asText();

        String clientDataChallenge = clientDataJSONNode.get("challenge").asText();
        String clientDataOrigin = clientDataJSONNode.get("origin").asText();

        LOGGER.info("userId  {} challenge {} {} {}", userId, challenge, clientDataChallenge, clientDataOrigin);
        if (!challenge.equals(clientDataChallenge)) {
            throw new Fido2RPRuntimeException("Challenges don't match");
        }

        List<FIDO2RegistrationEntity> registrations = registrationsRepository.findAllByUserId(userId);
        FIDO2RegistrationEntity credentialFound = registrations.parallelStream()
                .filter(f -> challengeVerifier.verifyChallenge(f.getChallenge(), challenge, clientDataChallenge))
                .filter(f -> domainVerifier.verifyDomain(f.getDomain(), clientDataOrigin))
                .findAny()
                .orElseThrow(() -> new Fido2RPRuntimeException("Can't find request with matching id and challenge"));


        CredAndCounterData attestationData = authenticatorAttestationVerifier.verifyAuthenticatorAttestationResponse(response, credentialFound.getDomain());
        credentialFound.setUncompressedECPoint(attestationData.getUncompressedEcPoint());
        credentialFound.setAttestationType(attestationData.getAttestationType());
        credentialFound.setStatus(RegistrationStatus.REGISTERED);
        credentialFound.setW3cAuthenticatorAttenstationResponse(response.toString());
        credentialFound.setPublicKeyId(attestationData.getCredId());
        registrationsRepository.save(credentialFound);
        return params;
    }

    private JsonNode createNewRegistration(JsonNode params) {

        String username = params.get("username").asText();
        String displayName = params.get("displayName").asText();
        String documentDomain = params.get("documentDomain").asText();

        LOGGER.info("New registration {} {} {}", username, displayName, documentDomain);

        String credentialType = params.hasNonNull("credentialType") ? params.get("credentialType").asText("public-key") : "public-key";
        ObjectNode credentialCreationOptionsNode = om.createObjectNode();
        byte buffer[] = new byte[32];
        new SecureRandom().nextBytes(buffer);
        String challenge = base64UrlEncoder.encodeToString(buffer);
        credentialCreationOptionsNode.put("challenge", challenge);
        ObjectNode credentialRpEntityNode = credentialCreationOptionsNode.putObject("rp");
        credentialRpEntityNode.put("name", "Mastercard RP");
        credentialRpEntityNode.put("id", documentDomain);

        ObjectNode credentialUserEntityNode = credentialCreationOptionsNode.putObject("user");
        new SecureRandom().nextBytes(buffer);
        String userId = base64UrlEncoder.encodeToString(buffer);
        credentialUserEntityNode.put("id", userId);
        credentialUserEntityNode.put("name", username);
        credentialUserEntityNode.put("displayName", displayName);
        credentialCreationOptionsNode.put("attestation", "direct");
        ArrayNode credentialParametersArrayNode = credentialCreationOptionsNode.putArray("pubKeyCredParams");
        ObjectNode credentialParametersNode = credentialParametersArrayNode.addObject();
        if ("public-key".equals(credentialType)) {
            credentialParametersNode.put("type", "public-key");
            credentialParametersNode.put("alg", -7);
        }
        if ("FIDO".equals(credentialType)) {
            credentialParametersNode.put("type", "FIDO");
            credentialParametersNode.put("alg", -7);
        }
        credentialCreationOptionsNode.put("status", "ok");
        FIDO2RegistrationEntity entity = new FIDO2RegistrationEntity();
        entity.setUsername(username);
        entity.setUserId(userId);
        entity.setChallenge(challenge);
        entity.setDomain(documentDomain);
        entity.setW3cCredentialCreationOptions(credentialCreationOptionsNode.toString());
        registrationsRepository.save(entity);
        return credentialCreationOptionsNode;
    }

    private JsonNode retrieveRegistration(JsonNode params) {
        LOGGER.info("authenticate {}", params);
        String username = params.get("username").asText();
        String documentDomain = params.get("documentDomain").asText();

        LOGGER.info("Registration {} {}", username, documentDomain);

        ObjectNode credentialRequestOptionsNode = om.createObjectNode();
        List<FIDO2RegistrationEntity> registrations = registrationsRepository.findAllByUsernameAndDomain(username, documentDomain);

        byte buffer[] = new byte[32];
        new SecureRandom().nextBytes(buffer);

        String challenge = base64UrlEncoder.encodeToString(buffer);
        credentialRequestOptionsNode.put("challenge", challenge);

        ObjectNode credentialUserEntityNode = credentialRequestOptionsNode.putObject("user");
        credentialUserEntityNode.put("name", username);

        ObjectNode publicKeyCredentialRpEntityNode = credentialRequestOptionsNode.putObject("rp");
        publicKeyCredentialRpEntityNode.put("name", "ACME Dawid");
        publicKeyCredentialRpEntityNode.put("id", documentDomain);
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


        FIDO2AuthenticationEntity entity = new FIDO2AuthenticationEntity();
        entity.setUsername(username);
        entity.setChallenge(challenge);
        entity.setDomain(documentDomain);
        entity.setW3cCredentialRequestOptions(credentialRequestOptionsNode.toString());
        authenticationsRepository.save(entity);
        return credentialRequestOptionsNode;
    }

}
