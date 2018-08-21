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
import com.mastercard.ess.fido2.ctap.AttestationConveyancePreference;
import com.mastercard.ess.fido2.database.FIDO2AuthenticationRepository;
import com.mastercard.ess.fido2.database.FIDO2RegistrationEntity;
import com.mastercard.ess.fido2.database.FIDO2RegistrationRepository;
import com.mastercard.ess.fido2.database.RegistrationStatus;
import com.mastercard.ess.fido2.service.AuthenticatorAttestationVerifier;
import com.mastercard.ess.fido2.service.ChallengeGenerator;
import com.mastercard.ess.fido2.service.ChallengeVerifier;
import com.mastercard.ess.fido2.service.CommonVerifiers;
import com.mastercard.ess.fido2.service.CredAndCounterData;
import com.mastercard.ess.fido2.service.DomainVerifier;
import com.mastercard.ess.fido2.service.Fido2RPRuntimeException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
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
    ChallengeGenerator challengeGenerator;

    @Autowired
    CommonVerifiers commonVerifiers;
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
        return createNewRegistration(params);
    }

    JsonNode verify(@RequestBody JsonNode params) {
        LOGGER.info("registerResponse {}", params);
        //JsonNode request = params.get("request");

        commonVerifiers.verifyBasicPayload(params);
        commonVerifiers.verifyBase64UrlString(params.get("type"));
        JsonNode response = params.get("response");
        JsonNode clientDataJSONNode = null;
        try {
            clientDataJSONNode = om.readTree(new String(base64UrlDecoder.decode(params.get("response").get("clientDataJSON").asText()), Charset.forName("UTF-8")));
        } catch (IOException e) {
            new Fido2RPRuntimeException("Can't parse message");
        }


        commonVerifiers.verifyClientJSON(clientDataJSONNode);
        commonVerifiers.verifyClientJSONTypeIsCreate(clientDataJSONNode);
        JsonNode keyIdNode = params.get("id");
        String keyId = commonVerifiers.verifyBase64UrlString(keyIdNode);


        String clientDataChallenge = base64UrlEncoder.withoutPadding().encodeToString(base64UrlDecoder.decode(clientDataJSONNode.get("challenge").asText()));
        LOGGER.info("Challenge {}", clientDataChallenge);
//        String clientDataOrigin = clientDataJSONNode.get("origin").asText();


        List<FIDO2RegistrationEntity> registrations = registrationsRepository.findAllByChallenge(clientDataChallenge);
        FIDO2RegistrationEntity credentialFound = registrations.parallelStream()
                .findAny()
                .orElseThrow(() -> new Fido2RPRuntimeException("Can't find request with matching challenge and domain"));

        domainVerifier.verifyDomain(credentialFound.getDomain(), clientDataJSONNode.get("origin").asText());
        CredAndCounterData attestationData = authenticatorAttestationVerifier.verifyAuthenticatorAttestationResponse(response, credentialFound);

        credentialFound.setUncompressedECPoint(attestationData.getUncompressedEcPoint());
        credentialFound.setStatus(RegistrationStatus.REGISTERED);
        credentialFound.setW3cAuthenticatorAttenstationResponse(response.toString());
        credentialFound.setSignatureAlgorithm(attestationData.getSignatureAlgorithm());
        credentialFound.setCounter(attestationData.getCounters());
        if (attestationData.getCredId() != null) {
            credentialFound.setPublicKeyId(attestationData.getCredId());
        } else {
            credentialFound.setPublicKeyId(keyId);
        }
        credentialFound.setType("public-key");
        registrationsRepository.save(credentialFound);
        //ArrayNode excludedCredentials = ((ObjectNode) params).putArray("excludeCredentials");


        ((ObjectNode) params).put("errorMessage", "");
        ((ObjectNode) params).put("status", "ok");
        return params;
    }

    private JsonNode createNewRegistration(JsonNode params) {
        commonVerifiers.verifyOptions(params);
        String username = params.get("username").asText();
        String displayName = params.get("displayName").asText();

        String documentDomain;
        String host;
        if (params.hasNonNull("documentDomain")) {
            documentDomain = params.get("documentDomain").asText();
        } else {
            documentDomain = rpDomain;
        }

        try {
            host = new URL(documentDomain).getHost();
        } catch (MalformedURLException e) {
            host = documentDomain;
//            throw new Fido2RPRuntimeException(e.getMessage());

        }


        String authenticatorSelection;
        if (params.hasNonNull("authenticatorSelection")) {
            authenticatorSelection = params.get("authenticatorSelection").asText();
        } else {
            authenticatorSelection = "";
        }


        LOGGER.info("Options {} {} {}", username, displayName, documentDomain);
        AttestationConveyancePreference attestationType = commonVerifiers.verifyAttestationConveyanceType(params);


        String credentialType = params.hasNonNull("credentialType") ? params.get("credentialType").asText("public-key") : "public-key";
        ObjectNode credentialCreationOptionsNode = om.createObjectNode();

        String challenge = challengeGenerator.getChallenge();
        credentialCreationOptionsNode.put("challenge", challenge);
        LOGGER.info("Challenge {}", challenge);
        ObjectNode credentialRpEntityNode = credentialCreationOptionsNode.putObject("rp");
        credentialRpEntityNode.put("name", "Mastercard RP");
        credentialRpEntityNode.put("id", documentDomain);

        ObjectNode credentialUserEntityNode = credentialCreationOptionsNode.putObject("user");
        byte[] buffer = new byte[32];
        new SecureRandom().nextBytes(buffer);
        String userId = base64UrlEncoder.encodeToString(buffer);
        credentialUserEntityNode.put("id", userId);
        credentialUserEntityNode.put("name", username);
        credentialUserEntityNode.put("displayName", displayName);
        credentialCreationOptionsNode.put("attestation", attestationType.toString());
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
        credentialCreationOptionsNode.set("authenticatorSelection", params.get("authenticatorSelection"));

        List<FIDO2RegistrationEntity> existingRegistrations = registrationsRepository.findAllByUsername(username);
        List<JsonNode> excludedKeys = existingRegistrations.parallelStream().map(
                f -> om.convertValue(new PublicKeyCredentialDescriptor(f.getType(), f.getPublicKeyId()), JsonNode.class)
        ).collect(Collectors.toList());

        ArrayNode excludedCredentials = credentialCreationOptionsNode.putArray("excludeCredentials");
        excludedCredentials.addAll(excludedKeys);
        credentialCreationOptionsNode.put("status", "ok");
        credentialCreationOptionsNode.put("errorMessage", "");
        FIDO2RegistrationEntity entity = new FIDO2RegistrationEntity();
        entity.setUsername(username);
        entity.setUserId(userId);
        entity.setChallenge(challenge);
        entity.setDomain(host);
        entity.setW3cCredentialCreationOptions(credentialCreationOptionsNode.toString());
        entity.setAttestationType(attestationType.toString());
        registrationsRepository.save(entity);
        return credentialCreationOptionsNode;
    }



}
