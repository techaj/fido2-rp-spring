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

package com.mastercard.ess.fido2.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mastercard.ess.fido2.database.FIDO2AuthenticationEntity;
import com.mastercard.ess.fido2.database.FIDO2AuthenticationRepository;
import com.mastercard.ess.fido2.database.FIDO2RegistrationEntity;
import com.mastercard.ess.fido2.database.FIDO2RegistrationRepository;
import com.mastercard.ess.fido2.database.RegistrationStatus;
import com.mastercard.ess.fido2.service.AuthenticatorAssertionVerifier;
import com.mastercard.ess.fido2.service.AuthenticatorAttestationVerifier;
import com.mastercard.ess.fido2.service.CredAndCounterData;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/webauthn")
public class WebAuthnController {
    private static final Logger LOGGER = LoggerFactory.getLogger(WebAuthnController.class);

    @Autowired
    private ObjectMapper om;

    @Autowired
    FIDO2RegistrationRepository registrationsRepository;

    @Autowired
    FIDO2AuthenticationRepository authenticationsRepository;

    @Autowired
    AuthenticatorAttestationVerifier  authenticatorAttestationVerifier;
    @Autowired
    AuthenticatorAssertionVerifier authenticatorAuthorizationVerifier;

    @Autowired
    @Qualifier("base64UrlEncoder")
    private Base64.Encoder base64UrlEncoder;

    @Autowired
    @Qualifier("base64UrlDecoder")
    private Base64.Decoder base64UrlDecoder;


    @PostMapping(value = {"/register"}, produces = {"application/json"}, consumes = {"application/json"})
    JsonNode register(@RequestBody JsonNode params) {
        LOGGER.info("register {}", params);
        String username = params.get("username").asText();
        String displayName = params.get("displayName").asText();
        String documentDomain = params.get("documentDomain").asText();
        String credentialType = params.hasNonNull("credentialType")? params.get("credentialType").asText("public-key") : "public-key";
        ObjectNode credentialCreationOptionsNode = om.createObjectNode();
        byte buffer[] = new byte[32];
        new SecureRandom().nextBytes(buffer);
        String challenge = base64UrlEncoder.encodeToString(buffer);
        credentialCreationOptionsNode.put("challenge", challenge);
        ObjectNode credentialRpEntityNode = credentialCreationOptionsNode.putObject("rp");
        credentialRpEntityNode.put("name", "ACME Dawid");
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
        if("public-key".equals(credentialType)) {
            credentialParametersNode.put("type", "public-key");
            credentialParametersNode.put("alg", -7);
        }
        if("FIDO".equals(credentialType)) {
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

    @PatchMapping(value = {"/register"}, produces = {"application/json"}, consumes = {"application/json"})
    JsonNode registerResponse(@RequestBody JsonNode params) {
        LOGGER.info("registerResponse {}", params);
        JsonNode request = params.get("request");
        JsonNode response = params.get("response");
        String userId = request.get("user").get("id").asText();
        String challenge = request.get("challenge").asText();
        JsonNode clientDataJSONNode = null;

        try {
            clientDataJSONNode = om.readTree(new String(base64UrlDecoder.decode(params.get("response").get("response").get("clientDataJSON").asText()),Charset.forName("UTF-8")));
        } catch (IOException e) {
            new RuntimeException(e);
        }
        String keyId = response.get("id").asText();

        String clientDataChallenge  = clientDataJSONNode.get("challenge").asText();
        String clientDataOrigin  = clientDataJSONNode.get("origin").asText();

        LOGGER.info("userId  {} challenge {} {} {}", userId,challenge,clientDataChallenge,clientDataOrigin);
        if(!challenge.equals(clientDataChallenge)){
            throw new RuntimeException("Challenges don't match");
        }

        List<FIDO2RegistrationEntity> registrations = registrationsRepository.findAllByUserId(userId);
        FIDO2RegistrationEntity credentialFound = registrations.parallelStream()
                .filter(f -> verifyChallenge(f.getChallenge(),challenge,clientDataChallenge))
                .filter(f-> verifyDomain(f.getDomain(),clientDataOrigin))
                .findAny()
                .orElseThrow(() -> new RuntimeException("Can't find request with matching id and challenge"));


        CredAndCounterData attestationData = authenticatorAttestationVerifier.verifyAuthenticatorAttestationResponse(response,credentialFound.getDomain());
        credentialFound.setUncompressedECPoint(attestationData.getUncompressedEcPoint());
        credentialFound.setAttestationType(attestationData.getAttestationType());
        credentialFound.setStatus(RegistrationStatus.REGISTERED);
        credentialFound.setW3cAuthenticatorAttenstationResponse(response.toString());
        credentialFound.setPublicKeyId(attestationData.getCredId());
        registrationsRepository.save(credentialFound);
        return params;
    }



    @PostMapping(value = {"/authenticate"}, produces = {"application/json"}, consumes = {"application/json"})
    JsonNode authenticate(@RequestBody JsonNode params) {

        LOGGER.info("authenticate {}", params);
        String username = params.get("username").asText();
        String documentDomain = params.get("documentDomain").asText();

        ObjectNode credentialRequestOptionsNode = om.createObjectNode();
        List<FIDO2RegistrationEntity> registrations =  registrationsRepository.findAllByUsernameAndDomain(username,documentDomain);

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

        for(FIDO2RegistrationEntity registration :registrations) {
            if(StringUtils.isEmpty(registration.getPublicKeyId())) {
                throw new RuntimeException("Can't find associated key. Have you registered");
            }
            ObjectNode publicKeyCredentialDescriptorNode = publicKeyCredentialDescriptors.addObject();
            publicKeyCredentialDescriptorNode.put("type","public-key");
            ArrayNode authenticatorTransportNode = publicKeyCredentialDescriptorNode.putArray("transports");
            authenticatorTransportNode.add("usb").add("ble").add("nfc");
            publicKeyCredentialDescriptorNode.put("id",registration.getPublicKeyId());
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

    @PatchMapping(value = {"/authenticate"}, produces = {"application/json"}, consumes = {"application/json"})
    JsonNode authenticateResponse(@RequestBody JsonNode params) {
        LOGGER.info("authenticateResponse {}", params);
        JsonNode request = params.get("request");
        JsonNode response = params.get("response");
        String challenge = request.get("challenge").asText();
        String username = request.get("user").get("name").asText();
        String domain = params.get("request").get("rp").get("id").asText();

        JsonNode clientDataJSONNode;
        try {
            clientDataJSONNode = om.readTree(new String(base64UrlDecoder.decode(params.get("response").get("response").get("clientDataJSON").asText()),Charset.forName("UTF-8")));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }


        FIDO2AuthenticationEntity authenticationEntity = authenticationsRepository.findByChallenge(challenge).orElseThrow(() -> new RuntimeException("Can't find matching request"));

        String clientDataChallenge  = clientDataJSONNode.get("challenge").asText();
        String clientDataOrigin  = clientDataJSONNode.get("origin").asText();

        verifyChallenge(authenticationEntity.getChallenge(),challenge,clientDataChallenge);
        verifyDomain(authenticationEntity.getDomain(),clientDataOrigin);

        String keyId = response.get("id").asText();
        FIDO2RegistrationEntity registration = registrationsRepository.findByPublicKeyId(keyId).orElseThrow(()->new RuntimeException("Couldn't find the key"));
        authenticatorAuthorizationVerifier.verifyAuthenticatorAssertionResponse(response, registration);

        authenticationEntity.setW3cAuthenticatorAssertionResponse(response.toString());
        authenticationsRepository.save(authenticationEntity);
        return params;
    }

    private boolean verifyChallenge(String challengeSent, String challengeReceived, String challengeInClientDataOrigin) {
        if(!challengeReceived.equals(challengeInClientDataOrigin)){
            throw new RuntimeException("Challenges don't match");
        }
        if(!challengeSent.equals(challengeInClientDataOrigin)){
            throw new RuntimeException("Challenges don't match");
        }
        return true;
    }

    private boolean verifyDomain(String domain, String clientDataOrigin) {
        // a hack, there is a problem when we are sending https://blah as rp.id
        // which is sent to us from the browser in let rpid = window.location.origin;
        // so instead we are using
        // let rpid = document.domain;
        // but then clientDataOrigin is https://
        try {
            if(!domain.equals(new URL(clientDataOrigin).getHost())){
                throw new RuntimeException("Domains don't match");
            }
            return true;
        } catch (MalformedURLException e) {
            throw new RuntimeException("Not valid domain");
        }
    }



}

