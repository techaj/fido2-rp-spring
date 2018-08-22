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
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mastercard.ess.fido2.database.FIDO2RegistrationEntity;
import com.mastercard.ess.fido2.service.processors.AttestationFormatProcessor;
import com.mastercard.ess.fido2.service.processors.AttestationProcessorFactory;
import java.io.IOException;
import java.util.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;


@Service
public class AuthenticatorAttestationVerifier {
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticatorAttestationVerifier.class);



    @Autowired
    CommonVerifiers commonVerifiers;

    @Autowired
    AuthenticatorDataParser authenticatorDataParser;

    @Autowired
    @Qualifier("cborMapper")
    ObjectMapper cborMapper;

    @Autowired
    @Qualifier("base64UrlDecoder")
    private Base64.Decoder base64UrlDecoder;

    @Autowired
    AttestationProcessorFactory attestationProcessorFactory;

    public CredAndCounterData verifyAuthenticatorAttestationResponse(JsonNode response, FIDO2RegistrationEntity credential) {
        JsonNode authenticatorResponse = response;
        String base64AuthenticatorData = authenticatorResponse.get("attestationObject").asText();
        String clientDataJson = authenticatorResponse.get("clientDataJSON").asText();
        byte[] authenticatorDataBuffer = base64UrlDecoder.decode(base64AuthenticatorData);
        CredAndCounterData credIdAndCounters = new CredAndCounterData();
        try {
            AuthData authData;
            JsonNode authenticatorDataNode = cborMapper.readTree(authenticatorDataBuffer);
            String fmt = commonVerifiers.verifyFmt(authenticatorDataNode.get("fmt"));
            LOGGER.info("Authenticator data {} {}", fmt, authenticatorDataNode.toString());
            credential.setAttestationType(fmt);
            JsonNode authDataNode = authenticatorDataNode.get("authData");
            String authDataText = commonVerifiers.verifyAuthData(authDataNode);
            JsonNode attStmt = authenticatorDataNode.get("attStmt");

            authData = authenticatorDataParser.parseAttestationData(authDataText);
            int counter = authenticatorDataParser.parseCounter(authData.getCounters());
            commonVerifiers.verifyCounter(counter);
            credIdAndCounters.setCounters(counter);
            byte[] clientDataHash = DigestUtils.getSha256Digest().digest(base64UrlDecoder.decode(clientDataJson));
            AttestationFormatProcessor attestationProcessor = attestationProcessorFactory.getCommandProcessor(fmt);
            attestationProcessor.process(attStmt, authData, credential, clientDataHash, credIdAndCounters);
            return credIdAndCounters;
        } catch (IOException e) {
            throw new Fido2RPRuntimeException("Problem with processing authenticator data");
        }
    }


}


