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
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import javax.security.cert.CertificateException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

@Service
public class AuthenticatorAssertionVerifier {
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticatorAssertionVerifier.class);

    @Autowired
    UncompressedECPointHelper uncompressedECPointHelper;

    @Autowired
    CommonVerifiers commonVerifiers;

    @Autowired
    AuthenticatorDataParser authenticatorDataParser;

    @Autowired
    @Qualifier("base64UrlDecoder")
    private Base64.Decoder base64UrlDecoder;

    @Autowired
    @Qualifier("base64Decoder")
    private Base64.Decoder base64Decoder;


    @Autowired
    @Qualifier("cborMapper")
    ObjectMapper cborMapper;

    public void verifyAuthenticatorAssertionResponse(JsonNode response, FIDO2RegistrationEntity registration) {
        JsonNode authenticatorResponse = response.get("response");
        String base64AuthenticatorData = authenticatorResponse.get("authenticatorData").asText();
        String clientDataJson = authenticatorResponse.get("clientDataJSON").asText();
        String signature = authenticatorResponse.get("signature").asText();
        String userHandle = authenticatorResponse.get("userHandle").asText();


        LOGGER.info("Authenticator data {}", base64AuthenticatorData);
        if ("fido-u2f".equals(registration.getAttestationType())) {
            AuthData authData = authenticatorDataParser.parseAssertionData(base64AuthenticatorData);
            commonVerifiers.verifyUserPresent(authData);
            byte[] clientDataHash = DigestUtils.getSha256Digest().digest(base64UrlDecoder.decode(clientDataJson));

            try {
                JsonNode uncompressedECPointNode = cborMapper.readTree(base64UrlDecoder.decode(registration.getUncompressedECPoint()));
                byte[] publicKey = uncompressedECPointHelper.createUncompressedPointFromCOSEPublicKey(uncompressedECPointNode);
                int coseCurveCode = uncompressedECPointHelper.getCodeCurve(uncompressedECPointNode);
                LOGGER.info("Uncompressed ECpoint node {}", uncompressedECPointNode.toString());
                LOGGER.info("EC Public key hex {}", Hex.encodeHexString(publicKey));
                ECPublicKey ecPublicKey = uncompressedECPointHelper.convertUncompressedPointToECKey(publicKey,coseCurveCode);
                commonVerifiers.verifyAssertionSignature(authData, clientDataHash, signature, ecPublicKey );
                int counter = authenticatorDataParser.parseCounter(authData.getCounters());
                commonVerifiers.verifyCounter(registration.getCounter(), counter);
                registration.setCounter(counter);

            } catch (CertificateException e) {
                throw new Fido2RPRuntimeException("Problem with certificate");
            } catch (Exception e) {
                throw new Fido2RPRuntimeException("General server error");
            }
        }

    }


}
