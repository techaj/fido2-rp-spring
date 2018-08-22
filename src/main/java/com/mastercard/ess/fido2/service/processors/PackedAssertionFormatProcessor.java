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

package com.mastercard.ess.fido2.service.processors;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mastercard.ess.fido2.cryptoutils.COSEHelper;
import com.mastercard.ess.fido2.ctap.AttestationFormat;
import com.mastercard.ess.fido2.ctap.UserVerification;
import com.mastercard.ess.fido2.database.FIDO2AuthenticationEntity;
import com.mastercard.ess.fido2.database.FIDO2RegistrationEntity;
import com.mastercard.ess.fido2.service.AuthData;
import com.mastercard.ess.fido2.service.AuthenticatorDataParser;
import com.mastercard.ess.fido2.service.CommonVerifiers;
import com.mastercard.ess.fido2.service.Fido2RPRuntimeException;
import java.security.PublicKey;
import java.util.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

@Service
public class PackedAssertionFormatProcessor implements AssertionFormatProcessor {
    private static final Logger LOGGER = LoggerFactory.getLogger(PackedAssertionFormatProcessor.class);

    @Autowired
    COSEHelper uncompressedECPointHelper;

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

    @Override
    public AttestationFormat getAttestationFormat() {
        return AttestationFormat.packed;
    }


    public void process(String base64AuthenticatorData, String signature, String clientDataJson, FIDO2RegistrationEntity registration, FIDO2AuthenticationEntity authenticationEntity) {
        AuthData authData = authenticatorDataParser.parseAssertionData(base64AuthenticatorData);
        commonVerifiers.verifyRpIdHash(authData, registration.getDomain());

        if (UserVerification.valueOf(authenticationEntity.getUserVerificationOption()) == UserVerification.required) {
            commonVerifiers.verifyRequiredUserPresent(authData);
        }
        if (UserVerification.valueOf(authenticationEntity.getUserVerificationOption()) == UserVerification.preferred) {
            commonVerifiers.verifyPreferredUserPresent(authData);
        }
        if (UserVerification.valueOf(authenticationEntity.getUserVerificationOption()) == UserVerification.discouraged) {
            commonVerifiers.verifyDiscouragedUserPresent(authData);
        }

        byte[] clientDataHash = DigestUtils.getSha256Digest().digest(base64UrlDecoder.decode(clientDataJson));

        try {

            JsonNode uncompressedECPointNode = cborMapper.readTree(base64UrlDecoder.decode(registration.getUncompressedECPoint()));
            PublicKey publicKey = uncompressedECPointHelper.createUncompressedPointFromCOSEPublicKey(uncompressedECPointNode);

            LOGGER.info("Uncompressed ECpoint node {}", uncompressedECPointNode.toString());
            LOGGER.info("EC Public key hex {}", Hex.encodeHexString(publicKey.getEncoded()));

            commonVerifiers.verifyAssertionSignature(authData, clientDataHash, signature, publicKey, registration.getSignatureAlgorithm());
            int counter = authenticatorDataParser.parseCounter(authData.getCounters());
            commonVerifiers.verifyCounter(registration.getCounter(), counter);
            registration.setCounter(counter);
        } catch (Exception e) {
            throw new Fido2RPRuntimeException("General server error " + e.getMessage());
        }
    }
}
