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
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
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
    CertificateValidator certificateValidator;

    @Autowired
    CertificateSelector certificateSelector;

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
    @Qualifier("base64UrlEncoder")
    private Base64.Encoder base64UrlEncoder;

    @Autowired
    @Qualifier("base64Decoder")
    private Base64.Decoder base64Decoder;

    public CredAndCounterData verifyAuthenticatorAttestationResponse(JsonNode response, String domain) {
        JsonNode authenticatorResponse = response.get("response");
        String base64AuthenticatorData = authenticatorResponse.get("attestationObject").asText();
        String clientDataJson = authenticatorResponse.get("clientDataJSON").asText();
        byte[] authenticatorDataBuffer = base64UrlDecoder.decode(base64AuthenticatorData);
        CredAndCounterData credIdAndCounters = new CredAndCounterData();
        try {
            AuthData authData;
            JsonNode authenticatorDataNode = cborMapper.readTree(authenticatorDataBuffer);
            LOGGER.info("Authenticator data {}", authenticatorDataNode.toString());
            if ("fido-u2f".equals(authenticatorDataNode.get("fmt").asText())) {
                credIdAndCounters.setAttestationType("fido-u2f");
                JsonNode authDataNode = authenticatorDataNode.get("authData");
                JsonNode attStmt = authenticatorDataNode.get("attStmt");
                String signature = attStmt.get("sig").asText();
                authData = authenticatorDataParser.parseAttestationData(authDataNode.asText());
                credIdAndCounters.setCredId(base64UrlEncoder.encodeToString(authData.getCredId()));
                credIdAndCounters.setCounters(authenticatorDataParser.parseCounter(authData.getCounters()));
                commonVerifiers.verifyUserPresent(authData);
                commonVerifiers.verifyRpIdHash(authData, domain);
                credIdAndCounters.setUncompressedEcPoint(base64UrlEncoder.encodeToString(authData.getCOSEPublicKey()));
                byte[] clientDataHash = DigestUtils.getSha256Digest().digest(base64UrlDecoder.decode(clientDataJson));
                if (attStmt.hasNonNull("x5c")) {
                    String x5c = attStmt.get("x5c").get(0).asText();
                    try {
                        X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(new ByteArrayInputStream(base64Decoder.decode(x5c)));
                        certificateValidator.saveCertificate(certificate);
                        certificate.checkValidity();
                        certificateValidator.verifyCert(certificate, certificateSelector.selectRootCertificate(certificate));
                        commonVerifiers.verifyAttestationSignature(authData, clientDataHash, signature, certificate);
                    } catch (CertificateException e) {
                        throw new Fido2RPRuntimeException("Problem with certificate");
                    }
                } else if (attStmt.hasNonNull("ecdaaKeyId")) {
                    String ecdaaKeyId = attStmt.get("ecdaaKeyId").asText();
                    throw new UnsupportedOperationException("TODO");
                } else {
                    throw new Fido2RPRuntimeException("Wrong key type");
                }
            }
            return credIdAndCounters;
        } catch (IOException e) {
            throw new Fido2RPRuntimeException("Problem with processing authenticator data");
        }


    }


}


