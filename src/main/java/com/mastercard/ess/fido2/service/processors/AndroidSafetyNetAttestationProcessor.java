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
import com.google.safetynet.AttestationStatement;
import com.google.safetynet.OfflineVerify;
import com.mastercard.ess.fido2.certification.CertificationKeyStoreUtils;
import com.mastercard.ess.fido2.database.FIDO2RegistrationEntity;
import com.mastercard.ess.fido2.service.AttestationFormat;
import com.mastercard.ess.fido2.service.AuthData;
import com.mastercard.ess.fido2.service.CertificateSelector;
import com.mastercard.ess.fido2.service.CertificateValidator;
import com.mastercard.ess.fido2.service.CommonVerifiers;
import com.mastercard.ess.fido2.service.CredAndCounterData;
import com.mastercard.ess.fido2.service.Fido2RPRuntimeException;
import com.mastercard.ess.fido2.service.UncompressedECPointHelper;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;
import javax.net.ssl.X509TrustManager;
import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

@Service
public class AndroidSafetyNetAttestationProcessor implements AttestationFormatProcessor {
    private static final Logger LOGGER = LoggerFactory.getLogger(AndroidSafetyNetAttestationProcessor.class);
    @Autowired
    CommonVerifiers commonVerifiers;

    @Autowired
    @Qualifier("cborMapper")
    ObjectMapper cborMapper;
    @Autowired
    AttestationProcessorFactory attestationProcessorFactory;
    @Autowired
    CertificateSelector certificateSelector;
    @Autowired
    CertificateValidator certificateValidator;
    @Autowired
    UncompressedECPointHelper uncompressedECPointHelper;
    @Autowired
    CertificationKeyStoreUtils utils;
    @Autowired
    @Qualifier("base64UrlDecoder")
    private Base64.Decoder base64UrlDecoder;
    @Autowired
    @Qualifier("base64UrlEncoder")
    private Base64.Encoder base64UrlEncoder;
    @Autowired
    @Qualifier("base64Decoder")
    private Base64.Decoder base64Decoder;

    @Override
    public AttestationFormat getAttestationFormat() {
        return AttestationFormat.android_safetynet;
    }

    @Override
    public void process(JsonNode attStmt, AuthData authData, FIDO2RegistrationEntity credential, byte[] clientDataHash, CredAndCounterData credIdAndCounters) {

        commonVerifiers.verifyThatNonEmptyString(attStmt.get("ver"));
        String response = attStmt.get("response").asText();

        KeyStore keyStore = utils.getCertificationKeyStore();
        X509TrustManager tm = utils.populateTrustManager(keyStore);

        LOGGER.info("Android safetynet payload {}", new String(base64Decoder.decode(response)));

        AttestationStatement stmt = OfflineVerify.parseAndVerify(new String(base64Decoder.decode(response)), tm);

        if (stmt == null) {
            throw new Fido2RPRuntimeException("Invalid safety net attestation ");
        }

        byte[] b1 = authData.getAuthDataDecoded();
        byte[] b2 = clientDataHash;
        byte[] buffer = ByteBuffer.allocate(b1.length + b2.length).put(b1).put(b2).array();
        byte[] hashedBuffer = DigestUtils.getSha256Digest().digest(buffer);
        byte[] nonce = stmt.getNonce();
        if (!Arrays.equals(hashedBuffer, nonce)) {
            throw new Fido2RPRuntimeException("Invalid safety net attestation ");
        }

        if (!stmt.isCtsProfileMatch()) {
            throw new Fido2RPRuntimeException("Invalid safety net attestation ");
        }

        Instant timestamp = Instant.ofEpochMilli(stmt.getTimestampMs());

        if (timestamp.isAfter(Instant.now())) {
            throw new Fido2RPRuntimeException("Invalid safety net attestation ");
        }

        if (timestamp.isBefore(Instant.now().minus(1, ChronoUnit.MINUTES))) {
            throw new Fido2RPRuntimeException("Invalid safety net attestation ");
        }

        credIdAndCounters.setAttestationType(getAttestationFormat().getFmt());
        credIdAndCounters.setCredId(base64UrlEncoder.encodeToString(authData.getCredId()));
        credIdAndCounters.setUncompressedEcPoint(base64UrlEncoder.encodeToString(authData.getCOSEPublicKey()));

    }


}
