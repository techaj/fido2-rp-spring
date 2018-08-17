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
import com.mastercard.ess.fido2.database.FIDO2RegistrationEntity;
import com.mastercard.ess.fido2.service.AttestationFormat;
import com.mastercard.ess.fido2.service.AuthData;
import com.mastercard.ess.fido2.service.CertificateSelector;
import com.mastercard.ess.fido2.service.CertificateValidator;
import com.mastercard.ess.fido2.service.CommonVerifiers;
import com.mastercard.ess.fido2.service.CredAndCounterData;
import com.mastercard.ess.fido2.service.Fido2RPRuntimeException;
import com.mastercard.ess.fido2.service.UncompressedECPointHelper;
import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

@Service
public class PackedAttestationProcessor implements AttestationFormatProcessor {
    private static final Logger LOGGER = LoggerFactory.getLogger(PackedAttestationProcessor.class);
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
        return AttestationFormat.packed;
    }

    @Override
    public void process(JsonNode attStmt, AuthData authData, FIDO2RegistrationEntity registration, byte[] clientDataHash, CredAndCounterData credIdAndCounters) {
        int alg = commonVerifiers.verifyAlgorithm(attStmt.get("alg"), authData.getKeyType());
        String signature = commonVerifiers.verifyBase64String(attStmt.get("sig"));


        if (attStmt.hasNonNull("x5c")) {
            Iterator<JsonNode> i = attStmt.get("x5c").elements();
            ArrayList<String> certificatePath = new ArrayList();
            while (i.hasNext()) {
                certificatePath.add(i.next().asText());
            }
            List<X509Certificate> certificates = certificatePath.parallelStream().map(f -> getCertificate(f)).filter(c -> {
                try {
                    c.checkValidity();
                    return true;
                } catch (CertificateException e) {
                    LOGGER.warn("Certificate not valid {}" + c.getIssuerDN().getName());
                    throw new Fido2RPRuntimeException("Certificate not valid ");
                }
            }).collect(Collectors.toList());
//                            certificateValidator.saveCertificate(certificate);

            credIdAndCounters.setSignatureAlgorithm(alg);
            List<X509Certificate> trustAnchorCertificates = certificateSelector.selectRootCertificate(certificates.get(0));
            Certificate verifiedCert = certificateValidator.verifyCert(certificates, trustAnchorCertificates);
            commonVerifiers.verifyPackedAttestationSignature(authData.getAuthDataDecoded(), clientDataHash, signature, verifiedCert, alg);
        } else if (attStmt.hasNonNull("ecdaaKeyId")) {
            String ecdaaKeyId = attStmt.get("ecdaaKeyId").asText();
            throw new UnsupportedOperationException("TODO");
        } else {
            ECPublicKey ecPublicKey = uncompressedECPointHelper.getPublicKeyFromUncompressedECPoint(authData.getCOSEPublicKey());
            commonVerifiers.verifyPackedSurrogateAttestationSignature(authData.getAuthDataDecoded(), clientDataHash, signature, ecPublicKey, alg);
        }
        credIdAndCounters.setAttestationType(getAttestationFormat().getFmt());
        credIdAndCounters.setCredId(base64UrlEncoder.encodeToString(authData.getCredId()));
        credIdAndCounters.setUncompressedEcPoint(base64UrlEncoder.encodeToString(authData.getCOSEPublicKey()));

    }

    X509Certificate getCertificate(String x5c) {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(new ByteArrayInputStream(base64Decoder.decode(x5c)));
        } catch (CertificateException e) {
            throw new Fido2RPRuntimeException(e.getMessage());
        }
    }
}
