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
//            switch(fmt) {
//                case "fido-u2f": {
//                    int alg = -7;
//                    credIdAndCounters.setAttestationType("fido-u2f");
//                    credIdAndCounters.setCredId(base64UrlEncoder.encodeToString(authData.getCredId()));
//                    String signature = commonVerifiers.verifyBase64String(attStmt.get("sig"));
//                    commonVerifiers.verifyAAGUIDZeroed(authData);
//                    commonVerifiers.verifyUserPresent(authData);
//                    commonVerifiers.verifyRpIdHash(authData, credential.getDomain());
//                    credIdAndCounters.setUncompressedEcPoint(base64UrlEncoder.encodeToString(authData.getCOSEPublicKey()));
//
//                    if (attStmt.hasNonNull("x5c")) {
//                        Iterator<JsonNode> i = attStmt.get("x5c").elements();
//                        ArrayList<String> certificatePath = new ArrayList();
//                        while (i.hasNext()) {
//                            certificatePath.add(i.next().asText());
//                        }
//                        List<X509Certificate> certificates = certificatePath.parallelStream().map(f -> getCertificate(f)).filter(c -> {
//                            try {
//                                c.checkValidity();
//                                return true;
//                            } catch (CertificateException e) {
//                                LOGGER.warn("Certificate not valid {}" + c.getIssuerDN().getName());
//                                throw new Fido2RPRuntimeException("Certificate not valid ");
//                            }
//                        }).collect(Collectors.toList());
////                            certificateValidator.saveCertificate(certificate);
//
//                        credIdAndCounters.setSignatureAlgorithm(alg);
//                        List<X509Certificate> trustAnchorCertificates = certificateSelector.selectRootCertificate(certificates.get(0));
//                        Certificate verifiedCert = certificateValidator.verifyCert(certificates, trustAnchorCertificates);
//                        commonVerifiers.verifyU2FAttestationSignature(authData, clientDataHash, signature, verifiedCert,alg);
//                    } else if (attStmt.hasNonNull("ecdaaKeyId")) {
//                        String ecdaaKeyId = attStmt.get("ecdaaKeyId").asText();
//                        throw new UnsupportedOperationException("TODO");
//                    } else {
//                        ECPublicKey ecPublicKey = uncompressedECPointHelper.getPublicKeyFromUncompressedECPoint(authData.getCOSEPublicKey());
//                        commonVerifiers.verifyPackedSurrogateAttestationSignature(authData.getAuthDataDecoded(), clientDataHash, signature, ecPublicKey, alg);
//                    }
//                }
//                ;
//                break;
//                case "packed": {
//                    int alg = commonVerifiers.verifyAlgorithm(attStmt.get("alg"),authData.getKeyType());
//                    String signature = commonVerifiers.verifyBase64String(attStmt.get("sig"));
//                    if (attStmt.hasNonNull("x5c")) {
//                        Iterator<JsonNode> i = attStmt.get("x5c").elements();
//                        ArrayList<String> certificatePath = new ArrayList();
//                        while (i.hasNext()) {
//                            certificatePath.add(i.next().asText());
//                        }
//                        List<X509Certificate> certificates = certificatePath.parallelStream().map(f -> getCertificate(f)).filter(c -> {
//                            try {
//                                c.checkValidity();
//                                return true;
//                            } catch (CertificateException e) {
//                                LOGGER.warn("Certificate not valid {}" + c.getIssuerDN().getName());
//                                throw new Fido2RPRuntimeException("Certificate not valid ");
//                            }
//                        }).collect(Collectors.toList());
////                            certificateValidator.saveCertificate(certificate);
//
//                        credIdAndCounters.setSignatureAlgorithm(alg);
//                        List<X509Certificate> trustAnchorCertificates = certificateSelector.selectRootCertificate(certificates.get(0));
//                        Certificate verifiedCert = certificateValidator.verifyCert(certificates, trustAnchorCertificates);
//                        commonVerifiers.verifyPackedAttestationSignature(authData.getAuthDataDecoded(), clientDataHash, signature, verifiedCert, alg);
//                    } else if (attStmt.hasNonNull("ecdaaKeyId")) {
//                        String ecdaaKeyId = attStmt.get("ecdaaKeyId").asText();
//                        throw new UnsupportedOperationException("TODO");
//                    } else {
//                        ECPublicKey ecPublicKey = uncompressedECPointHelper.getPublicKeyFromUncompressedECPoint(authData.getCOSEPublicKey());
//                        commonVerifiers.verifyPackedSurrogateAttestationSignature(authData.getAuthDataDecoded(), clientDataHash, signature, ecPublicKey, alg);
//                    }
//                }; break;
//
//                case "tpm": {
//                    commonVerifiers.verifyTPMVersion(attStmt.get("ver"));
//                    int alg = commonVerifiers.verifyAlgorithm(attStmt.get("alg"),authData.getKeyType());
//                    String signature = commonVerifiers.verifyBase64String(attStmt.get("sig"));
//                    if (attStmt.hasNonNull("x5c")) {
//                        Iterator<JsonNode> i = attStmt.get("x5c").elements();
//                        ArrayList<String> certificatePath = new ArrayList();
//                        while (i.hasNext()) {
//                            certificatePath.add(i.next().asText());
//                        }
//                        List<X509Certificate> certificates = certificatePath.parallelStream().map(f -> getCertificate(f)).filter(c -> {
//                            try {
//                                c.checkValidity();
//                                return true;
//                            } catch (CertificateException e) {
//                                LOGGER.warn("Certificate not valid {}" + c.getIssuerDN().getName());
//                                throw new Fido2RPRuntimeException("Certificate not valid ");
//                            }
//                        }).collect(Collectors.toList());
////                            certificateValidator.saveCertificate(certificate);
//
//                        credIdAndCounters.setSignatureAlgorithm(alg);
//                        List<X509Certificate> trustAnchorCertificates = certificateSelector.selectRootCertificate(certificates.get(0));
//                        Certificate verifiedCert = certificateValidator.verifyCert(certificates, trustAnchorCertificates);
//                        commonVerifiers.verifyPackedAttestationSignature(authData.getAuthDataDecoded(), clientDataHash, signature, verifiedCert, alg);
//                    } else if (attStmt.hasNonNull("ecdaaKeyId")) {
//                        String ecdaaKeyId = attStmt.get("ecdaaKeyId").asText();
//                        throw new UnsupportedOperationException("TODO");
//                    } else {
//                        ECPublicKey ecPublicKey = uncompressedECPointHelper.getPublicKeyFromUncompressedECPoint(authData.getCOSEPublicKey());
//                        commonVerifiers.verifyPackedSurrogateAttestationSignature(authData.getAuthDataDecoded(), clientDataHash, signature, ecPublicKey, alg);
//                    }
//                }
//                break;
//                default:
//                    throw new Fido2RPRuntimeException("Unsupported format");
//            }

            return credIdAndCounters;
        } catch (IOException e) {
            throw new Fido2RPRuntimeException("Problem with processing authenticator data");
        }
    }


}


