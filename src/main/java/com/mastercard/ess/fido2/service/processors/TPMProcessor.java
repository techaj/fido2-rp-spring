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
import com.mastercard.ess.fido2.certification.CertificationKeyStoreUtils;
import com.mastercard.ess.fido2.cryptoutils.COSEHelper;
import com.mastercard.ess.fido2.cryptoutils.CryptoUtils;
import com.mastercard.ess.fido2.ctap.AttestationFormat;
import com.mastercard.ess.fido2.database.FIDO2RegistrationEntity;
import com.mastercard.ess.fido2.service.AuthData;
import com.mastercard.ess.fido2.service.CertificateValidator;
import com.mastercard.ess.fido2.service.CommonVerifiers;
import com.mastercard.ess.fido2.service.CredAndCounterData;
import com.mastercard.ess.fido2.service.Fido2RPRuntimeException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;
import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import tss.tpm.TPMS_ATTEST;
import tss.tpm.TPMS_CERTIFY_INFO;
import tss.tpm.TPMT_PUBLIC;
import tss.tpm.TPM_GENERATED;

@Service
public class TPMProcessor implements AttestationFormatProcessor {
    private static final Logger LOGGER = LoggerFactory.getLogger(TPMProcessor.class);

    @Autowired
    CryptoUtils cryptoUtils;
    @Autowired
    CommonVerifiers commonVerifiers;
    @Autowired
    CertificationKeyStoreUtils utils;
    @Autowired
    CertificateValidator certificateValidator;
    @Autowired
    @Qualifier("cborMapper")
    ObjectMapper cborMapper;
    @Autowired
    COSEHelper uncompressedECPointHelper;
    @Autowired
    @Qualifier("base64Decoder")
    private Base64.Decoder base64Decoder;

    @Override
    public AttestationFormat getAttestationFormat() {
        return AttestationFormat.tpm;
    }

    @Override
    public void process(JsonNode attStmt, AuthData authData, FIDO2RegistrationEntity credential, byte[] clientDataHash, CredAndCounterData credIdAndCounters) {
        JsonNode cborPublicKey;
        try {
            cborPublicKey = cborMapper.readTree(authData.getCOSEPublicKey());
        } catch (IOException e) {
            throw new Fido2RPRuntimeException("Problem with TPM attestation");
        }

        byte[] hashedBuffer = getHashedBuffer(cborPublicKey.get("3").asInt(), authData.getAttestationBuffer(), clientDataHash);
        byte[] keyBufferFromAuthData = base64Decoder.decode(cborPublicKey.get("-1").asText());

        Iterator<JsonNode> i = attStmt.get("x5c").elements();

        String pubArea = attStmt.get("pubArea").asText();
        String certInfo = attStmt.get("certInfo").asText();

        if (i.hasNext()) {
            ArrayList<String> aikCertificatePath = new ArrayList();
            aikCertificatePath.add(i.next().asText());
            ArrayList<String> certificatePath = new ArrayList();

            while (i.hasNext()) {
                certificatePath.add(i.next().asText());
            }

            List<X509Certificate> certificates = cryptoUtils.getCertficates(certificatePath);
            List<X509Certificate> aikCertificates = cryptoUtils.getCertficates(aikCertificatePath);
            List<X509Certificate> trustAnchorCertificates = utils.getCertificates();
            X509Certificate verifiedCert = (X509Certificate) certificateValidator.verifyAttestationCertificates(certificates, trustAnchorCertificates);
            X509Certificate aikCertificate = aikCertificates.get(0);

            verifyTPMCertificateExtenstion(aikCertificate, authData);
            verifyAIKCertificate(aikCertificate, verifiedCert);

            String signature = commonVerifiers.verifyBase64String(attStmt.get("sig"));
            byte[] certInfoBuffer = base64Decoder.decode(certInfo);
            byte[] signatureBytes = base64Decoder.decode(signature.getBytes());

            commonVerifiers.verifySignature(signatureBytes, certInfoBuffer, aikCertificate, authData.getKeyType());

            byte[] pubAreaBuffer = base64Decoder.decode(pubArea);
            TPMT_PUBLIC tpmtPublic = TPMT_PUBLIC.fromTpm(pubAreaBuffer);
            TPMS_ATTEST tpmsAttest = TPMS_ATTEST.fromTpm(certInfoBuffer);


            verifyMagicInTpms(tpmsAttest);
            verifyTPMSCertificateName(tpmtPublic, tpmsAttest, pubAreaBuffer);
            verifyTPMSExtraData(hashedBuffer, tpmsAttest.extraData);
            verifyThatKeysAreSame(tpmtPublic, keyBufferFromAuthData);


        } else {
            throw new Fido2RPRuntimeException("Problem with TPM attestation. Unsupported ");
        }

    }

    private void verifyThatKeysAreSame(TPMT_PUBLIC tpmtPublic, byte[] keyBufferFromAuthData) {
        byte[] tmp = tpmtPublic.unique.toTpm();
        byte[] keyBufferFromTPM = Arrays.copyOfRange(tmp, 2, tmp.length);

        if (!Arrays.equals(keyBufferFromTPM, keyBufferFromAuthData)) {
            throw new Fido2RPRuntimeException("Problem with TPM attestation.");
        }
    }

    private void verifyTPMSExtraData(byte[] hashedBuffer, byte[] extraData) {
        if (!Arrays.equals(hashedBuffer, extraData)) {
            throw new Fido2RPRuntimeException("Problem with TPM attestation.");
        }
    }

    private void verifyTPMSCertificateName(TPMT_PUBLIC tpmtPublic, TPMS_ATTEST tpmsAttest, byte[] pubAreaBuffer) {

        byte[] pubAreaDigest;
        switch (tpmtPublic.nameAlg.asEnum()) {
            case SHA1:
            case SHA256: {
                pubAreaDigest = DigestUtils.getSha256Digest().digest(pubAreaBuffer);
            }
            break;
            default:
                throw new Fido2RPRuntimeException("Problem with TPM attestation");
        }
        // this is not really certificate info but nameAlgID + hex.encode(pubAreaDigest)
        // reverse engineered from FIDO Certification tool

        TPMS_CERTIFY_INFO certifyInfo = (TPMS_CERTIFY_INFO) tpmsAttest.attested;
        byte[] certificateName = Arrays.copyOfRange(certifyInfo.name, 2, certifyInfo.name.length);
        if (!Arrays.equals(certificateName, pubAreaDigest)) {
            throw new Fido2RPRuntimeException("Problem with TPM attestation.");
        }
    }

    private void verifyMagicInTpms(TPMS_ATTEST tpmsAttest) {
        if (tpmsAttest.magic.toInt() != TPM_GENERATED.VALUE.toInt()) {
            throw new Fido2RPRuntimeException("Problem with TPM attestation");
        }
    }

    private byte[] getHashedBuffer(int digestAlgorith, byte[] authenticatorDataBuffer, byte[] clientDataHashBuffer) {
        MessageDigest hashedBufferDigester = commonVerifiers.getDigest(digestAlgorith);
        byte[] b1 = authenticatorDataBuffer;
        byte[] b2 = clientDataHashBuffer;
        byte[] buffer = ByteBuffer.allocate(b1.length + b2.length).put(b1).put(b2).array();
        return hashedBufferDigester.digest(buffer);
    }

    private void verifyTPMCertificateExtenstion(X509Certificate aikCertificate, AuthData authData) {
        byte[] ext = aikCertificate.getExtensionValue("1 3 6 1 4 1 45724 1 1 4");
        if (ext != null && ext.length > 0) {
            String fidoAAGUID = new String(ext, Charset.forName("UTF-8"));
            if (!authData.getAaguid().equals(fidoAAGUID)) {
                throw new Fido2RPRuntimeException("Problem with TPM attestation");
            }
        }
    }

    private void verifyAIKCertificate(X509Certificate aikCertificate, X509Certificate rootCertificate) {
        try {
            aikCertificate.verify(rootCertificate.getPublicKey());
        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException e) {
            LOGGER.warn("Problem with AIK certificate {}", e.getMessage());
            throw new Fido2RPRuntimeException("Problem with TPM attestation");
        }
    }

}
