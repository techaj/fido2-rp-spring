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
import com.mastercard.ess.fido2.cryptoutils.AndroidKeyUtils;
import com.mastercard.ess.fido2.cryptoutils.CryptoUtils;
import com.mastercard.ess.fido2.database.FIDO2RegistrationEntity;
import com.mastercard.ess.fido2.service.AttestationFormat;
import com.mastercard.ess.fido2.service.AuthData;
import com.mastercard.ess.fido2.service.CertificateValidator;
import com.mastercard.ess.fido2.service.CommonVerifiers;
import com.mastercard.ess.fido2.service.CredAndCounterData;
import com.mastercard.ess.fido2.service.Fido2RPRuntimeException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

@Service
public class AndroidKeyAttestationProcessor implements AttestationFormatProcessor {
    private static final Logger LOGGER = LoggerFactory.getLogger(AndroidKeyAttestationProcessor.class);
    @Autowired
    CommonVerifiers commonVerifiers;
    @Autowired
    @Qualifier("cborMapper")
    ObjectMapper cborMapper;

    @Autowired
    CryptoUtils cryptoUtils;
    @Autowired
    CertificateValidator certificateValidator;
    @Autowired
    AndroidKeyUtils androidKeyUtils;
    @Autowired
    CertificationKeyStoreUtils utils;
    @Autowired
    @Qualifier("base64Decoder")
    private Base64.Decoder base64Decoder;

    @Override
    public AttestationFormat getAttestationFormat() {
        return AttestationFormat.android_key;
    }

    @Override
    public void process(JsonNode attStmt, AuthData authData, FIDO2RegistrationEntity credential, byte[] clientDataHash, CredAndCounterData credIdAndCounters) {

        LOGGER.info("Android-key payload ");

        Iterator<JsonNode> i = attStmt.get("x5c").elements();

        ArrayList<String> certificatePath = new ArrayList();
        while (i.hasNext()) {
            certificatePath.add(i.next().asText());
        }
        List<X509Certificate> certificates = cryptoUtils.getCertficates(certificatePath);
        List<X509Certificate> trustAnchorCertificates = utils.getCertificates();
        X509Certificate verifiedCert = (X509Certificate) certificateValidator.verifyCert(certificates, trustAnchorCertificates);
        ECPublicKey pubKey = (ECPublicKey) verifiedCert.getPublicKey();

        try {
            ASN1Sequence extensionData = androidKeyUtils.extractAttestationSequence(verifiedCert);
            int attestationVersion = androidKeyUtils.getIntegerFromAsn1(extensionData.getObjectAt(AndroidKeyUtils.ATTESTATION_VERSION_INDEX));
            int attestationSecurityLevel = androidKeyUtils.getIntegerFromAsn1(extensionData.getObjectAt(AndroidKeyUtils.ATTESTATION_SECURITY_LEVEL_INDEX));
            int keymasterSecurityLevel = androidKeyUtils.getIntegerFromAsn1(extensionData.getObjectAt(AndroidKeyUtils.KEYMASTER_SECURITY_LEVEL_INDEX));
            byte[] attestationChallenge = ((ASN1OctetString) extensionData.getObjectAt(AndroidKeyUtils.ATTESTATION_CHALLENGE_INDEX)).getOctets();

            if (!Arrays.equals(clientDataHash, attestationChallenge)) {
                throw new Fido2RPRuntimeException("Invalid android key attestation ");
            }

            ASN1Encodable[] softwareEnforced = ((ASN1Sequence) extensionData.getObjectAt(AndroidKeyUtils.SW_ENFORCED_INDEX)).toArray();
            ASN1Encodable[] teeEnforced = ((ASN1Sequence) extensionData.getObjectAt(AndroidKeyUtils.TEE_ENFORCED_INDEX)).toArray();

        } catch (Exception e) {
            LOGGER.warn("Problem with android key", e);
            throw new Fido2RPRuntimeException("Problem with android key");
        }
        String signature = commonVerifiers.verifyBase64String(attStmt.get("sig"));
        commonVerifiers.verifyAttestationSignature(authData, clientDataHash, signature, verifiedCert, authData.getKeyType());

//        credIdAndCounters.setAttestationType(getAttestationFormat().getFmt());
//        credIdAndCounters.setCredId(base64UrlEncoder.encodeToString(authData.getCredId()));
//        credIdAndCounters.setUncompressedEcPoint(base64UrlEncoder.encodeToString(authData.getCOSEPublicKey()));
    }

}


