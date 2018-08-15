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

import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class CertificateValidator {
    private static final Logger LOGGER = LoggerFactory.getLogger(CertificateValidator.class);

    void saveCertificate(X509Certificate certificate) throws IOException {
        FileUtils.writeStringToFile(new File("c:/tmp/cert-" + certificate.getSerialNumber() + ".crt"), certificate.toString());
    }


    public Certificate verifyCert(List<X509Certificate> certs, List<X509Certificate> trustChainCertificates) {
        try {

            if (isSelfSigned(certs.get(0))) {
                return null;
            }

            Set<TrustAnchor> trustAnchors = trustChainCertificates.parallelStream().map(f -> new TrustAnchor(f, null)).collect(Collectors.toSet());
            PKIXParameters params = new PKIXParameters(trustAnchors);


            CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
//            PKIXRevocationChecker rc = (PKIXRevocationChecker)cpv.getRevocationChecker();
//            rc.setOptions(EnumSet.of(PKIXRevocationChecker.Option.SOFT_FAIL,PKIXRevocationChecker.Option.PREFER_CRLS));
//            params.addCertPathChecker(rc);
            params.setRevocationEnabled(false);
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            CertPath certPath = certFactory.generateCertPath(certs);
            try {
                CertPathValidatorResult result = cpv.validate(certPath, params);
                return certPath.getCertificates().get(0);
            } catch (CertPathValidatorException ex) {
                LOGGER.warn("Cert not validated against the root {}", ex.getMessage());
                throw new Fido2RPRuntimeException("Problem with certificate");
            }

        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | CertificateException e) {
            LOGGER.warn("Cert verification problem {}", e.getMessage(), e);
            throw new Fido2RPRuntimeException("Problem with certificate");
        }
    }

    private boolean isSelfSigned(X509Certificate cert) {
        try {
            // Try to verify certificate signature with its own public key
            PublicKey key = cert.getPublicKey();
            cert.verify(key);
            return cert.getIssuerDN().equals(cert.getSubjectDN());
        } catch (SignatureException | InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException e) {
            LOGGER.warn("Probably not self signed cert. Cert verification problem {}", e.getMessage());
            return false;
        }

    }


}
