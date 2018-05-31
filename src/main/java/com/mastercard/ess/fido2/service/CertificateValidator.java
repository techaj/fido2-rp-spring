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
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
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


    void verifyCert(X509Certificate cert, java.security.cert.X509Certificate rootCertificate) {
        try {
            if (isSelfSigned(cert)) {
                return;
            }

            TrustAnchor trustAnchor = new TrustAnchor(rootCertificate, null);
            Set<TrustAnchor> trustAnchors = new HashSet(Arrays.asList(new TrustAnchor[]{trustAnchor}));
            PKIXParameters params = new PKIXParameters(trustAnchors);
            params.setRevocationEnabled(false);
            CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            CertPath certPath = certFactory.generateCertPath(Arrays.asList(new Certificate[]{cert}));
            try {
                cpv.validate(certPath, params);
            } catch (CertPathValidatorException ex) {
                LOGGER.warn("Cert not validated against the root {}", ex.getMessage(), ex);
            }

        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | CertificateException e) {
            LOGGER.warn("Cert verification problem {}", e.getMessage(), e);
            throw new RuntimeException(e);
        }
    }

    private boolean isSelfSigned(X509Certificate cert) {
        return cert.getIssuerDN().equals(cert.getSubjectDN());
    }
}
