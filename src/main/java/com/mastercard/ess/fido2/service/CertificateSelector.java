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
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class CertificateSelector {
    private static final Logger LOGGER = LoggerFactory.getLogger(CertificateSelector.class);

    @Value("${certs.location}")
    private String certsLocation;

    X509Certificate selectRootCertificate(X509Certificate certificate) {
        try {

            switch(certificate.getIssuerDN().getName()){
                case "CN=Yubico U2F Root CA Serial 457200631": return (X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(new FileInputStream(new File(certsLocation+"yubico-u2f-ca-certs.crt")));
                default:
                    throw new RuntimeException("Can't find certificate");
            }
        } catch (CertificateException | FileNotFoundException e) {
            LOGGER.info("Problem {} ", e.getMessage());
            throw new RuntimeException(e);
        }

    }

}
