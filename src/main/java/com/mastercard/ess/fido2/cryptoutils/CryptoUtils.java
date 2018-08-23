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

package com.mastercard.ess.fido2.cryptoutils;

import com.mastercard.ess.fido2.service.Fido2RPRuntimeException;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;


@Service
public class CryptoUtils {
    private static final Logger LOGGER = LoggerFactory.getLogger(CryptoUtils.class);
    @Autowired
    @Qualifier("base64Decoder")
    private Base64.Decoder base64Decoder;


    public X509Certificate getCertificate(String x509certificate) {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(base64Decoder.decode(x509certificate)));
        } catch (CertificateException e) {
            throw new Fido2RPRuntimeException(e.getMessage());
        }
    }

    public List<X509Certificate> getCertificates(List<String> certificatePath) {
        final CertificateFactory cf;
        try {
            cf = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new Fido2RPRuntimeException(e.getMessage());
        }

        return certificatePath.parallelStream().map(x509certificate -> {
            try {
                return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(base64Decoder.decode(x509certificate)));
            } catch (CertificateException e) {
                throw new Fido2RPRuntimeException(e.getMessage());
            }
        }).filter(c -> {
            try {
                c.checkValidity();
                return true;
            } catch (CertificateException e) {
                LOGGER.warn("Certificate not valid {}", c.getIssuerDN().getName());
                throw new Fido2RPRuntimeException("Certificate not valid ");
            }
        }).collect(Collectors.toList());

    }
}
