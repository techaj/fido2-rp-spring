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

package com.mastercard.ess.fido2.certification;

import com.fasterxml.jackson.databind.JsonNode;
import com.mastercard.ess.fido2.service.Fido2RPRuntimeException;
import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;


@Service
public class CertificationKeyStoreUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(CertificationKeyStoreUtils.class);

    @Autowired
    MetadataProcessor metadataProcessor;

    @Autowired
    KeyStoreCreator keyStoreCreator;

    @Autowired
    @Qualifier("base64Decoder")
    private Base64.Decoder base64Decoder;

    public KeyStore getCertificationKeyStore() {
        final CertificateFactory cf;
        try {
            cf = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new Fido2RPRuntimeException(e.getMessage());
        }

        Map<String, JsonNode> metadata = metadataProcessor.getMetadata();
        List<CertificateHolder> certHolders = metadata.entrySet().stream().map(de -> {
            List<CertificateHolder> certs = new ArrayList<>();
            Iterator<JsonNode> iter = de.getValue().get("attestationRootCertificates").iterator();
            int i = 0;
            while (iter.hasNext()) {
                try {
                    i++;
                    JsonNode certNode = iter.next();
                    ByteArrayInputStream certBytes = new ByteArrayInputStream(base64Decoder.decode(certNode.asText().getBytes("UTF-8")));
                    certs.add(new CertificateHolder(de.getKey() + "-" + i, cf.generateCertificate(certBytes)));
                } catch (CertificateException | UnsupportedEncodingException e) {
                    LOGGER.warn("Problem processing {} {}", de.getKey(), e.getMessage());
                }
            }

            return certs;
        }).flatMap(ch -> ch.stream()).collect(Collectors.toList());
        return keyStoreCreator.createKeyStore(certHolders);
    }

    public X509TrustManager populateTrustManager(KeyStore keyStore) {
        TrustManagerFactory trustManagerFactory = null;
        try {

            trustManagerFactory = TrustManagerFactory.getInstance("X509");
            trustManagerFactory.init(keyStore);
            TrustManager[] tms = trustManagerFactory.getTrustManagers();

            return (X509TrustManager) tms[0];

        } catch (NoSuchAlgorithmException | KeyStoreException e) {
            LOGGER.error("Unrecoverable problem with the platform", e);
            System.exit(1);
        }
        return null;
    }
}
