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

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

@Service
public class KeyStoreCreator {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeyStoreCreator.class);

    @Autowired
    @Qualifier("base64Encoder")
    private Base64.Encoder base64Encoder;

    public KeyStore createKeyStore(List<CertificateHolder> certificates) {
        byte[] password = new byte[200];
        new SecureRandom().nextBytes(password);

        try {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, base64Encoder.encodeToString(password).toCharArray());

            certificates.stream().forEach(ch -> {
                try {
                    ks.setCertificateEntry(ch.alias, ch.cert);
                } catch (KeyStoreException e) {
                    LOGGER.warn("Can't load certificate {} {}", ch.alias, e.getMessage());
                }
            });
            return ks;
        } catch (IOException | NoSuchAlgorithmException | CertificateException | KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }


}
