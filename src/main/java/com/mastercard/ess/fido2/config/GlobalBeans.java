

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

package com.mastercard.ess.fido2.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.mastercard.ess.fido2.ctap.AttestationFormat;
import java.security.Provider;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;


@Configuration
public class GlobalBeans {

    @Bean(name="cborMapper")
    public ObjectMapper getCborMapper() {
        return new ObjectMapper(new CBORFactory());
    }

    @Bean(name="base64UrlEncoder")
    public Base64.Encoder getBase64UrlEncoder() {
        return Base64.getUrlEncoder().withoutPadding();
    }

    @Bean(name = "base64Encoder")
    public Base64.Encoder getBase64Encoder() {
        return Base64.getEncoder().withoutPadding();
    }

    @Bean(name="base64UrlDecoder")
    public Base64.Decoder getBase64UrlDecoder() {
        return Base64.getUrlDecoder();
    }

    @Bean(name="base64Decoder")
    public Base64.Decoder getBase64Decoder() {
        return Base64.getDecoder();
    }


    @Primary
    @Bean
    public ObjectMapper getJsonMapper() {
        return new ObjectMapper();
    }

    @Bean
    Provider getBouncyCastleProvider() {
        BouncyCastleProvider p = new BouncyCastleProvider();
        return p;
    }

    @Bean(name = "supportedAttestationFormats")
    public List<String> getSupportedAttestationFormats() {
        return Arrays.stream(AttestationFormat.values()).map(f -> f.getFmt()).collect(Collectors.toList());
    }

}
