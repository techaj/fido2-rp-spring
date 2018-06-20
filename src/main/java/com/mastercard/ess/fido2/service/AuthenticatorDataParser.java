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

import com.fasterxml.jackson.core.JsonLocation;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORParser;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Base64;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

@Service
public class AuthenticatorDataParser {


    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticatorDataParser.class);
    @Autowired
    @Qualifier("base64UrlDecoder")
    private Base64.Decoder base64UrlDecoder;

    @Autowired
    @Qualifier("base64Decoder")
    private Base64.Decoder base64Decoder;


    @Autowired
    private CommonVerifiers commonVerifiers;

    AuthData parseAttestationData(String incomingAuthData){
        return parseAuthData(incomingAuthData, true);
    }

    public AuthData parseAssertionData(String incomingAuthData) {
        return parseAuthData(incomingAuthData, false);
    }

    private AuthData parseAuthData(String incomingAuthData, boolean isAttestation) {
        AuthData authData = new AuthData();
        byte[] buffer;

        buffer = base64Decoder.decode(incomingAuthData.getBytes());
        authData.setAuthDataDecoded(buffer);
        int offset = 0;
        byte[] rpIdHashBuffer = Arrays.copyOfRange(buffer, offset, offset += 32);
        LOGGER.info("RPIDHASH hex {}", Hex.encodeHexString(rpIdHashBuffer));
        byte[] flagsBuffer = Arrays.copyOfRange(buffer, offset, offset += 1);

        boolean hasAtFlag = commonVerifiers.verifyAtFlag(flagsBuffer);
        LOGGER.info("FLAGS hex {}", Hex.encodeHexString(flagsBuffer));

        byte[] counterBuffer = Arrays.copyOfRange(buffer, offset, offset += 4);
        LOGGER.info("COUNTERS hex {}", Hex.encodeHexString(counterBuffer));
        authData.setRpIdHash(rpIdHashBuffer).setFlags(flagsBuffer).setCounters(counterBuffer);
        byte[] attestationBuffer = Arrays.copyOfRange(buffer, offset, buffer.length);
        commonVerifiers.verifyAttestationBuffer(hasAtFlag, attestationBuffer);

        if (hasAtFlag) {
            byte[] aaguidBuffer = Arrays.copyOfRange(buffer, offset, offset += 16);
            LOGGER.info("AAGUID hex {}", Hex.encodeHexString(aaguidBuffer));

            byte[] credIDLenBuffer = Arrays.copyOfRange(buffer, offset, offset += 2);
            LOGGER.info("CredIDLen hex {}", Hex.encodeHexString(credIDLenBuffer));
            int size = ByteBuffer.wrap(credIDLenBuffer).asShortBuffer().get();
            LOGGER.info("size {}", size);
            byte[] credIDBuffer = Arrays.copyOfRange(buffer, offset, offset += size);
            LOGGER.info("credID hex {}", Hex.encodeHexString(credIDBuffer));

            byte[] cosePublicKeyBuffer = Arrays.copyOfRange(buffer, offset, buffer.length);
            LOGGER.info("cosePublicKey hex {}", Hex.encodeHexString(cosePublicKeyBuffer));
            CBORFactory f = new CBORFactory();

            long keySize = 0;
            try {
                CBORParser parser = f.createParser(cosePublicKeyBuffer);
                while (!parser.isClosed()) {
                    JsonToken t = parser.nextToken();
                    JsonLocation tocloc = parser.getTokenLocation();
                    if (t.isStructEnd()) {
                        keySize = tocloc.getByteOffset();
                        break;
                    }
                }
                parser.close();
            } catch (IOException e) {
                throw new Fido2RPRuntimeException(e.getMessage());
            }
            offset += keySize;
            ObjectMapper mapper = new ObjectMapper(f);

            int keyType = -100;
            try {
                JsonNode key = mapper.readTree(cosePublicKeyBuffer);
                keyType = key.get("3").asInt();
                LOGGER.info("cosePublicKey {}", key);
            } catch (IOException e) {
                throw new Fido2RPRuntimeException("Unable to parse public key CBOR");
            }
            authData.setAaguid(aaguidBuffer).setCredId(credIDBuffer).setCOSEPublicKey(cosePublicKeyBuffer).setKeyType(keyType);
            byte[] leftovers = Arrays.copyOfRange(buffer, offset, buffer.length);
            commonVerifiers.verifyNoLeftovers(leftovers);
        }



        return authData;
    }

    public int parseCounter(byte[] counter) {
        int cnt = ByteBuffer.wrap(counter).asIntBuffer().get();
        return cnt;
    }
}

