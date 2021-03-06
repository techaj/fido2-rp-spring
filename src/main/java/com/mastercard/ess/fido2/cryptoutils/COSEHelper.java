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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mastercard.ess.fido2.ctap.CoseEC2Algorithm;
import com.mastercard.ess.fido2.ctap.CoseKeyType;
import com.mastercard.ess.fido2.ctap.CoseRSAAlgorithm;
import com.mastercard.ess.fido2.service.Fido2RPRuntimeException;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;


@Service
public class COSEHelper {
    private static final byte UNCOMPRESSED_POINT_INDICATOR = 0x04;
    private static final Logger LOGGER = LoggerFactory.getLogger(COSEHelper.class);

    @Autowired
    @Qualifier("base64Decoder")
    private Base64.Decoder base64Decoder;

    @Autowired
    @Qualifier("base64UrlDecoder")
    private Base64.Decoder base64UrlDecoder;

    @Autowired
    @Qualifier("cborMapper")
    ObjectMapper cborMapper;

    @Autowired
    Provider provider;

    private static String convertCoseCurveToSunCurveName(int curve) {
        switch (curve) {
            case 1:
                return "secp256r1";
            default:
                throw new Fido2RPRuntimeException("Unsupported curve");
        }
    }

    public int getCodeCurve(JsonNode uncompressedECPointNode) {
        return uncompressedECPointNode.get("-1").asInt();
    }

    public PublicKey createUncompressedPointFromCOSEPublicKey(JsonNode uncompressedECPointNode) {
        int keyToUse = uncompressedECPointNode.get("1").asInt();
        int algorithmToUse = uncompressedECPointNode.get("3").asInt();
        CoseKeyType keyType = CoseKeyType.fromNumericValue(keyToUse);

        switch (keyType) {
            case RSA: {
                CoseRSAAlgorithm coseRSAAlgorithm = CoseRSAAlgorithm.fromNumericValue(algorithmToUse);
                switch (coseRSAAlgorithm) {
                    case RS65535:
                    case RS256: {
                        byte[] rsaKey_n = base64Decoder.decode(uncompressedECPointNode.get("-1").asText());
                        byte[] rsaKey_e = base64Decoder.decode(uncompressedECPointNode.get("-2").asText());
                        return convertUncompressedPointToRSAKey(rsaKey_n, rsaKey_e);
                    }
                    default: {
                        throw new Fido2RPRuntimeException("Don't know what to do with this key" + keyType);
                    }
                }
            }
            case EC2: {
                CoseEC2Algorithm coseEC2Algorithm = CoseEC2Algorithm.fromNumericValue(algorithmToUse);
                switch (coseEC2Algorithm) {
                    case ES256: {
                        int curve = uncompressedECPointNode.get("-1").asInt();
                        byte[] x = base64Decoder.decode(uncompressedECPointNode.get("-2").asText());
                        byte[] y = base64Decoder.decode(uncompressedECPointNode.get("-3").asText());
                        byte[] buffer = ByteBuffer.allocate(1 + x.length + y.length).put(UNCOMPRESSED_POINT_INDICATOR).put(x).put(y).array();
                        return convertUncompressedPointToECKey(buffer, curve);
                    }
                    default: {
                        throw new Fido2RPRuntimeException("Don't know what to do with this key" + keyType + " and algorithm " + coseEC2Algorithm);
                    }
                }
            }
            case OKP: {
                throw new Fido2RPRuntimeException("Don't know what to do with this key" + keyType);
            }
            default:
                throw new Fido2RPRuntimeException("Don't know what to do with this key" + keyType);
        }

    }

    private PublicKey convertUncompressedPointToRSAKey(byte[] rsaKey_n, byte[] rsaKey_e) {
        AlgorithmParameters parameters = null;
        try {

            BigInteger n = new BigInteger(1, rsaKey_n);
            BigInteger e = new BigInteger(1, rsaKey_e);
            RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(n, e);
            final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(publicKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            LOGGER.error("Problem here ", e);
            throw new Fido2RPRuntimeException(e.getMessage());
        }
    }

    public ECPublicKey convertUncompressedPointToECKey(final byte[] uncompressedPoint, int curve) {
        AlgorithmParameters parameters = null;
        try {
            parameters = AlgorithmParameters.getInstance("EC");

            parameters.init(new ECGenParameterSpec(convertCoseCurveToSunCurveName(curve)));
            ECParameterSpec params = parameters.getParameterSpec(ECParameterSpec.class);

            int offset = 0;
            if (uncompressedPoint[offset++] != UNCOMPRESSED_POINT_INDICATOR) {
                throw new IllegalArgumentException(
                        "Invalid uncompressedPoint encoding, no uncompressed point indicator");
            }

            int keySizeBytes = (params.getOrder().bitLength() + Byte.SIZE - 1)
                    / Byte.SIZE;

            if (uncompressedPoint.length != 1 + 2 * keySizeBytes) {
                throw new IllegalArgumentException(
                        "Invalid uncompressedPoint encoding, not the correct size");
            }

            final BigInteger x = new BigInteger(1, Arrays.copyOfRange(
                    uncompressedPoint, offset, offset + keySizeBytes));
            offset += keySizeBytes;
            final BigInteger y = new BigInteger(1, Arrays.copyOfRange(
                    uncompressedPoint, offset, offset + keySizeBytes));
            final ECPoint w = new ECPoint(x, y);
            final ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(w, params);
            final KeyFactory keyFactory = KeyFactory.getInstance("EC");
            return (ECPublicKey) keyFactory.generatePublic(ecPublicKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidParameterSpecException e) {
            throw new Fido2RPRuntimeException(e.getMessage());
        }
    }

    public PublicKey getPublicKeyFromUncompressedECPoint(byte[] uncompressedECPointCOSEPubKey) {
        JsonNode uncompressedECPointNode = null;
        try {
            uncompressedECPointNode = cborMapper.readTree(uncompressedECPointCOSEPubKey);
        } catch (IOException e) {
            throw new Fido2RPRuntimeException("Unable to parse the structure ");
        }
        LOGGER.debug("Uncompressed ECpoint node {}", uncompressedECPointNode.toString());
        PublicKey publicKey = createUncompressedPointFromCOSEPublicKey(uncompressedECPointNode);
        LOGGER.debug("EC Public key hex {}", Hex.encodeHexString(publicKey.getEncoded()));
        return publicKey;
    }
}
