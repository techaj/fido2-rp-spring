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

import com.fasterxml.jackson.databind.JsonNode;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

@Service
class UncompressedECPointHelper {
    private static final byte UNCOMPRESSED_POINT_INDICATOR = 0x04;

    @Autowired
    @Qualifier("base64Decoder")
    private Base64.Decoder base64Decoder;

    int getCodeCurve(JsonNode uncompressedECPointNode){
        return  uncompressedECPointNode.get("-1").asInt();
    }

    byte[] createUncompressedPointFromCOSEPublicKey(JsonNode uncompressedECPointNode){
        byte[] x = base64Decoder.decode(uncompressedECPointNode.get("-2").asText());
        byte[] y = base64Decoder.decode(uncompressedECPointNode.get("-3").asText());
        return ByteBuffer.allocate(1+x.length+y.length).put(UNCOMPRESSED_POINT_INDICATOR).put(x).put(y).array();
    }

    ECPublicKey convertUncompressedPointToECKey(final byte[] uncompressedPoint,int curve)
            throws Exception {

        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec(convertCoseCurveToSunCurveName(curve)));
        ECParameterSpec params= parameters.getParameterSpec(ECParameterSpec.class);

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
    }

    private static String convertCoseCurveToSunCurveName(int curve) {
        switch(curve){
            case 1:return "secp256r1";
            default: throw new Fido2RPRuntimeException("Unsupported curve");
        }
    }
}
