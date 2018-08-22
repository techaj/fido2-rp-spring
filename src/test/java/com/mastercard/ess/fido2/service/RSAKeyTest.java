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

import java.math.BigInteger;
import java.util.Base64;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.junit.Test;

public class RSAKeyTest {

    @Test
    public void test1() {
        byte[] nBuff = Base64.getUrlDecoder().decode("qsoJFK1az5IhMV54v-d__UAmB-K5i4H0raBG6g0NiaITB7meIoIXK2cqX-Uch1bY7kPJ4rxnbmMVCLBmOSoyAi_nf6LiAic9P5xqekZymGjTb0qFVAV6oyetVWHg8lYUp6tL2x6aw7QAnTWhLIPJfdZCYUGqmkiGqg3K8XiiVyhssPbxhz72uYRWqC_t77KeKSoH5RdKnrZUP5CmAWPTOiucJfJlapi6B9RAeye9jYnZUf2jUxhZliG347N6AB2DahauvQiEv1T7gAEiSNWJ1NZIzj450nDo2LtN2kt3Y8QW35_1lDbKFpHkTg7c_S8wcU4cBDfweLx0MeBvptE_Ww");
        byte[] eBuff = Base64.getUrlDecoder().decode("AQAB");
        BigInteger n = new BigInteger(nBuff);
        BigInteger e = new BigInteger(eBuff);
        RSAKeyParameters rsaKeyParameters = new RSAKeyParameters(false, n, e);
    }
}
