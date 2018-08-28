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

import java.security.SecureRandom;
import java.util.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

@Service
public class ChallengeGenerator {

    @Autowired
    @Qualifier("base64UrlEncoder")
    private Base64.Encoder base64UrlEncoder;

    public String getChallenge() {
        byte buffer[] = new byte[32];
        new SecureRandom().nextBytes(buffer);
        return base64UrlEncoder.withoutPadding().encodeToString(buffer);
    }
}
