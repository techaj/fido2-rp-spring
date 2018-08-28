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

package com.mastercard.ess.fido2.service.processors;

import com.fasterxml.jackson.databind.JsonNode;
import com.mastercard.ess.fido2.ctap.AttestationFormat;
import com.mastercard.ess.fido2.database.FIDO2RegistrationEntity;
import com.mastercard.ess.fido2.service.AuthData;
import com.mastercard.ess.fido2.service.CredAndCounterData;


public interface AttestationFormatProcessor {
    AttestationFormat getAttestationFormat();

    void process(JsonNode attStmt, AuthData authData, FIDO2RegistrationEntity credential, byte[] clientDataHash, CredAndCounterData credIdAndCounters);


}
