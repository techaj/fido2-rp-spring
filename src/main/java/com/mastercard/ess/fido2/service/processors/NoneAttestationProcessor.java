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
import com.mastercard.ess.fido2.service.CommonVerifiers;
import com.mastercard.ess.fido2.service.CredAndCounterData;
import com.mastercard.ess.fido2.service.Fido2RPRuntimeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;


@Service
public class NoneAttestationProcessor implements AttestationFormatProcessor {
    private static final Logger LOGGER = LoggerFactory.getLogger(NoneAttestationProcessor.class);
    @Autowired
    CommonVerifiers commonVerifiers;

    @Override
    public AttestationFormat getAttestationFormat() {
        return AttestationFormat.none;
    }

    @Override
    public void process(JsonNode attStmt, AuthData authData, FIDO2RegistrationEntity credential, byte[] clientDataHash, CredAndCounterData credIdAndCounters) {
        LOGGER.info("None/Surrogate attestation {}", attStmt);
        if (attStmt.iterator().hasNext()) {
            throw new Fido2RPRuntimeException("Problem with None/Surrogate attestation");
        }
        credIdAndCounters.setAttestationType(getAttestationFormat().getFmt());

    }
}
