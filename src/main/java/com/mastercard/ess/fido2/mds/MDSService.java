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

package com.mastercard.ess.fido2.mds;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mastercard.ess.fido2.service.CommonVerifiers;
import com.mastercard.ess.fido2.service.Fido2RPRuntimeException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class MDSService {

    private static final Logger LOGGER = LoggerFactory.getLogger(MDSService.class);
    @Autowired
    CommonVerifiers commonVerifiers;
    @Autowired
    @Qualifier("mdsRestTemplate")
    RestTemplate restTemplate;
    @Autowired
    @Qualifier("tocEntries")
    Map<String, JsonNode> tocEntries;
    @Autowired
    ObjectMapper om;
    @Autowired
    TOCEntryDigester tocEntryDigester;
    @Value("${mds.service.accesstoken}")
    private String mdsServiceAccessToken;
    @Value("${mds.service.url}")
    private String mdsServiceUrl;
    @Autowired
    @Qualifier("base64UrlDecoder")
    private Base64.Decoder base64UrlDecoder;

    public JsonNode fetchMetadata(byte[] aaguidBuffer) {
        String aaguid = deconvert(aaguidBuffer);

        JsonNode tocEntry = tocEntries.get(aaguid);
        if (tocEntry == null) {
            throw new Fido2RPRuntimeException("Authenticator not in TOC aaguid " + aaguid);
        }

        URI metadataUrl;
        try {
            metadataUrl = new URI(tocEntry.get("url").asText());
            LOGGER.info("Authenticator AAGUI {} url metadataUrl {} ", aaguid, metadataUrl);
        } catch (URISyntaxException e) {
            throw new Fido2RPRuntimeException("Invalid URI in TOC aaguid " + aaguid);
        }

        verifyTocEntryStatus(aaguid, tocEntry);
        String metadataHash = commonVerifiers.verifyThatString(tocEntry.get("hash"));

        LOGGER.info("Reaching MDS at {}", metadataUrl.toString());


        HttpHeaders headers = new HttpHeaders();
        headers.set("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        ResponseEntity<String> response = restTemplate.getForEntity(metadataUrl, String.class);
        String body = response.getBody();

        HttpStatus status = response.getStatusCode();
        LOGGER.info("Response from resource server {}", response.getStatusCode());
        if (status.is2xxSuccessful()) {
            byte[] bodyBuffer;
            try {
                bodyBuffer = body.getBytes("UTF-8");
            } catch (UnsupportedEncodingException e) {
                throw new Fido2RPRuntimeException("Unable to verify metadata hash for aaguid " + deconvert(aaguidBuffer));
            }
            byte[] digest = tocEntryDigester.getDigester().digest(bodyBuffer);
            if (!Arrays.equals(digest, base64UrlDecoder.decode(metadataHash))) {
                throw new Fido2RPRuntimeException("Unable to verify metadata hash for aaguid " + deconvert(aaguidBuffer));
            }

            try {
                return om.readTree(base64UrlDecoder.decode(body));
            } catch (IOException e) {
                LOGGER.warn("Can't parse payload from the server ");
                throw new Fido2RPRuntimeException("Unable to parse payload from server for aaguid " + deconvert(aaguidBuffer));
            }
        } else {
            throw new Fido2RPRuntimeException("Unable to retrieve metadata for aaguid " + deconvert(aaguidBuffer) + " status " + status);
        }
    }

    private void verifyTocEntryStatus(String aaguid, JsonNode tocEntry) {

        JsonNode statusReports = tocEntry.get("statusReports");


        Iterator<JsonNode> iter = statusReports.elements();
        while (iter.hasNext()) {
            JsonNode statusReport = iter.next();
            AuthenticatorStatus authenticatorStatus = AuthenticatorStatus.valueOf(statusReport.get("status").asText());
            String authenticatorEffectiveDate = statusReport.get("effectiveDate").asText();
            LOGGER.info("Authenticator AAGUI {} status {} effective date {}", aaguid, authenticatorStatus, authenticatorEffectiveDate);
            verifyStatusAcceptaable(aaguid, authenticatorStatus);
        }
    }

    ;

    private String deconvert(byte[] aaguidBuffer) {
        return Hex.encodeHexString(aaguidBuffer).replaceFirst("([0-9a-fA-F]{8})([0-9a-fA-F]{4})([0-9a-fA-F]{4})([0-9a-fA-F]{4})([0-9a-fA-F]+)", "$1-$2-$3-$4-$5");
    }

    private void verifyStatusAcceptaable(String aaguid, AuthenticatorStatus status) {
        final List<AuthenticatorStatus> undesiredAuthenticatorStatus = Arrays.asList(new AuthenticatorStatus[]{AuthenticatorStatus.USER_VERIFICATION_BYPASS, AuthenticatorStatus.ATTESTATION_KEY_COMPROMISE, AuthenticatorStatus.USER_KEY_REMOTE_COMPROMISE, AuthenticatorStatus.USER_KEY_PHYSICAL_COMPROMISE, AuthenticatorStatus.ATTESTATION_KEY_COMPROMISE, AuthenticatorStatus.NOT_FIDO_CERTIFIED, AuthenticatorStatus.SELF_ASSERTION_SUBMITTED});
        if (undesiredAuthenticatorStatus.contains(status)) {
            throw new Fido2RPRuntimeException("Authenticator " + aaguid + "status undesirable " + status);
        }


    }


}
