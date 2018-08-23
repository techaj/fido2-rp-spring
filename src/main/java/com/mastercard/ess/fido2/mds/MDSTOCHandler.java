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
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.mastercard.ess.fido2.service.Fido2RPRuntimeException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Service;

@Service
public class MDSTOCHandler implements ApplicationRunner {
    private static final Logger LOGGER = LoggerFactory.getLogger(MDSTOCHandler.class);
    @Autowired
    ObjectMapper om;
    @Autowired
    @Qualifier("tocEntries")
    Map<String, JsonNode> tocEntries;
    @Autowired
    TOCEntryDigester tocEntryDigester;
    @Value("${mds.toc.file.location}")
    private String mdsTocFileLocation;

    public Map<String, JsonNode> parseTOC() {
        Path path = FileSystems.getDefault().getPath(mdsTocFileLocation);
        BufferedReader reader = null;
        try {
            reader = Files.newBufferedReader(path);
            JWSObject jwsObject = JWSObject.parse(reader.readLine());
            JWSAlgorithm algorithm = jwsObject.getHeader().getAlgorithm();
            tocEntryDigester.setDigester(resolveDigester(algorithm));
            String jwtPayload = jwsObject.getPayload().toString();
            JsonNode toc = om.readTree(jwtPayload);
            LOGGER.info("Legal header {}", toc.get("legalHeader"));
            ArrayNode entries = (ArrayNode) toc.get("entries");
            int numberOfEntries = toc.get("no").asInt();
            LOGGER.info("Number of entries {} {}", numberOfEntries, entries.size());
            Iterator<JsonNode> iter = entries.elements();
            Map<String, JsonNode> tocEntries = new HashMap<>();
            while (iter.hasNext()) {
                JsonNode tocEntry = iter.next();
                tocEntries.put(tocEntry.get("aaguid").asText(), tocEntry);
            }

            return tocEntries;
        } catch (IOException e) {
            throw new Fido2RPRuntimeException("Unable to read TOC at " + mdsTocFileLocation);
        } catch (ParseException e) {
            throw new Fido2RPRuntimeException("Unable to parse TOC at " + mdsTocFileLocation);
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    LOGGER.warn("Unable to close reader {}", path);
                }
            }
        }

    }

    private MessageDigest resolveDigester(JWSAlgorithm algorithm) {
        if (JWSAlgorithm.ES256.equals(algorithm)) {
            return DigestUtils.getSha256Digest();
        } else {
            throw new Fido2RPRuntimeException("Don't know what to do with " + algorithm);
        }
    }

    @Override
    public void run(ApplicationArguments applicationArguments) throws Exception {
        LOGGER.info("Populating TOC entries from {}", mdsTocFileLocation);
        tocEntries.putAll(parseTOC());
    }
}
