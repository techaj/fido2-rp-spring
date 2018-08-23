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

package com.mastercard.ess.fido2.certification;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

@Component
public class DirectoryBasedMetadataLoader implements ApplicationRunner {
    private static final Logger LOGGER = LoggerFactory.getLogger(DirectoryBasedMetadataLoader.class);

    @Value("${certification.server.metadata.folder}")
    private String certificationServerMetadataFolder;

    @Autowired
    private ObjectMapper om;

    @Autowired
    @Qualifier("authenticatorsMetadata")
    Map<String, JsonNode> authenticatorsMetadata;

    Map<String, JsonNode> getAAGUIDMapOfMetadata() {
        Path path = FileSystems.getDefault().getPath(certificationServerMetadataFolder);
        Map<String, JsonNode> nodes = Collections.synchronizedMap(new HashMap<>());
        DirectoryStream<Path> directoryStream = null;
        try {
            directoryStream = Files.newDirectoryStream(path);
            Iterator<Path> iter = directoryStream.iterator();
            while (iter.hasNext()) {
                Path filePath = iter.next();
                try {
                    LOGGER.info("Reading file {}", filePath);
                    BufferedReader reader = Files.newBufferedReader(filePath);
                    JsonNode jsonNode = om.readTree(reader);
                    if (jsonNode.hasNonNull("aaguid")) {
                        String aaguid = jsonNode.get("aaguid").asText();
                        String convertedAaguid = aaguid.replaceAll("-", "");
                        LOGGER.info("AAGUID conversion old {} new {}", aaguid, convertedAaguid);
                        nodes.put(convertedAaguid, jsonNode);
                    } else {
                        LOGGER.info("No aaguid for file path {}", filePath);
                    }
                } catch (IOException ex) {
                    LOGGER.warn("Can't process {} {}", filePath, ex.getMessage());
                }
            }

        } catch (IOException e) {
            LOGGER.warn("Something wrong with path ", e);
        } finally {
            if (directoryStream != null) {
                try {
                    directoryStream.close();
                } catch (IOException e) {
                    LOGGER.warn("Something wrong with directory stream", e);
                }
            }
        }
        return nodes;
    }

    @Override
    public void run(ApplicationArguments applicationArguments) throws Exception {
        LOGGER.info("Populating metadata from {}", certificationServerMetadataFolder);
        authenticatorsMetadata.putAll(getAAGUIDMapOfMetadata());
    }
}
