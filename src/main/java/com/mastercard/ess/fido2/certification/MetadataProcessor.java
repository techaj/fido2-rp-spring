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
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class MetadataProcessor {
    private static final Logger LOGGER = LoggerFactory.getLogger(MetadataProcessor.class);

    @Value("${certification.server.metadata.folder}")
    private String certificationServerMetadataFolder;

    @Autowired
    private ObjectMapper om;

    public Map<String, JsonNode> getMetadata() {
        Path path = FileSystems.getDefault().getPath(certificationServerMetadataFolder);
        HashMap<String, JsonNode> nodes = new HashMap<>();
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
                        nodes.put(aaguid, jsonNode);
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
}
