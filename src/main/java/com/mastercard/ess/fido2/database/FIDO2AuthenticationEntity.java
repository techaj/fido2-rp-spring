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

package com.mastercard.ess.fido2.database;

import javax.persistence.Access;
import javax.persistence.AccessType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Lob;
import javax.persistence.Table;


@Entity
@Table(name = "FIDO2_AUTHENTICATION")
public class FIDO2AuthenticationEntity extends FIDO2Entity {

    @Id
    @Access(AccessType.PROPERTY)
    @Column(name = "Id")
    private String id;

    @Column(name = "registrationId",length = 255)
    private String registrationId;

    @Column(name = "Username",length = 255)
    private String username;

    @Column(name = "Domain",length = 255)
    private String domain;

    @Column(name = "UserID",length = 255)
    private String userId;

    @Column(name = "Challenge",length = 512)
    private String challenge;

    @Lob
    @Column(name = "CredentialRequestOptions")
    private String w3cCredentialRequestOptions;

    @Lob
    @Column(name = "AuthenticatorAttestationResponse")
    private String w3cAuthenticatorAssertionResponse;


    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getChallenge() {
        return challenge;
    }

    public void setChallenge(String challenge) {
        this.challenge = challenge;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }


    @Override
    public String getId() {
        return id;
    }

    @Override
    protected void setId(String id) {
        this.id = id;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    @Override
    public boolean equals(Object o) {
        return super.equals(o);     // Sonar complains that equals/hashCode should be defined here
    }

    public String getRegistrationId() {
        return registrationId;
    }

    public void setRegistrationId(String registrationId) {
        this.registrationId = registrationId;
    }

    public String getW3cCredentialRequestOptions() {
        return w3cCredentialRequestOptions;
    }

    public void setW3cCredentialRequestOptions(String w3cCredentialRequestOptions) {
        this.w3cCredentialRequestOptions = w3cCredentialRequestOptions;
    }

    public String getW3cAuthenticatorAssertionResponse() {
        return w3cAuthenticatorAssertionResponse;
    }

    public void setW3cAuthenticatorAssertionResponse(String w3cAuthenticatorAssertionResponse) {
        this.w3cAuthenticatorAssertionResponse = w3cAuthenticatorAssertionResponse;
    }

    @Override
    public int hashCode() {
        return super.hashCode();    // Sonar complains that equals/hashCode should be defined here
    }
}
