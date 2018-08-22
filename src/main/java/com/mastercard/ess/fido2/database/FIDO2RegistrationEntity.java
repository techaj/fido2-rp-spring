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

import com.mastercard.ess.fido2.ctap.AttestationConveyancePreference;
import javax.persistence.Access;
import javax.persistence.AccessType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Lob;
import javax.persistence.Table;

@Entity
@Table(name = "FIDO2_REGISTRATION")
public class FIDO2RegistrationEntity extends FIDO2Entity {

    @Id
    @Access(AccessType.PROPERTY)
    @Column(name = "Id")
    private String id;


    @Column(name = "Username",length = 255)
    private String username;

    @Column(name = "Domain",length = 255)
    private String domain;

    @Column(name = "UserID",length = 255)
    private String userId;

    @Column(name = "Challenge",length = 512)
    private String challenge;

    @Lob
    @Column(name = "CredentialCreationOptions")
    private String w3cCredentialCreationOptions;

    @Lob
    @Column(name = "AuthenticatorAttestationResponse")
    private String w3cAuthenticatorAttenstationResponse;

    @Lob
    @Column(name = "ECPoint")
    private String uncompressedECPoint;


    @Column(name = "RegistrationKeyId", length = 512)
    private String publicKeyId;


    @Column(name = "RegistrationKeyType", length = 512)
    private String type;

    @Column(name = "Status", length = 32)
    private RegistrationStatus status;

    @Column(name = "Counter")
    private int counter;

    @Column(name = "AttestationType",length = 128)
    private String attestationType;

    @Column(name = "SigAlgorithmType")
    private int signatureAlgorithm;

    @Column(name = "AttestationConveyancePreference")
    private AttestationConveyancePreference attestationConveyancePreferenceType;

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



    public String getW3cCredentialCreationOptions() {
        return w3cCredentialCreationOptions;
    }

    public void setW3cCredentialCreationOptions(String w3cCredentialCreationOptions) {
        this.w3cCredentialCreationOptions = w3cCredentialCreationOptions;
    }

    public String getW3cAuthenticatorAttenstationResponse() {
        return w3cAuthenticatorAttenstationResponse;
    }

    public void setW3cAuthenticatorAttenstationResponse(String w3cAuthenticatorAttenstationResponse) {
        this.w3cAuthenticatorAttenstationResponse = w3cAuthenticatorAttenstationResponse;
    }

    public String getPublicKeyId() {
        return publicKeyId;
    }

    public void setPublicKeyId(String publicKeyId) {
        this.publicKeyId = publicKeyId;
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

    @Override
    public int hashCode() {
        return super.hashCode();    // Sonar complains that equals/hashCode should be defined here
    }

    public RegistrationStatus getStatus() {
        return status;
    }

    public void setStatus(RegistrationStatus status) {
        this.status = status;
    }

    public int getCounter() {
        return counter;
    }

    public void setCounter(int counter) {
        this.counter = counter;
    }

    public String getAttestationType() {
        return attestationType;
    }

    public FIDO2RegistrationEntity setAttestationType(String attestationType) {
        this.attestationType = attestationType;
        return this;
    }

    public String getUncompressedECPoint() {
        return uncompressedECPoint;
    }

    public FIDO2RegistrationEntity setUncompressedECPoint(String uncompressedECPoint) {
        this.uncompressedECPoint = uncompressedECPoint;
        return this;
    }

    public String getType() {
        return type;
    }

    public FIDO2RegistrationEntity setType(String type) {
        this.type = type;
        return this;
    }


    public int getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(int signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public AttestationConveyancePreference getAttestationConveyancePreferenceType() {
        return attestationConveyancePreferenceType;
    }

    public void setAttestationConveyancePreferenceType(AttestationConveyancePreference attestationConveyancePreferenceType) {
        this.attestationConveyancePreferenceType = attestationConveyancePreferenceType;
    }
}
