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


import java.util.Date;
import java.util.UUID;
import javax.persistence.Column;
import javax.persistence.MappedSuperclass;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import org.springframework.data.domain.Persistable;



@MappedSuperclass
public abstract class FIDO2Entity implements Persistable<String> {
    @Column(name = "CRTE_DTTM", nullable = false)
    @Temporal(TemporalType.TIMESTAMP)
    private Date createdDate;

    @Column(name = "UPDT_DTTM", nullable = false)
    @Temporal(TemporalType.TIMESTAMP)
    private Date updatedDate;

    @Column(name = "CRTE_BY_ID", nullable = true)
    private String createdBy;

    @Column(name = "UPDT_BY_ID", nullable = true)
    private String updatedBy;

    public FIDO2Entity() {
        setId(UUID.randomUUID().toString());
    }

    // should only be called by constructor
    protected abstract void setId(String id);

    public Date getCreatedDate() {
        return createdDate;
    }

    // should only be called from onPersist/onUpdate
    public void setCreatedDate(Date createdDate) {
        this.createdDate = createdDate;
    }

    public Date getUpdatedDate() {
        return updatedDate;
    }

    // should only be called from onPersist/onUpdate
    public void setUpdatedDate(Date updatedDate) {
        this.updatedDate = updatedDate;
    }

    public String getCreatedBy() {
        return createdBy;
    }

    // should only be called from onPersist/onUpdate
    void setCreatedBy(String createdBy) {
        this.createdBy = createdBy;
    }

    public String getUpdatedBy() {
        return updatedBy;
    }

    // should only be called from onPersist/onUpdate
    void setUpdatedBy(String updatedBy) {
        this.updatedBy = updatedBy;
    }


    @Override
    public boolean isNew() {
        return getCreatedDate() == null;
    }

    @PrePersist
    protected void onPersist() {
        Date currentDate = new Date();
        setCreatedDate(currentDate);
        setUpdatedDate(currentDate);

    }

    @PreUpdate
    protected void onUpdate() {
        setUpdatedDate(new Date());

    }



    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) {
            return false;
        } else if (getId() != null) {   // should always be present but just in case
            return getId().equals(((FIDO2Entity)o).getId());
        } else {
            return super.equals(o);
        }
    }

    @Override
    public int hashCode() {
        if (getId() != null) {   // should always be present but just in case
            return getId().hashCode();
        } else {
            return super.hashCode();
        }
    }

    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this, ToStringStyle.JSON_STYLE);
    }

}
