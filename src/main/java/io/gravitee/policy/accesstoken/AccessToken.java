/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.policy.accesstoken;

import java.time.LocalDateTime;

public class AccessToken
{
    private String accessToken;
    private AccessTokenTypeEnum tokenType;
    private LocalDateTime expiresIn;
    private String rawData;

    public String getAccessToken() { return this.accessToken; }
    public void setAccesToken(String value) { this.accessToken = value; }
    public AccessTokenTypeEnum getTokenType() { return this.tokenType; }
    public void setTokenType(AccessTokenTypeEnum value) { this.tokenType = value; }
    public void setTokenType(String value) 
    {
        switch (value)
        {
            case "Bearer":
            case "BearerToken":
                this.tokenType = AccessTokenTypeEnum.BEARER;
                break;
            default:
                this.tokenType = AccessTokenTypeEnum.ACCESS_TOKEN;
                break;
            
        }
    }
    public LocalDateTime getExpiresIn() { return this.expiresIn; }
    public void setExpiresIn(LocalDateTime value) { this.expiresIn = value; }
    public void setExpiresIn(Long value) { this.expiresIn = LocalDateTime.now().plusSeconds(value); }
    public String getRawData() { return this.rawData; }
    public void setRawData(String rawData) { this.rawData = rawData; }

    public AccessToken(String accessToken, String tokenType, Long expiresIn, String rawData)
    {
        this.setAccesToken(accessToken);
        this.setTokenType(tokenType);
        this.setExpiresIn(expiresIn);
        this.setRawData(rawData);
    }
}

