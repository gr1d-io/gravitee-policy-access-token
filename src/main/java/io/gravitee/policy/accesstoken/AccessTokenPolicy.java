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

import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequest;
import io.gravitee.policy.accesstoken.configuration.AccessTokenPolicyConfiguration;
import org.json.JSONArray;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

import org.json.JSONException;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
// @SuppressWarnings("unused")
public class AccessTokenPolicy 
{

    private static final Logger LOGGER = LoggerFactory.getLogger(AccessTokenPolicy.class);

    static final String KEYCHAIN_KEY = "keychain";
    static final String AUTHORIZATION_KEY = "Authorization";
    
    /**
     * Policy configuration
     */
    private final AccessTokenPolicyConfiguration policyConfiguration;

    public AccessTokenPolicy(AccessTokenPolicyConfiguration policyConfiguration) 
    {
        this.policyConfiguration = policyConfiguration;
    }

    @OnRequest
    public void onRequest(Request request, Response response, ExecutionContext executionContext, PolicyChain policyChain) 
    {
        String requestKeychain = lookForKeychain(executionContext, request);

        AccessTokenPolicy.LOGGER.warn(requestKeychain);

        if (requestKeychain == null || requestKeychain.isEmpty()) {
            policyChain.failWith(PolicyResult.failure(
                    HttpStatusCode.FORBIDDEN_403,
                    "[Keychain->AccessToken] Couldn't find keychain data inside context."));
            return;
        }

        try
        {
            JSONArray apiList = new JSONArray(requestKeychain);            
            KeychainInterpreter interpreter = new KeychainInterpreter(apiList);
            String url = interpreter.applyQuery(this.policyConfiguration.getUrl());
            AccessTokenRequest accessTokenRequest = new AccessTokenRequest(url, interpreter.getHeaders(), interpreter.getBody());
            accessTokenRequest.doRequest(res -> {
                if (res.succeeded())
                {
                    AccessToken accessToken = res.result();
                    if (accessToken.getAccessToken() == null || accessToken.getAccessToken().isEmpty())
                    {
                        policyChain.failWith(PolicyResult.failure("[Keychain->AccessToken] Error on handling access token: Access token is null/empty."));
                    }
                    else if (this.injectAccessToken(request, accessToken))
                    {
                        AccessTokenPolicy.LOGGER.info("[Keychain->AccessToken] Done.");
                        policyChain.doNext(request, response);
                    }
                    else
                    {
                        policyChain.failWith(PolicyResult.failure("[Keychain->AccessToken] Error on handling access token: Access token type not recognized."));
                    }   
                }
                else
                {
                    policyChain.failWith(PolicyResult.failure("[Keychain->AccessToken] Error on retrieving access token: "+res.cause().getLocalizedMessage()));
                }
            }, this.policyConfiguration);
        }
        catch (JSONException e)
        {
            policyChain.failWith(PolicyResult.failure(HttpStatusCode.FORBIDDEN_403, e.getMessage()));
            return;
        }
        catch(UnsupportedEncodingException e)
        {
            policyChain.failWith(PolicyResult.failure("[Keychain->AccessToken] Error on processing keychain data: "+e.getLocalizedMessage()));
        }
        catch(IOException e)
        {
            policyChain.failWith(PolicyResult.failure("[Keychain->AccessToken] Error on retrieving access token: "+e.getLocalizedMessage()));
        }
    }

    private String lookForKeychain(ExecutionContext executionContext, Request request) 
    {

        Object attrib = executionContext.getAttribute(KEYCHAIN_KEY);
        String keychainResponse = null;

        if(attrib!=null)
            keychainResponse = (String)attrib;

        return keychainResponse;
    }

    private Boolean injectAccessToken(Request request, AccessToken accessToken) 
    {
        String headerKey = this.policyConfiguration.getHeaderKey();
        if (headerKey == null || headerKey.isEmpty()) {
            headerKey = AccessTokenPolicy.AUTHORIZATION_KEY;
        }
        String token = "";
        switch(accessToken.getTokenType())
        {
            case BEARER:
                token = String.format("Bearer %s", accessToken.getAccessToken());
                break;
            case ACCESS_TOKEN:
                token = accessToken.getAccessToken();
                break;
            default:
                break;
        }
        if (!token.isEmpty())
        {
            AccessTokenPolicy.LOGGER.info("[Keychain->AccessToken] Access Token APPLIED. => "+headerKey+":"+ token);
            request.headers().add(headerKey, token);
        }
        else
        {
            AccessTokenPolicy.LOGGER.info("[Keychain->AccessToken] Access Token NOT APPLIED. Token type not recognized.");
        }
        return (!token.isEmpty());
    }
}
