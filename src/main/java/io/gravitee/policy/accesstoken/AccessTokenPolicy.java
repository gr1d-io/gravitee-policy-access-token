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
                    "Couldn't find keychain data inside context."));
            return;
        }

        try
        {
            AccessToken accessToken = this.getAccessToken(requestKeychain);
            AccessTokenPolicy.LOGGER.info("Access Token: " + accessToken.getAccessToken());
            this.injectAccessToken(request, accessToken);
            AccessTokenPolicy.LOGGER.info("Done.");
        }
        catch (JSONException e)
        {
            policyChain.failWith(PolicyResult.failure(HttpStatusCode.FORBIDDEN_403, e.getMessage()));
            return;
        }
        catch(UnsupportedEncodingException e)
        {
            policyChain.failWith(PolicyResult.failure("Error on processing keychain data: "+e.getLocalizedMessage()));
        }
        catch(IOException e)
        {
            policyChain.failWith(PolicyResult.failure("Error on retrieving access token: "+e.getLocalizedMessage()));
        }

        policyChain.doNext(request,response);
    }

    private String lookForKeychain(ExecutionContext executionContext, Request request) 
    {

        Object attrib = executionContext.getAttribute(KEYCHAIN_KEY);
        String keychainResponse = null;

        if(attrib!=null)
            keychainResponse = (String)attrib;

        return keychainResponse;
    }

    private AccessToken getAccessToken(String requestKeychain) throws UnsupportedEncodingException, IOException 
    {
        JSONArray apiList = new JSONArray(requestKeychain);            
        KeychainInterpreter interpreter = new KeychainInterpreter(apiList);
        String url = interpreter.applyQuery(this.policyConfiguration.getUrl());
        String method = "POST";
        AccessTokenRequest accessTokenRequest = new AccessTokenRequest(url, method, interpreter.getHeaders(), interpreter.getBody());
        return accessTokenRequest.getAccessToken();
    }

    private void injectAccessToken(Request request, AccessToken accessToken) 
    {
        String headerKey = this.policyConfiguration.getHeaderKey();
        if (headerKey == null || headerKey.isEmpty()) {
            headerKey = AccessTokenPolicy.AUTHORIZATION_KEY;
        }
        switch(accessToken.getTokenType())
        {
            case BEARER:
                request.headers().add(headerKey, String.format("Bearer %s", accessToken.getAccessToken()));
                break;
            case ACCESS_TOKEN:
                request.headers().add(headerKey, accessToken.getAccessToken());
                break;
            default:
                break;
        }
    }
}
