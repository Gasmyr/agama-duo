package org.gluu.agama.duo;

import com.duosecurity.Client;
import com.duosecurity.exception.DuoException;
import com.duosecurity.model.Token;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.HashMap;
import java.util.Map;

class DuoClientService{

    private static Client duoClient;

    public static String  duoValidate(String clientId) throws DuoException {
        System.out.println("passed from assignment clientId  :  " + clientId);
        Map<String, String> stateMap = new HashMap<>();;
        String CLIENT_ID = "DI1QCWC6TY96FLSPDEKE";
        String CLIENT_SECRET = "sPqo9w4BgBOJexIwJd105ZEzaLeoqEB2HaunMKLF";
        String API_HOST = "api-de9a3a97.duosecurity.com";
        String HTTPS_REDIRECT_URI = "https://shekhar16-evolving-bream.gluu.info/jans-auth/fl/callback";
        this.duoClient = new Client.Builder(CLIENT_ID, CLIENT_SECRET, API_HOST, HTTPS_REDIRECT_URI).build();

        String state = duoClient.generateState();
        // Store the state to remember the session and username
        String username = "admin";
        stateMap.put(state, username);

        // Step 4: Create the authUrl and redirect to it
        String authUrl = duoClient.createAuthUrl(username, state);

        return authUrl;

    }

    public static String validateCallback(Map callbackUrl, String uid) throws DuoException {
        String CLIENT_ID = "DI1QCWC6TY96FLSPDEKE";
        String CLIENT_SECRET = "sPqo9w4BgBOJexIwJd105ZEzaLeoqEB2HaunMKLF";
        String API_HOST = "api-de9a3a97.duosecurity.com";
        String HTTPS_REDIRECT_URI = "https://shekhar16-evolving-bream.gluu.info/jans-auth/fl/callback";
        this.duoClient = new Client.Builder(CLIENT_ID, CLIENT_SECRET, API_HOST, HTTPS_REDIRECT_URI).build();

        System.out.println("check callbackUrl  :  " + callbackUrl);
        String state = (String) callbackUrl.get("state");
        String duoCode = (String) callbackUrl.get("duo_code");
        System.out.println("state : " + state + " duoCode : " + duoCode + "uid" + uid);
        Token token = duoClient.exchangeAuthorizationCodeFor2FAResult(duoCode, uid);
        String result = "false";
        // If the auth was successful, render the welcome page otherwise return an error
        if (authWasSuccessful(token)) {
            result = tokenToJson(token);
        }
        return result;
    }

    private static boolean authWasSuccessful(Token token) {
        if (token != null && token.getAuth_result() != null) {
            return "ALLOW".equalsIgnoreCase(token.getAuth_result().getStatus());
        }
        return false;
    }

    private static String tokenToJson(Token token) throws DuoException {
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            return objectMapper.writer().writeValueAsString(token);
        } catch (JsonProcessingException jpe) {
            throw new DuoException("Could not convert token to JSON");
        }
    }

}
