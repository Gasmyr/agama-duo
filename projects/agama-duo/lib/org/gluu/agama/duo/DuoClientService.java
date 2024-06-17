import com.duosecurity.Client;
import com.duosecurity.exception.DuoException;
import com.duosecurity.model.Token;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

public class DuoClientService{

    //private static Client duoClient;
    protected static final Logger log = LoggerFactory.getLogger(DuoClientService.class);

    private String clientId;
    private String clientSecret;
    private String apiHost;
    private String redirectUri;
    
    public DuoClientService(){
        super();
    }

    public DuoClientService(String clientId, String clientSecret, String apiHost, String redirectUri){
        log.debug("Duo client details : clientId :{}, clientSecret:{}, apiHost:{}, redirectUri:{} ", clientId, clientSecret, apiHost, redirectUri);
        this.clientId = clientId;
        this.clientSecret= clientSecret;
        this.apiHost= apiHost;
        this.redirectUri= redirectUri;
    }

    public String  duoValidate() throws DuoException {
        log.debug("Inside duoValidate details : clientId :{}, clientSecret:{}, apiHost:{}, redirectUri:{} ", clientId, clientSecret, apiHost, redirectUri);
        Map<String, String> stateMap = new HashMap<>();;
        /*String CLIENT_ID = "DI1QCWC6TY96FLSPDEKE";
        String CLIENT_SECRET = "sPqo9w4BgBOJexIwJd105ZEzaLeoqEB2HaunMKLF";
        String API_HOST = "api-de9a3a97.duosecurity.com";
        String HTTPS_REDIRECT_URI = "https://shekhar16-evolving-bream.gluu.info/jans-auth/fl/callback";*/
        Client duoClient = new Client.Builder(clientId, clientSecret, apiHost, redirectUri).build();

        String state = duoClient.generateState();
        // Store the state to remember the session and username
        String username = "admin";
        stateMap.put(state, username);

        // Step 4: Create the authUrl and redirect to it
        String authUrl = duoClient.createAuthUrl(username, state);

        return authUrl;

    }

    public String validateCallback(Map callbackUrl, String uid) throws DuoException {
        log.debug("Inside validateCallback details : clientId :{}, clientSecret:{}, apiHost:{}, redirectUri:{} ", clientId, clientSecret, apiHost, redirectUri);
        /*String CLIENT_ID = "DI1QCWC6TY96FLSPDEKE";
        String CLIENT_SECRET = "sPqo9w4BgBOJexIwJd105ZEzaLeoqEB2HaunMKLF";
        String API_HOST = "api-de9a3a97.duosecurity.com";
        String HTTPS_REDIRECT_URI = "https://shekhar16-evolving-bream.gluu.info/jans-auth/fl/callback";*/
        Client duoClient = new Client.Builder(clientId, clientSecret, apiHost, redirectUri).build();

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

    private boolean authWasSuccessful(Token token) {
        if (token != null && token.getAuth_result() != null) {
            return "ALLOW".equalsIgnoreCase(token.getAuth_result().getStatus());
        }
        return false;
    }

    private String tokenToJson(Token token) throws DuoException {
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            return objectMapper.writer().writeValueAsString(token);
        } catch (JsonProcessingException jpe) {
            throw new DuoException("Could not convert token to JSON");
        }
    }

}
