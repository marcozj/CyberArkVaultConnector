package com.saviynt.ssm.custom.cyberarkvault;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

/**
 *
 * @author marcozhang
 */
public class VaultInstance {

    private static final Logger log = Logger.getLogger(VaultInstance.class.getName());
    private final String userAgent = "Saviynt Connector Framework";
    private String accessToken = null;
    private String baseurl = null;
    private Boolean sslverify = true;
    
    public VaultInstance(String url, Boolean ssl_verify) {
        baseurl = url;
        sslverify = ssl_verify;
    }
    
    public void getAccessToken(String username, String password) throws JsonProcessingException, IOException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, VaultException {
        String logonurl = baseurl + "/PasswordVault/API/auth/Cyberark/Logon/";

        log.log(Level.INFO, "Authenticating...");

        VaultAuthRequestBuilder authbuilder = new VaultAuthRequestBuilder();
        VaultAuthRequest body = authbuilder.buildAuthRequest(username, password);

        ObjectMapper mapper = new ObjectMapper();
        String jsonStr = mapper.writeValueAsString(body);

        RequestFactory requestFactory = new RequestFactory();
        RestTemplate restTemplate = new RestTemplate(requestFactory.getRequestFactory(sslverify));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        // build the request
        HttpEntity<String> request = new HttpEntity<>(jsonStr, headers);
        // Send authentication request
        ResponseEntity<String> response = restTemplate.postForEntity(logonurl, request, String.class);
        String token = response.getBody();
        if (token != null) {
            accessToken = token.substring(1, token.length() - 1);
            log.log(Level.INFO, "Successfully obtained access token");
            //log.log(Level.INFO, "Token : {0}", accessToken);
        } else {
            throw new VaultException("Vault access token is null");
        }

    }

    /*
    Get account details call response example:
    {
        "value": [
            {
                "categoryModificationTime": 1704437805,
                "id": "21_556",
                "name": "iadmadm@KCSIAMPOC02",
                "address": "10.9.48.176",
                "userName": "iamadm",
                "platformId": "KCS_Windows_Privilege",
                "safeName": "TS_Storage",
                "secretType": "password",
                "platformAccountProperties": {
                    "LogonDomain": "10.9.48.176",
                    "ServerName": "KCSIAMPOC02"
                },
                "secretManagement": {
                    "automaticManagementEnabled": false,
                    "manualManagementReason": "password",
                    "lastModifiedTime": 1704437805
                },
                "createdTime": 1704437747
            }
        ],
        "count": 1
    }
     */
    public String getAccountId(String accountname, String safename) throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, VaultException {
        String accountid = null;
        String URL = baseurl + "/passwordvault/api/accounts?search=" + accountname + "&filter=safeName eq " + safename;
        log.log(Level.INFO, "Retrieving account id for accountname {0} in safe {1} with URL {2}", new Object[]{accountname, safename, URL});
        if (accessToken == null) {
            throw new VaultException("Vault access token is null");
        }

        RequestFactory requestFactory = new RequestFactory();
        RestTemplate restTemplate = new RestTemplate(requestFactory.getRequestFactory(sslverify));
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.add("User-Agent", userAgent);
        headers.add("Authorization", accessToken);

        HttpEntity<String> requestEntity = new HttpEntity<>(headers);
        ResponseEntity<String> response = restTemplate.exchange(URL, HttpMethod.GET, requestEntity, String.class);

        if (response.getStatusCode() == HttpStatus.OK) {
            JSONObject jsonResp = new JSONObject(response.getBody());
            JSONArray accounts = jsonResp.getJSONArray("value");
            // Expect only one record return
            if (accounts.length() == 1) {
                JSONObject account = accounts.getJSONObject(0);
                accountid = account.getString("id");
            } else {
                throw new RuntimeException("Retrieved either 0 or more than 1 accounts");
            }
        }
        return accountid;
    }

    public String retrieveSecret(String accountid) throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, VaultException {
        String secret;
        String URL = baseurl + "/passwordvault/api/accounts/" + accountid + "/password/retrieve";

        log.log(Level.INFO, "Retrieving secret with URL {0}", URL);
        if (accessToken == null) {
            throw new VaultException("Vault access token is null");
        }

        RequestFactory requestFactory = new RequestFactory();
        RestTemplate restTemplate = new RestTemplate(requestFactory.getRequestFactory(sslverify));
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.add("User-Agent", userAgent);
        headers.add("Authorization", accessToken);

        JSONObject json = new JSONObject();
        json.put("reason", "Saviynt connector retrieves credential");

        HttpEntity<String> requestEntity = new HttpEntity<>(json.toString(), headers);
        ResponseEntity<String> response = restTemplate.exchange(URL, HttpMethod.POST, requestEntity, String.class);
        log.log(Level.INFO, "Checkout Response Code : {0}", response.getStatusCodeValue());
        String returnsecret = response.getBody();

        if (returnsecret == null) {
            throw new VaultException("No secret is returned");
        }
        // Returned value from API call is double quoted. Need to remove the double quote.
        secret = returnsecret.substring(1, returnsecret.length() - 1);
        log.log(Level.INFO, "Successfully retrieved secret");
        //log.log(Level.INFO, "Retrieved secret: {0}", secret);
        
        return secret;
    }

}
