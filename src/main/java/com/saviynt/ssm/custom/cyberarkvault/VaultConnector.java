package com.saviynt.ssm.custom.cyberarkvault;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import com.saviynt.ssm.abstractConnector.VaultConnectorSpecification;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.saviynt.ssm.abstractConnector.VaultConfigVo;
import com.saviynt.ssm.abstractConnector.exceptions.ConnectorException;
import com.saviynt.ssm.abstractConnector.exceptions.InvalidAttributeValueException;
import com.saviynt.ssm.abstractConnector.exceptions.InvalidCredentialException;
import com.saviynt.ssm.abstractConnector.exceptions.MissingKeyException;
import com.saviynt.ssm.abstractConnector.exceptions.OperationTimeoutException;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.json.JSONObject;
import org.apache.commons.lang3.StringUtils;

/**
 * The VaultConnector is an example custom vault connector to help you build
 * your own vault connector to save the secret in a vault and obtain the secret
 * from the vault for any connection. The VaultConnector extends from the
 * VaultConnectorSpecification framework class and implements the following
 * methods: getSecret(), setSecret(), displayName(), version(), and
 * setVaultConfig(). The VaultConnector also includes an optional method named
 * dataFormatting().EIC invokes these methods while executing the provisioning
 * and import jobs to obtain the secret from the vault and set the secret in the
 * vault, while performing any operation with the connector (such as save and
 * test connection from the UI while creating a new connection). These methods
 * are also invoked from the connections while implementing CPAM use cases.
 *
 */
public class VaultConnector extends VaultConnectorSpecification {

    private static final Logger log = Logger.getLogger(VaultConnector.class.getName());
    /**
     * The Constant serialVersionUID.
     */
    public static final long serialVersionUID = 1L;

    public static void main(String[] args) throws JsonProcessingException, IOException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, VaultException {
        VaultInstance vault = new VaultInstance("https://xxx.xxx.xxx.xxx", false);
        String username = "xxx";
        String password = "xxx";
        vault.getAccessToken(username, password);
        vault.retrieveSecret(vault.getAccountId("xxxx", "xxx"));
    }

    /**
     * to retrieve connector display name.
     *
     * @return the string
     */
    @Override
    public String displayName() {
        return "CustomCyberArkVaultConnector";
    }

    /**
     * to retrieve connector version.
     *
     * @return the string
     */
    @Override
    public String version() {
        return "1.0";
    }

    /**
     * Sets the vault configuration needed for establishing the connectivity
     * with your vault. The attributes defined in configData and setVaultConfig
     * parameters are dynamically populated on this vault's connector's UI in
     * EIC. The connection attributes must be specified in the below format.
     * Example: List<String> connectionAttributes =
     * configData.getConnectionAttributes();
     * connectionAttributes.add("AUTH_URL");
     *
     * Connection attributes that need to be encrypted can be added to
     * configData as below: Example : List<String> encryptedConnectionAttributes
     * = configData.getEncryptedConnectionAttributes();
     * encryptedConnectionAttributes.add("Password");
     *
     * Description or details of the format in which the config attributes are
     * supposed to be input from the UI can be added in configData as below:
     * JSONObject jsonObject = new JSONObject(connectionAttributesDescription);
     * jsonObject.put("Password", "Provide password to connect with
     * application"); jsonObject.put("CreateUserJSON", "SAMPLE JSON {}");
     * configData.getConnectionAttributesDescription().setConnectionAttributesDescription(jsonObject.toString());
     *
     * Connection attributes that are mandatory (or required) can be added to
     * configData as below: Example : List<String> requiredConnectionAttributes
     * = configData.getRequiredConnectionAttributes();
     * requiredConnectionAttributes.add("AUTH_URL");
     *
     * @param configData This is a metadata that contains the details of the
     * information required and configurations needed for establishing the
     * connectivity to the vault and for doing setSecret and getSecret
     * operations. This is defined in setVaultConfig(). These appear as JSON or
     * fields on the UI that have to be input at the time of creating the
     * connection for this vault connector in EIC.
     */
    @Override
    public void setVaultConfig(VaultConfigVo configData) {
        log.log(Level.INFO, "In setVaultConfig method");

        /*
		In example code we can define AUTH_URL,username,
		password, ACCOUNT_URL, KEY_URL as the connection parameters as below: 
         */
        List<String> connectionAttributes = configData.getConnectionAttributes();
        //Example code

        connectionAttributes.add("Vault_URL");
        connectionAttributes.add("Username");
        connectionAttributes.add("Password");
        connectionAttributes.add("SSL_Verification");

        /*
		 Set the attributes that need to be encrypted. In example code, making Password as encrypted attribute.
         */
        List<String> encryptedConnectionAttributes = configData.getEncryptedConnectionAttributes();
        encryptedConnectionAttributes.add("Password");

        /*
		Add description of the connection attributes as below.These will be shown on the UI
		for to these attributes as the required input value format 
         */
        String connectionAttributesDescription = configData.getConnectionAttributesDescription();

        JSONObject jsonObject;
        if (StringUtils.isNotEmpty(connectionAttributesDescription)) {
            jsonObject = new JSONObject(connectionAttributesDescription);
        } else {
            jsonObject = new JSONObject();
        }
        jsonObject.put("Vault_URL", "The URL of CyberArk Password Vault Web Access (PVWA) for access its REST API. For example: https://xxx.xxx.xxx");
        jsonObject.put("Username", "CyberArk user which has permissions to retrieve vaulted account credential.");
        jsonObject.put("Password", "The password of CyberArk user");
        jsonObject.put("SSL_Verification", "To disable SSL certificate verification for testing purpose, specify No. Default value is Yes to verify SSL certificate.");

        configData.setConnectionAttributesDescription(jsonObject.toString());

        /*
		set the attributes that are required as below. In example code, making all of our connection attributes as "required"
         */
        List<String> requiredConnectionAttributes = configData.getRequiredConnectionAttributes();
        //example code

        requiredConnectionAttributes.add("Vault_URL");
        requiredConnectionAttributes.add("Username");
        requiredConnectionAttributes.add("Password");
        requiredConnectionAttributes.add("SSL_Verification");

        log.log(Level.INFO, "Exit setVaultConfig method");

    }

    /**
     * Saves the secret in the vault. This method is called for creating or
     * updating the secret in the vault. Example : Perform the following steps
     * to save the secret in the vault: Step 1 : Retrieve the value of the
     * encryptedConnAttr attribute from the data parameter to identify the
     * attributes that are saved in the vault. Step 2 : Retrieve the value of
     * the vaultConnectionAtributes attribute from the data parameter to obtain
     * the values of the parameters required for connecting to the vault. Step 3
     * : Retrieve the value of the keyMapping attribute from the vaultConfigData
     * parameter to define the mapping to store each encrypted attribute in the
     * vault. Step 4 : Write the logic to connect to the vault and save the
     * secret in the vault. Step 5 : Return the mapping details as explained in
     * the parameter description.
     *
     * @param vaultConfigData This parameter is defined in the JSON format and
     * contains the key mappings for all the encrypted attributes of the
     * connection using the vault. It contains the mapping attributes that are
     * defined for every encrypted attribute in the vault configuration of the
     * connector in EIC UI. For each encrypted attribute, keyName and
     * encryptionMechanism are mandatory mapping attributes required by the
     * vault connector framework. The ignoreMapping attribute is an optional
     * mapping attribute. You can add additional mapping attributes under
     * keyMapping based on your requirement. For example, if you require a path
     * or a folder also as one of your mapping attribute, add it in the
     * keyMapping that you provide for each encrypted attribute on the vault
     * configuration UI of the connector in EIC UI.
     *
     * ignoreMapping: By default, the vault connector framework adds the name of
     * the connection as a prefix to all of the mappings attributes of the
     * encrypted attributes to uniquely save and identify the connection in the
     * vault. Specify this attribute if you do not want the vault connector
     * framework to append the connection name to it. For example, if keyName is
     * not specified in the ignoreMapping attribute, the vault connector
     * framework sends the value of keyName in vaultConfigData as
     * MyADConnector~#~abcd215 where MyADConnector is the name of the connection
     * and abcd215 is the name of the key.
     *
     * keyName: This is the name of the encrypted attribute stored in the vault.
     *
     * encryptionmechanism: This is the name of the encryption mechanism used
     * for storing the secret in the vault. Encryption is handled internally by
     * the vault connector framework.If encryption is selected, secret's value
     * will be encrypted by the vault connector framework before passing it onto
     * this function. The encryption mechanism can be None, Encrypted, or
     * Base64.
     *
     * <P>
     * Below is an example where PASSWORD is specified as an encrypted attribute
     * and mapped to abcd215 in the vault.      <pre>
     * "vaultConfigData": {
     * "keyMapping": {
     * "PASSWORD": {
     * "keyName": "abcd215",
     * "encryptionmechanism":"None"/"Encrypted"/"Base64"
     * "ignoreMapping":[
     * "keyName"
     * ]
     * }
     * }
     * }
     * </pre>
     *
     * @param data This parameter is defined in the JSON format and contains all
     * the connection parameters required establishing the connecting with your
     * vault along with the encrypted connection attribute which the connector
     * will obtain from your vault. vaultConnectionAttributes : This attribute
     * contains all the data required to access the secret from your vault.
     * encryptedConnAttr : This attribute contains all attributes stored in the
     * vault and their actual runtime values.
     *
     * <P>
     * Below is an example where PASSWORD is specified as an encrypted attribute
     * which is mapped to the actual runtime value of password@1234. The
     * vaultConnectionAtributes attribute contains all the data required to
     * access the secret from your vault.
     *
     * <pre>
     * "data": {
     * "vaultConnectionAtributes": {
     * "AUTH_URL": "https://sampleVault/session/auth",
     * "username": "abcd@xyz.com",
     * "password": "password@vault",
     * "ACCOUNT_URL": "https://sampleVault/select_account",
     * "KEY_URL": "https://sampleVault/keys"
     * },
     * "encryptedConnAttr": {
     * "PASSWORD": "password@1234"
     * }
     * }
     * </pre>
     *
     * @return a map that contains the status of whether the secret is set or
     * not. The data in the map is added as follows: Example: Map map = new
     * HashMap(); //rest of code to be executed map.put("status", "success"); In
     * case of any failure, just throw ConnectorException with appropriate
     * message instead of returning success. e.g throw new
     * ConnectorException("your exception message");
     * @throws ConnectorException when the connection fails.
     */
    @Override
    public Map setSecret(Map<String, Object> vaultConfigData, Map<String, Object> data) throws ConnectorException {
        log.log(Level.INFO, "In setSecret method");
        Map map = new HashMap();
        try {
            log.log(Level.INFO, "Received following parameters in setSecret method");
            log.log(Level.INFO, "vaultConfigData : {0}", prettyPrint(vaultConfigData));
            log.log(Level.INFO, "data : {0}", prettyPrint(data));

            //Example code given below to explain how a secret can be stored in the vault using vaultConfigData and data parameters
            /*
				//We get all the attributes required to connect to the vault from "data" as follows:
				Map<String, Object> vaultConnectionAttr = (Map<String, Object>) data.get("vaultConnectionAtributes"); 
	
			    //For our Sample vault we get AUTH_URL, username, password and account_url to connect to the vault from "vaultConnectionAttr" (obtained from "data") for fetching the password from the vault.
				//Using these values connection can be established with the vault where the secret is to be stored. 
				String url = (String) vaultConnectionAttr.get("AUTH_URL");     
				String username = (String) vaultConnectionAttr.get("username");
				String password = (String) vaultConnectionAttr.get("password");
				String account_url = (String) vaultConnectionAttr.get("ACCOUNT_URL");
				String key_url = (String) vaultConnectionAttr.get("KEY_URL");
					
					
			        
				//We get "encryptedConnAttr" from "data". We will use this to set all the encrypted connection attribute (secret) in the vault.
				Map<String, String> encryptedConnAttr = (Map<String, String>)data.get("encryptedConnAttr");
					
					
				
				//We get keyMapping for all encrypted attribute from "vaultConfigData". This will be used to get the "keyName" with which the secret is stored in the vault.
				Map<String, Object> vaultConfigJSON = (Map<String, Object>) vaultConfigData.get("keyMapping");
					
					
				//For every encrypted connection attribute (here only "PASSWORD"), we get the keyName with which the secret is to be stored from "vaultConfigData".
				//Every secret would be stored with corresponding value in the vault
				for(Map.Entry<String, String> dataMap : encryptedConnAttr.entrySet()) {
					String attributeName = (String) dataMap.getKey();
					String attributeValue = (String) dataMap.getValue();
					String keyName = (String) ((Map) vaultConfigJSON.get(attributeName)).get("keyName");
					//using  attributes from vaultConnectionAttr connect to the vault and save the value of the secret ("attributvalue") with the given "keyName" in the vault
				}
				
			
             */
            //Build the return map. This map contains one key - "status". The Key "status" would
            //contain "success" if the secret is successfully fetched from the vault. In case any exception or error
            //occurs, ConnectorException needs to be thrown 
            map.put("status", "success");

        } catch (JsonProcessingException e) {
            throw new ConnectorException(e.getMessage());
        }
        log.log(Level.INFO, "Exit setSecret method");
        return map;
    }

    /**
     * Obtains the secret from the vault. This method is called to retrieve the
     * value of the secret from the vault. Perform the following steps to obtain
     * the secret from the vault: Step 1 : Retrieve the value of the
     * encryptedConnAttr attribute from the data parameter to identify the
     * attributes to be retrieved from the vault. Step 2 : Retrieve the value of
     * the vaultConnectionAtributes attribute from the data parameter to obtain
     * the values of the parameters required for connecting to the vault. Step 3
     * : Retrieve the value of the keyMapping attribute from the vaultConfigData
     * parameter to define the mapping to store each encrypted attribute in the
     * vault. Step 4 : Write the logic to connect to the vault and retrieve the
     * value of the secrets from the vault. Step 5 : Return the mapping details
     * as explained in the parameter description.
     *
     * @param vaultConfigData This parameter is defined in the JSON format and
     * contains the key mappings for all the encrypted attributes of the
     * connection using the vault. It contains the mapping attributes that are
     * defined for every encrypted attribute in the vault configuration of the
     * connector in EIC UI. For each encrypted attribute, keyName and
     * encryptionMechanism are mandatory mapping attributes required by the
     * vault connector framework. The ignoreMapping attribute is an optional
     * mapping attribute. You can add additional mapping attributes under
     * keyMapping based on your requirement. For example, if you require a path
     * or a folder also as one of your mapping attribute, add it in the
     * keyMapping that you provide for each encrypted attribute on the vault
     * configuration UI of the connector in EIC UI.
     *
     * ignoreMapping: By default, the vault connector framework adds the name of
     * the connection as a prefix to all of the mappings attributes of the
     * encrypted attributes to uniquely save and identify the connection in the
     * vault. Specify this attribute if you do not want the vault connector
     * framework to append the connection name to it. For example, if keyName is
     * not specified in the ignoreMapping attribute, the vault connector
     * framework sends the value of keyName in vaultConfigData as
     * MyADConnector~#~abcd215 where MyADConnector is the name of the connection
     * and abcd215 is the name of the key.
     *
     * keyName: This is the name of the encrypted attribute stored in the vault.
     *
     * encryptionmechanism: This is the name of the encryption mechanism used
     * for retrieving the secret from the vault. Encryption is handled
     * internally by the vault connector framework. Value of the secret returned
     * from this method will be decrypted by the Vault connector framework as
     * per selected encryption mechanism. The encryption mechanism can be None,
     * Encrypted or Base64. *
     *
     *
     *
     * <P>
     * Below is an example where PASSWORD is specified as an encrypted attribute
     * and abcd215 is the value of PASSWORD that will be retrieved from the
     * vault.      <pre>
     * "vaultConfigData": {
     * "keyMapping": {
     * "PASSWORD": {
     * "keyName": "abcd215",
     * "encryptionmechanism":"None"/"Encrypted"/"Base64"
     * "ignoreMapping":[
     * "keyName"
     * ]
     * }
     * }
     * }
     * </pre>
     *
     * @param data This parameter is defined in the JSON format and contains all
     * the connection parameters required for establishing the connection with
     * your vault along with the encrypted connection attribute whose value will
     * be obtained from your vault. vaultConnectionAttributes : This attribute
     * contains all the data required to retrieve the secret from your vault.
     * encryptedConnAttr : This attribute contains all attributes retrieved from
     * the vault.
     *
     * <P>
     * Below is an example where PASSWORD is specified as an encrypted attribute
     * which is mapped to the actual runtime value of password@vault that will
     * be retrieved from the vault. The vaultConnectionAtributes attribute
     * contains the details required for establishing a connection with the
     * vault.
     *
     * <pre>
     * "data": {
     * "vaultConnectionAtributes": {
     * "AUTH_URL": "https://sampleVault/session/auth",
     * "username": "abcd@xyz.com",
     * "password": "password@vault",
     * "ACCOUNT_URL": "https://sampleVault/select_account",
     * "KEY_URL": "https://sampleVault/keys"
     * },
     * "encryptedConnAttr": {
     * "PASSWORD": null
     * }
     * }
     * </pre>
     *
     * @return a map that contains encryptedConnAttr and status of whether the
     * secret is obtained or not. The key 'encryptedConnAttr' has the value in
     * the format of a map. The key of this map should be the encrypted
     * attribute's name and its value should be its value as obtained from the
     * vault.The data in the map is added as follows:
     * <P>
     * Example:      <pre>
     * Map map = new HashMap();
     * //rest of code to be executed
     * map.put("encryptedConnAttr", <Map containing key as the attribute name and value as data obtained from the vault>);
     * map.put("status", "success");
     * </pre> In case of any failure, just throw ConnectorException with
     * appropriate message instead of returning success. e.g throw new
     * ConnectorException("your exception message");
     *
     * @throws ConnectorException when the connection fails.
     */
    /*
    Vault config example in EIC connector page
    {"accountname":"iamadm@KCSIAMTD912-POC","ignoreMapping":["accountname","safename"],"safename":"CPM-ADM"}
    {"accountname":"iadmadm@KCSIAMPOC02","ignoreMapping":["accountname","safename"],"safename":"TS_Storage"}
    
    vaultConfigData : {keyMapping={PASSWORD={accountname=iamadm@KCSIAMTD912-POC, ignoreMapping=ktb-linux-174~#~[accountname, safename], safename=CPM-ADM}}, connectionName=ktb-linux-174} 
    encryptedConnAttr : {PASSWORD=null} 
    */
    @Override
    public Map getSecret(Map<String, Object> vaultConfigData, Map<String, Object> data) throws ConnectorException {
        log.log(Level.INFO, "In getSecret method");
        Map map = new HashMap();
        try {
            log.log(Level.INFO, "Received following parameters in getSecret method");
            log.log(Level.INFO, "vaultConfigData : {0}", vaultConfigData.toString());
            log.log(Level.INFO, "encryptedConnAttr : {0}", data.get("encryptedConnAttr").toString());
            //log.log(Level.INFO, "data : {0}", data.toString());

            //This map will be used in building the return map.
            Map<String, Object> vaultConnectionAttr = (Map<String, Object>) data.get("vaultConnectionAtributes");
            String url = (String) vaultConnectionAttr.get("Vault_URL");
            String username = (String) vaultConnectionAttr.get("Username");
            String password = (String) vaultConnectionAttr.get("Password");
            String sslverify = (String) vaultConnectionAttr.get("SSL_Verification");
            

            Map valueMap = new HashMap();

            Map<String, String> encryptedConnAttr = (Map<String, String>) data.get("encryptedConnAttr");

            Map<String, Object> vaultConfigJSON = (Map<String, Object>) vaultConfigData.get("keyMapping");
            for (Map.Entry<String, String> dataMap : encryptedConnAttr.entrySet()) {
                String attributeName = (String) dataMap.getKey();
                log.log(Level.INFO, "attributeName : {0}", attributeName);
                Map<String, Object> attrObject = (Map<String, Object>) vaultConfigJSON.get(attributeName);
                if (attrObject != null) {
                    String accountName = (String) ((Map) vaultConfigJSON.get(attributeName)).get("accountname");
                    String safeName = (String) ((Map) vaultConfigJSON.get(attributeName)).get("safename");
                    log.log(Level.INFO, "accountName : {0}", accountName);
                    log.log(Level.INFO, "safeName : {0}", safeName);

                    if (accountName != null && safeName != null) {
                        VaultInstance vault = new VaultInstance(url, !sslverify.equalsIgnoreCase("no"));
                        vault.getAccessToken(username, password);
                        String valueOfSecret = vault.retrieveSecret(vault.getAccountId(accountName, safeName));
                        valueMap.put(attributeName, valueOfSecret);
                    }
                }
            }

            //Build the return map. This map contains two keys "encryptedConnAttr" and "status". The key "encryptedConnAttr" would contain a map
            //with key as all the encrypted connection attribute and corresponding value as the secret fetched for the attributes. The Key "status" would
            //contain "success" if the secret is successfully fetched from the vault. In case of failure, ConnectorException should be thrown from the method
            map.put("encryptedConnAttr", valueMap);
            map.put("status", "success");

        } catch (VaultException | IOException | KeyManagementException | KeyStoreException | NoSuchAlgorithmException e) {
            throw new ConnectorException(e.getMessage());
        }

        //log.log(Level.INFO, "Returned map: {0}", map.toString());
        log.log(Level.INFO, "Exit getSecret method");
        return map;
    }

    /**
     * This method is used by the vault connector framework to modify the value
     * of the vaultConfigData parameter before it is passed to getSecret() or
     * setSecret() methods. Skip this method if no modification is required in
     * the value of the vaultConfigData parameter.
     *
     * @param vaultConfigData This parameter is defined in the JSON format and
     * contains the key mappings for all the encrypted attributes of the
     * connection using the vault. It contains the mapping attributes that are
     * defined for every encrypted attribute in the vault configuration of the
     * connector in EIC UI. For each encrypted attribute, keyName and
     * encryptionMechanism are mandatory mapping attributes required by the
     * vault connector framework. The ignoreMapping attribute is an optional
     * mapping attribute. You can add additional mapping attributes under
     * keyMapping based on your requirement. For example, if you require a path
     * or a folder also as one of your mapping attribute, add it in the
     * keyMapping that you provide for each encrypted attribute on the vault
     * configuration UI of the connector in EIC UI.
     *
     * ignoreMapping: By default, the vault connector framework adds the name of
     * the connection as a prefix to all of the mappings attributes of the
     * encrypted attributes to uniquely save and identify the connection in the
     * vault. Specify this attribute if you do not want the vault connector
     * framework to append the connection name to it. For example, if keyName is
     * not specified in the ignoreMapping attribute, the vault connector
     * framework sends the value of keyName in vaultConfigData as
     * MyADConnector~#~abcd215 where MyADConnector is the name of the connection
     * and abcd215 is the name of the key.
     *
     * keyName: This is the name of the encrypted attribute stored in the vault.
     *
     * encryptionmechanism: This is the name of the encryption mechanism used
     * for retrieving the secret from the vault. Encryption is handled
     * internally by the vault connector framework. Value of the secret returned
     * from this method will be decrypted by the Vault connector framework as
     * per selected encryption mechanism. The encryption mechanism can be None,
     * Encrypted or Base64.
     *
     * <P>
     * Below is an example where PASSWORD is an encrypted attribute mapped with
     * a value of abcd215.      <pre>
     * "vaultConfigData": {
     * "keyMapping": {
     * "PASSWORD": {
     * "keyName": "abcd215",
     * "encryptionmechanism":"None"/"Encrypted"/"Base64"
     * "ignoreMapping":[
     * "keyName"
     * ]
     * }
     * }
     * }
     * </pre>
     *
     * @return a map containing vaultConfigData which can be modified as per
     * the requirement. This formatted map will be used as new vaultConfigData
     * in getSecret and setSeret methods. If no modification is required, return
     * null.
     */
    @Override
    public Map dataFormatting(Map vaultConfigData) {
        log.log(Level.INFO, "In dataFormatting method");
        log.log(Level.INFO, "Received following parameters in dataFormatting method");
        log.log(Level.INFO, "vaultConfigData :  {0}", vaultConfigData);

        // The value for the incoming map ("vaultConfigData") can be modified in this method and the modified map can be returned.
        //Example code: 
        /*
			Map<String, Object> keyMapping=(Map<String, Object>) vaultConfigData.get("keyMapping");
			keyMapping.put("keyName", "newKeyName@123");
         */
        //For sampleVault we are not doing any changes in vaultConfigData, so returning null
        log.log(Level.INFO, "Exit dataFormatting method");
        return null;
    }

    /**
     * This method is used to test the connection with the vault.Note - This is
     * for future implementation and must be ignored for now.
     * @param vaultConfigData
     * @param data
     * @return 
     */
    @Override
    public Map test(Map<String, Object> vaultConfigData, Map<String, Object> data) throws ConnectorException,
            InvalidCredentialException, InvalidAttributeValueException, OperationTimeoutException, MissingKeyException {
        // This is for future implementation and must be ignored for now.
        log.log(Level.INFO, "In test method");
        log.log(Level.INFO, "Exit test method");
        return null;
    }

    /**
     * Note - This is for future implementation and must be ignored for now.
     * @param vaultConfigData
     * @param data
     * @return 
     */
    @Override
    public Map seal(Map<String, Object> vaultConfigData, Map<String, Object> data) throws ConnectorException {
        return null;
    }

    /**
     * Note - This is for future implementation and must be ignored for now.
     * @param vaultConfigData
     * @param data
     * @return 
     */
    @Override
    public Map unseal(Map<String, Object> vaultConfigData, Map<String, Object> data) throws ConnectorException {
        return null;
    }

    /**
     * This is a utility method for logging the map in a proper format.
     * @param map
     * @return 
     * @throws com.fasterxml.jackson.core.JsonProcessingException 
     */
    public String prettyPrint(Map<String, Object> map) throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(map);
    }
}
