import msal from '@azure/msal-node';
import axios from 'axios';

const cca = new msal.ConfidentialClientApplication(config.msalConfig);
const MS_GRAPH_SCOPE = 'https://graph.microsoft.com/';

var graph = {};

graph.tokenRequest = {
    scopes: [MS_GRAPH_SCOPE + '.default'],
};

graph.apiConfig = {
    users: `${MS_GRAPH_SCOPE}v1.0/users?$filter=userType eq 'Member'&\$select=displayName,mail,accountEnabled`,
};

graph.getToken = async function getToken(tokenRequest) {
    return await cca.acquireTokenByClientCredential(tokenRequest);
};

graph.callApi = async function callApi(endpoint, accessToken, opts = {}) {

    const options = {
        headers: {
            Authorization: `Bearer ${accessToken}`
        }
    };

    if (opts.id)
        endpoint = endpoint.replace('{id}', opts.id);

    try {
        let data = [];
        let response = await axios.get(endpoint, options);
        data = [...data, ...response.data.value];

        // call nextLink as long as it exists, so all data should be fetched
        while (response.data.hasOwnProperty('@odata.nextLink')) {
            console.log('graph_azuread.js', "callApi", { endpoint: endpoint, '@odata.nextLink': response.data['@odata.nextLink'] });
            response = await axios.get(response.data['@odata.nextLink'], options);
            // concat previous (nextLink-)data with current nextLink-data
            data = [...data, ...response.data.value];
        }
        return data;
    } catch (error) {
        logger.info('[msGraph]', 'callApi-error', error);
        logger.info('[msGraph]', 'callApi-endpoint', endpoint);
        logger.info('[msGraph]', 'callApi-opts', opts);
        return error;
    }
};

const msGraphHandler = {};

msGraphHandler.fetchAzureADUsers = async () => {

    logger.info(`[msGraph] Fetching Users From Azure AD`);

    // token to fetch users/groups
    const graph_azureResponse = await graph.getToken(graph.tokenRequest);
    if (!graph_azureResponse) console.log('error');

    var users = [];
    users = await graph.callApi(graph.apiConfig.users, graph_azureResponse.accessToken);
    
    if (typeof users === 'undefined' || !users) {
        logger.error("[msGraph] Could not fetch users.");
    }
    else {
        AzureADUsers = users;
    }
    setTimeout(msGraphHandler.fetchAzureADUsers, 1800000); // Update users on 30 minute loop
}

msGraphHandler.ValidateUser = (user) => {
    
    // Userlist aanwezig??
    if (Object.keys(AzureADUsers).length === 0 || !AzureADUsers) {
        logger.error(`[msGraph] Azure Userlist not available!! [FORCE AccountEnabled: true]`);
        return true;
    }

    else {
        
        // User in Azure?
        var azureuser = AzureADUsers.find(item => item.displayName === user['CN']);
       
        if (azureuser && azureuser.accountEnabled === true) {
            logger.info(`[msGraph][CN=${user['CN']}] mail: ${azureuser.mail} | AccountEnabled: ${azureuser.accountEnabled}`);
            return true;
        }
    }
    logger.error(`[msGraph][CN=${user['CN']}] mail: ${user['emailAddress']} | AccountEnabled: false`);
    return false;
}

export default msGraphHandler;