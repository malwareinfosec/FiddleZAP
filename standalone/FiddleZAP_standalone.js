// FiddleZAP is a simplified version of EKFiddle for OWASP ZAP
// This is the standalone script
// version: 0.0.2

// Declare global variables
var extNeon = org.parosproxy.paros.control.Control.getSingleton().getExtensionLoader().getExtension("ExtensionNeonMarker");
var System = Java.type('java.lang.System');
var extHist = org.parosproxy.paros.control.Control.getSingleton().
getExtensionLoader().getExtension(org.parosproxy.paros.extension.history.ExtensionHistory.NAME);
var extensionAlert = org.parosproxy.paros.control.Control.getSingleton().getExtensionLoader().getExtension(
    org.zaproxy.zap.extension.alert.ExtensionAlert.NAME)

// Warn user if Neonmarker add-on was not found
if (extNeon != null) {
    print('Neonmarker add-on installed properly');
} else {
    print('Please install the Neonmarker add-on to have color mapping');
}

// Warn user if extension alert is not installed
if (extensionAlert != null) {
    print('extensionAlert add-on installed properly');
} else {
    print('Please install the extensionAlert');
}

// Get operating system
var OS = System.getProperty('os.name').toLowerCase();
if (OS.indexOf("win") >= 0) {
    var FiddleZAPPath = (System.getProperty('user.home') + '\\Documents\\' + 'FiddleZAP' + '\\');
    print('Windows OS: ' + FiddleZAPPath);
}
if (OS.indexOf("mac") >= 0) {
    var FiddleZAPPath = (System.getProperty('user.home') + '/Documents/' + 'FiddleZAP' + '/');
    print('Mac OS: ' + FiddleZAPPath);
}
if (OS.indexOf("nix") >= 0 ||
    OS.indexOf("nux") >= 0 ||
    OS.indexOf("aix") > 0) {
    var FiddleZAPPath = (System.getProperty('user.home') + '/Documents/' + 'FiddleZAP' + '/');
    print('Linux OS: ' + FiddleZAPPath);
}

// Override path
// if for some reason the path is not correct
// you can uncomment the below and write your own
// var FiddleZAPPath = '';


// Load rules (regexes)
// rulesPath
communityRules = FiddleZAPPath + 'community_rules.txt'
userRules = FiddleZAPPath + 'user_rules.txt'

var rulesArray = [];

var communityRulesArr = loadScriptFromFile(communityRules).split("\r\n");
var userRulesArr = loadScriptFromFile(userRules).split("\r\n");

var tempArr = communityRulesArr.concat(userRulesArr);

for (var i = 0; i < tempArr.length; i++) {
    if (tempArr[i].startsWith("alertType")) {
        var alertType = tempArr[i].split('alertType:').pop().split('; alertTitle:')[0];
        var alertTitle = tempArr[i].split('alertTitle:\"').pop().split('\"; alertRegex:')[0];
        var alertRegex = new RegExp(tempArr[i].split('alertRegex:\/').pop().split('\/; alertColor:')[0], 'g');
        var alertColor = Number(tempArr[i].split('alertColor:\"').pop().split('\"; alertRisk:')[0]);
        var alertRisk = Number(tempArr[i].split('alertRisk:').pop().split('; alertConfidence:')[0]);
        var alertConfidence = Number(tempArr[i].split('alertConfidence:').pop().split('; alertDesc:')[0]);
        var alertDesc = tempArr[i].split('alertDesc:\"').pop().split('\"; alertSolution:')[0];
        var alertSolution = tempArr[i].split('alertSolution:\"').pop().split('\"; alertReference:')[0];
        var alertReference = tempArr[i].split('alertReference:"').pop().split('\"; alertCweId:')[0];
        var alertCweId = Number(tempArr[i].split('alertCweId:').pop().split('; alertWascId:')[0]);
        var alertWascId = Number(tempArr[i].split('alertWascId:').pop().split('\$')[0]);

        rulesArray.push({
            "alertType": alertType,
            "alertTitle": alertTitle,
            "alertRegex": alertRegex,
            "alertColor": alertColor,
            "alertRisk": alertRisk,
            "alertConfidence": alertConfidence,
            "alertDesc": alertDesc,
            "alertSolution": alertSolution,
            "alertReference": alertReference,
            "alertCweId": alertCweId,
            "alertWascId": alertWascId
        });
    }
}

print('Rules have been loaded');

function listChildren(node, level) {
    var j;
    for (j = 0; j < node.getChildCount(); j++) {
        uri = node.getChildAt(j).getHistoryReference().getURI().toString();
        msg = node.getChildAt(j).getHistoryReference().getHttpMessage();
        hostname = node.getChildAt(j).getHistoryReference().getURI().getHost().toString();
        currentId = node.getChildAt(j).getHistoryReference().getHistoryId();

        // Loop through rules Array
        for (var i = 0; i < rulesArray.length; i++) {

            // Call URI regexes function
            URIRegexes(rulesArray[i].alertType, rulesArray[i].alertRegex, currentId, uri, 
             rulesArray[i].alertTitle, hostname, rulesArray[i].alertRisk, rulesArray[i].alertConfidence,
             rulesArray[i].alertDesc, rulesArray[i].alertSolution, rulesArray[i].alertReference, rulesArray[i].alertCweId, rulesArray[i].alertWascId);

            // Call SourceCode regexes function
            responseLength = msg.getResponseBody().length();
            if (responseLength > 0) {
                responseBody = msg.getResponseBody().toString();
                SourceCodeRegexes(responseBody, rulesArray[i].alertType, rulesArray[i].alertRegex, currentId, uri,
                 rulesArray[i].alertTitle, hostname, rulesArray[i].alertRisk, rulesArray[i].alertConfidence,
                 rulesArray[i].alertDesc, rulesArray[i].alertSolution, rulesArray[i].alertReference, rulesArray[i].alertCweId, rulesArray[i].alertWascId);
            }
        }

        listChildren(node.getChildAt(j), level + 1);
    }
}

root = org.parosproxy.paros.model.Model.getSingleton().
getSession().getSiteTree().getRoot();

listChildren(root, 0);


function loadScriptFromFile(file) {
    var Files = Java.type('java.nio.file.Files');
    var Paths = Java.type('java.nio.file.Paths');
    var String = Java.type('java.lang.String');

    var filePath = Paths.get(file);
    return new String(Files.readAllBytes(filePath), 'UTF-8');
}

function tagAlert(hr, alertType, alertRegex, currentId, uri, alertTitle, hostname,
 alertRisk, alertConfidence, alertDesc, alertSolution, alertReference, alertCweId, alertWascId) {
    hr.addTag(alertTitle);
    if (extNeon != null) {
        extNeon.addColorMapping(alertTitle, alertColor);
    }

    if (extensionAlert != null) {
        var alert = new org.parosproxy.paros.core.scanner.Alert(1, alertRisk, 3, alertTitle)
        alert.setMessage(msg)
        alert.setUri(msg.getRequestHeader().getURI().toString())
        alert.setDescription(alertDesc);
		alert.setReference(alertReference);
        alert.setEvidence(alertRegex.toString())
        extensionAlert.alertFound(alert, hr)
    }
}

function URIRegexes(alertType, alertRegex, currentId, uri, alertTitle, hostname,
 alertRisk, alertConfidence, alertDesc, alertSolution, alertReference, alertCweId, alertWascId) {
    // Check for URI in url
    if (alertType == "URI") {
        if (alertRegex.test(uri)) {
            alertRegex.lastIndex = 0 // Reset index
            // Look for match
            var matchFound = []
            var comm
            while (comm = alertRegex.exec(uri)) {
                matchFound.push(comm[0]);
            }
            // A match was found
            print("Found " + alertTitle + " in: " + uri);
            // Call function to tag and alert
            hr = extHist.getHistoryReference(currentId);
            tagAlert(hr, alertType, alertRegex, currentId, uri, alertTitle, hostname, alertRisk,
             alertConfidence, alertDesc, alertSolution, alertReference, alertCweId, alertWascId);

        }
    }
}

function SourceCodeRegexes(responseBody, alertType, alertRegex, currentId, uri, alertTitle, hostname,
 alertRisk, alertConfidence, alertDesc, alertSolution, alertReference, alertCweId, alertWascId) {
    // Check for SourceCode in responseBody
    if (alertType == "SourceCode") {
        if (alertRegex.test(responseBody)) {
            alertRegex.lastIndex = 0 // Reset index
            // Look for match
            var matchFound = []
            var comm
            while (comm = alertRegex.exec(responseBody)) {
                matchFound.push(comm[0]);
            }
            // A match was found
            print("Found " + alertTitle + " in: " + uri);
            // Call function to tag and alert
            hr = extHist.getHistoryReference(currentId);
            tagAlert(hr, alertType, alertRegex, currentId, uri, alertTitle, hostname, alertRisk,
             alertConfidence, alertDesc, alertSolution, alertReference, alertCweId, alertWascId);

        }
    }
}