// FiddleZAP is a simplified version of EKFiddle for OWASP ZAP
// This is the passive rules script
// version: 0.0.1

// Declare global variables
var PluginPassiveScanner = Java.type("org.zaproxy.zap.extension.pscan.PluginPassiveScanner");
var extNeon = org.parosproxy.paros.control.Control.getSingleton().getExtensionLoader().getExtension("ExtensionNeonMarker");
var System = Java.type('java.lang.System');

// Warn user if Neonmarker add-on was not found
if (extNeon != null) {
    print('Neonmarker add-on installed properly');
} else {
    print('Please install the Neonmarker add-on to have color mapping');
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

/**
 * Passively scans an HTTP message. The scan function will be called for 
 * request/response made via ZAP, actual messages depend on the function
 * "appliesToHistoryType", defined below.
 * 
 * @param ps - the PassiveScan parent object that will do all the core interface tasks 
 *     (i.e.: providing access to Threshold settings, raising alerts, etc.). 
 *     This is an ScriptsPassiveScanner object.
 * @param msg - the HTTP Message being scanned. This is an HttpMessage object.
 * @param src - the Jericho Source representation of the message being scanned.
 */

function scan(ps, msg, src) {
    // Overall dynamic variables
    var url = msg.getRequestHeader().getURI().toString();
    var hostname = msg.getRequestHeader().getHostName().toString()
    var body = msg.getResponseBody().toString()

    // Ignore certain types of content
    var contenttype = msg.getResponseHeader().getHeader("Content-Type")
    var unwantedfiletypes = ['image/png', 'image/jpeg', 'image/gif', 'application/x-shockwave-flash', 'application/pdf']

    if (unwantedfiletypes.indexOf("" + contenttype) >= 0) {
        // Ignore unwanted content
        return
    } else {
        // Loop through rules Array
        for (var i = 0; i < rulesArray.length; i++) {
            // Check for SourceCode in body
            if (rulesArray[i].alertType == "SourceCode") {
                if (rulesArray[i].alertRegex.test(body)) {
                    rulesArray[i].alertRegex.lastIndex = 0 // Reset index
                    // Look for match
                    var matchFound = []
                    var comm
                    while (comm = rulesArray[i].alertRegex.exec(body)) {
                        matchFound.push(comm[0]);
                    }
                    // A match was found
                    print("Found " + rulesArray[i].alertTitle + " in: " + url);
                    // Call function to tag and alert 
                    tagAlert(ps,
                        rulesArray[i].alertTitle,
                        hostname, rulesArray[i].alertRisk,
                        rulesArray[i].alertConfidence,
                        rulesArray[i].alertDesc,
                        rulesArray[i].alertRegex.source,
                        rulesArray[i].alertSolution,
                        rulesArray[i].alertCweId,
                        rulesArray[i].alertWascId)
                }
            }
            // Check for URI in url
            if (rulesArray[i].alertType == "URI") {
                if (rulesArray[i].alertRegex.test(url)) {
                    rulesArray[i].alertRegex.lastIndex = 0 // Reset index
                    // Look for match
                    var matchFound = []
                    var comm
                    while (comm = rulesArray[i].alertRegex.exec(url)) {
                        matchFound.push(comm[0]);
                    }
                    // A match was found
                    print("Found " + rulesArray[i].alertTitle + " in: " + url);
                    // Call function to tag and alert 
                    tagAlert(ps,
                        rulesArray[i].alertTitle,
                        hostname, rulesArray[i].alertRisk,
                        rulesArray[i].alertConfidence,
                        rulesArray[i].alertDesc,
                        rulesArray[i].alertRegex.source,
                        rulesArray[i].alertSolution,
                        rulesArray[i].alertCweId,
                        rulesArray[i].alertWascId)
                }
            }

        } // end of loop through alert rules

    } // end of unwanted files check

} // end of function

/**
 * Tells whether or not the scanner applies to the given history type.
 *
 * @param {Number} historyType - The ID of the history type of the message to be scanned.
 * @return {boolean} Whether or not the message with the given type should be scanned by this scanner.
 */
function appliesToHistoryType(historyType) {
    // For example, to just scan spider messages:
    // return historyType == org.parosproxy.paros.model.HistoryReference.TYPE_SPIDER;

    // Default behaviour scans default types.
    return PluginPassiveScanner.getDefaultHistoryTypes().contains(historyType);
}


function loadScriptFromFile(file) {
    var Files = Java.type('java.nio.file.Files');
    var Paths = Java.type('java.nio.file.Paths');
    var String = Java.type('java.lang.String');

    var filePath = Paths.get(file);
    return new String(Files.readAllBytes(filePath), 'UTF-8');
}

function tagAlert(ps, alertTitle, hostname, alertRisk, alertConfidence, alertDesc, alertRegex, alertSolution, alertCweId, alertWascId) {
    ps.addTag(alertTitle);
    if (extNeon != null) {
        extNeon.addColorMapping(alertTitle, alertColor);
    }
    ps.newAlert()
        .setRisk(alertRisk)
        .setConfidence(alertConfidence)
        .setName(alertTitle + " at: " + hostname)
        .setDescription(alertDesc)
        .setParam('')
        .setEvidence(alertRegex)
        .setOtherInfo('')
        .setSolution(alertSolution)
        .setReference(alertReference)
        .setCweId(alertCweId)
        .setWascId(alertWascId)
        .raise();
}