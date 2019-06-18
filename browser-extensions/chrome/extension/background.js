function sendManualMessage(message, sendResponse) {
  chrome.runtime.sendNativeMessage("eidonkey", message, sendResponse);
//  appendMessage("Sent message: <b>" + JSON.stringify(message) + "</b>");
}

chrome.runtime.onMessageExternal.addListener(
	function(request, sender, sendResponse) {
		console.log("Message received " + request);
		if (request.path) {
			sendManualMessage(request, sendResponse);        
	} 
});