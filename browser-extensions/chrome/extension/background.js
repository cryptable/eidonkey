
chrome.runtime.onMessageExternal.addListener(
	(request, sender, sendResponse) => {
		console.log("Message received " + request.path);
		if (request.path) {
			chrome.runtime.sendNativeMessage("eidonkey", request, function(resp) {
				console.log("Message received " + resp);
				sendResponse(resp);
			});
		}
		else {
			sendResponse("{error}");
		}
		return true;
	}
);