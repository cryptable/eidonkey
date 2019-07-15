// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

function appendMessage(text) {
  document.getElementById('response').innerHTML += "<p>" + text + "</p>";
}

function sendMessage() {
  message = {"path": document.getElementById('input-text').value};
  chrome.runtime.sendNativeMessage("eidonkey", message, onNativeMessage);
  appendMessage("Sent message: <b>" + JSON.stringify(message) + "</b>");
}

function onNativeMessage(message) {
  if (message === undefined) {
    appendMessage("Failed message: " + chrome.runtime.lastError.message);
  } else {
    appendMessage("Received message: <b>" + JSON.stringify(message) + "</b>");
  }
  return true;
}

document.addEventListener('DOMContentLoaded', function () {
  document.getElementById('send-message-button').addEventListener(
      'click', sendMessage);
});

