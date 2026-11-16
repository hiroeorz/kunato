"use strict";

(function () {
  var form = document.getElementById("login-form");
  var input = document.getElementById("token");
  var error = document.getElementById("login-error");
  var disabled = document.getElementById("auth-disabled");

  fetch("/api/v1/session", { credentials: "same-origin" })
    .then(function (response) {
      return response.json();
    })
    .then(function (session) {
      if (!session.enabled) {
        form.hidden = true;
        disabled.hidden = false;
        window.location.replace("/");
        return;
      }
      if (session.authenticated) {
        window.location.replace("/");
        return;
      }
      input.focus();
    })
    .catch(function () {
      error.textContent = "The console is not reachable.";
    });

  form.addEventListener("submit", function (event) {
    event.preventDefault();
    error.textContent = "";
    var token = input.value.trim();
    if (!token) {
      error.textContent = "Enter the console token.";
      return;
    }
    fetch("/api/v1/session", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: token }),
    })
      .then(function (response) {
        if (response.ok) {
          window.location.replace("/");
          return;
        }
        if (response.status === 429) {
          error.textContent = "Too many attempts. Wait a minute and try again.";
          return;
        }
        error.textContent = "That token was not accepted.";
      })
      .catch(function () {
        error.textContent = "The console is not reachable.";
      });
  });
})();
