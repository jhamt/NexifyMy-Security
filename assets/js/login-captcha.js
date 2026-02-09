/**
 * NexifyMy Security - Login Captcha JavaScript
 */

(function () {
  "use strict";

  var retries = 0;
  var maxRetries = 40;

  function setRecaptchaV3Tokens() {
    var tokenFields = document.querySelectorAll(".nexifymy-recaptcha-v3-token");
    if (!tokenFields.length) {
      return;
    }

    if (
      typeof window.grecaptcha === "undefined" ||
      typeof window.grecaptcha.ready !== "function"
    ) {
      if (retries < maxRetries) {
        retries++;
        window.setTimeout(setRecaptchaV3Tokens, 250);
      }
      return;
    }

    window.grecaptcha.ready(function () {
      tokenFields.forEach(function (field) {
        var siteKey = field.getAttribute("data-site-key");
        var action = field.getAttribute("data-action") || "login";

        if (!siteKey) {
          return;
        }

        window.grecaptcha.execute(siteKey, { action: action }).then(function (token) {
          field.value = token;
        });
      });
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", setRecaptchaV3Tokens);
  } else {
    setRecaptchaV3Tokens();
  }
})();
