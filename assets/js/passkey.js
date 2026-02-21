/**
 * NexifyMy Security - Passkey/WebAuthn JavaScript
 * Handles registration and authentication using the Web Authentication API.
 */

(function ($) {
  "use strict";

  // Check WebAuthn support.
  if (!window.PublicKeyCredential) {
    console.log("WebAuthn not supported in this browser.");
    return;
  }

  /**
   * Base64URL encode/decode utilities.
   */
  const base64url = {
    encode: function (buffer) {
      const bytes = new Uint8Array(buffer);
      let str = "";
      for (let i = 0; i < bytes.length; i++) {
        str += String.fromCharCode(bytes[i]);
      }
      return btoa(str)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");
    },
    decode: function (str) {
      str = str.replace(/-/g, "+").replace(/_/g, "/");
      while (str.length % 4) {
        str += "=";
      }
      const decoded = atob(str);
      const bytes = new Uint8Array(decoded.length);
      for (let i = 0; i < decoded.length; i++) {
        bytes[i] = decoded.charCodeAt(i);
      }
      return bytes.buffer;
    },
  };

  /**
   * Register a new passkey.
   */
  async function registerPasskey(name) {
    try {
      // Get registration options from server.
      const optionsResponse = await $.ajax({
        url: nexifymyPasskey.ajaxUrl,
        type: "POST",
        data: {
          action: "nexifymy_passkey_register_options",
          nonce: nexifymyPasskey.nonce,
        },
      });

      if (!optionsResponse.success) {
        throw new Error(
          optionsResponse.data || "Failed to get registration options."
        );
      }

      const options = optionsResponse.data;

      // Convert base64url to ArrayBuffer.
      options.challenge = base64url.decode(options.challenge);
      options.user.id = base64url.decode(options.user.id);

      if (options.excludeCredentials) {
        options.excludeCredentials = options.excludeCredentials.map((cred) => ({
          ...cred,
          id: base64url.decode(cred.id),
        }));
      }

      // Create credential.
      const credential = await navigator.credentials.create({
        publicKey: options,
      });

      // Prepare response for server.
      const response = {
        id: credential.id,
        rawId: base64url.encode(credential.rawId),
        type: credential.type,
        clientDataJSON: base64url.encode(credential.response.clientDataJSON),
        attestationObject: base64url.encode(
          credential.response.attestationObject
        ),
      };

      // Verify with server.
      const verifyResponse = await $.ajax({
        url: nexifymyPasskey.ajaxUrl,
        type: "POST",
        data: {
          action: "nexifymy_passkey_register_verify",
          nonce: nexifymyPasskey.nonce,
          name: name || "Passkey",
          response: JSON.stringify(response),
        },
      });

      if (!verifyResponse.success) {
        throw new Error(
          verifyResponse.data || "Failed to verify registration."
        );
      }

      return { success: true, message: verifyResponse.data.message };
    } catch (error) {
      console.error("Passkey registration error:", error);
      return {
        success: false,
        message: error.message || "Registration failed.",
      };
    }
  }

  /**
   * Authenticate with a passkey.
   */
  async function authenticatePasskey() {
    try {
      // Get authentication options from server.
      const optionsResponse = await $.ajax({
        url: nexifymyPasskey.ajaxUrl,
        type: "POST",
        data: {
          action: "nexifymy_passkey_auth_options",
          nonce: nexifymyPasskey.nonce,
        },
      });

      if (!optionsResponse.success) {
        throw new Error(
          optionsResponse.data || "Failed to get authentication options."
        );
      }

      const options = optionsResponse.data;
      const sessionId = options.sessionId;

      // Convert base64url to ArrayBuffer.
      const publicKeyOptions = {
        challenge: base64url.decode(options.challenge),
        rpId: options.rpId,
        timeout: options.timeout,
        userVerification: options.userVerification,
      };

      if (options.allowCredentials) {
        publicKeyOptions.allowCredentials = options.allowCredentials.map(
          (cred) => ({
            type: cred.type,
            id: base64url.decode(cred.id),
          })
        );
      }

      // Get credential.
      const credential = await navigator.credentials.get({
        publicKey: publicKeyOptions,
      });

      // Prepare response for server.
      const response = {
        id: credential.id,
        rawId: base64url.encode(credential.rawId),
        type: credential.type,
        clientDataJSON: base64url.encode(credential.response.clientDataJSON),
        authenticatorData: base64url.encode(
          credential.response.authenticatorData
        ),
        signature: base64url.encode(credential.response.signature),
        userHandle: credential.response.userHandle
          ? base64url.encode(credential.response.userHandle)
          : null,
      };

      // Verify with server.
      const verifyResponse = await $.ajax({
        url: nexifymyPasskey.ajaxUrl,
        type: "POST",
        data: {
          action: "nexifymy_passkey_auth_verify",
          nonce: nexifymyPasskey.nonce,
          sessionId: sessionId,
          response: JSON.stringify(response),
        },
      });

      if (!verifyResponse.success) {
        throw new Error(verifyResponse.data || "Authentication failed.");
      }

      return {
        success: true,
        message: verifyResponse.data.message,
        redirectUrl: verifyResponse.data.redirectUrl,
      };
    } catch (error) {
      console.error("Passkey authentication error:", error);
      return {
        success: false,
        message: error.message || "Authentication failed.",
      };
    }
  }

  /**
   * Delete a passkey.
   */
  async function deletePasskey(credentialId) {
    try {
      const response = await $.ajax({
        url: nexifymyPasskey.ajaxUrl,
        type: "POST",
        data: {
          action: "nexifymy_passkey_delete",
          nonce: nexifymyPasskey.nonce,
          credentialId: credentialId,
        },
      });

      return {
        success: response.success,
        message: response.data?.message || response.data,
      };
    } catch (error) {
      return { success: false, message: error.message };
    }
  }

  // Initialize on DOM ready.
  $(document).ready(function () {
    // Login page: Passkey login button.
    $("#passkey-login-btn").on("click", async function () {
      const $btn = $(this);
      const originalText = $btn.html();

      $btn
        .prop("disabled", true)
        .html(
          '<span class="spinner is-active" style="float: none; margin: 0;"></span> ' +
            nexifymyPasskey.strings.authenticating
        );

      const result = await authenticatePasskey();

      if (result.success && result.redirectUrl) {
        window.location.href = result.redirectUrl;
      } else {
        $btn.prop("disabled", false).html(originalText);
        alert(result.message || nexifymyPasskey.strings.error);
      }
    });

    // Profile page: Register passkey button.
    $("#passkey-register-btn").on("click", async function () {
      const $btn = $(this);
      const $status = $("#passkey-status");
      const name = $("#passkey-name").val() || "Passkey";

      $btn.prop("disabled", true);
      $status.html(
        '<span class="spinner is-active" style="float: none;"></span> ' +
          nexifymyPasskey.strings.registering
      );

      const result = await registerPasskey(name);

      if (result.success) {
        $status.html(
          '<span style="color: green;">✓ ' +
            nexifymyPasskey.strings.registered +
            "</span>"
        );
        // Reload to show new passkey.
        setTimeout(() => location.reload(), 1000);
      } else {
        $status.html(
          '<span style="color: red;">✗ ' + result.message + "</span>"
        );
        $btn.prop("disabled", false);
      }
    });

    // Profile page: Delete passkey button.
    $(document).on("click", ".passkey-delete", async function () {
      if (!confirm(nexifymyPasskey.strings.confirmDelete)) {
        return;
      }

      const $btn = $(this);
      const credentialId = $btn.data("id");
      const $li = $btn.closest("li");

      $btn.prop("disabled", true);

      const result = await deletePasskey(credentialId);

      if (result.success) {
        $li.fadeOut(300, function () {
          $(this).remove();
          // Check if list is empty.
          if ($("#passkey-list ul li").length === 0) {
            $("#passkey-list").html(
              '<p class="description">No passkeys registered yet.</p>'
            );
          }
        });
      } else {
        alert(result.message);
        $btn.prop("disabled", false);
      }
    });
  });
})(jQuery);
