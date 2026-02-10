/**
 * NexifyMy Security Admin JavaScript
 */

(function ($) {
  "use strict";

  var NexifymySecurity = {
    init: function () {
      this.bindEvents();
      this.loadDashboardData();
      this.loadLogs();
      this.loadNotifications();
      this.loadBlockedIPs();
      this.loadQuarantinedFiles();
      this.loadDeletedQuarantineFiles();
      this.loadDatabaseInfo();
      this.loadBackups();
      this.loadOptimizationStats();
      this.loadLiveTraffic();
      this.loadTrafficStats();
      this.loadCountryList();
      this.loadHardeningStatus();
      this.loadCdnStatus();
      this.loadVulnerabilityResults();
      this.loadVulnerabilitySettings();
      this.loadPasswordSettings();
      this.loadAnalyticsDashboard();
    },

    bindEvents: function () {
      // Tab Navigation is handled by the delegated handler below in TAB NAVIGATION HANDLERS section

      // Quick scan buttons on dashboard
      $("#run-quick-scan").on("click", function () {
        NexifymySecurity.runScan("quick");
      });

      $("#run-deep-scan").on("click", function () {
        NexifymySecurity.runScan("deep");
      });

      // Scanner page buttons
      $(".scan-btn").on("click", function () {
        var mode = $(this).closest(".nms-scan-mode-card").data("mode");
        NexifymySecurity.runScan(mode);
      });

      // Logs page
      $("#refresh-logs").on("click", function () {
        NexifymySecurity.loadLogs();
      });

      $("#log-severity-filter").on("change", function () {
        NexifymySecurity.loadLogs();
      });

      // Settings
      $("#save-schedule").on("click", function () {
        NexifymySecurity.saveSchedule();
      });

      // General Settings Save
      $("#save-general-settings").on("click", function () {
        var $btn = $(this);
        var $status = $("#general-status");
        var originalText = $btn.text();

        var settings = {
          general: {
            language: $("#settings-language").val(),
            email_notifications: $("#settings-email").is(":checked") ? 1 : 0,
            email_address: $("#settings-email-address").val(),
            auto_updates: $("#settings-auto-update").is(":checked") ? 1 : 0,
          },
        };

        $btn.prop("disabled", true).text("Saving...");
        $status.html('<span style="color: #666;">Saving...</span>');

        $.ajax({
          url: nexifymySecurity.ajaxUrl,
          type: "POST",
          dataType: "json",
          data: {
            action: "nexifymy_save_settings",
            settings: settings,
            nonce: nexifymySecurity.nonce,
          },
          success: function (response) {
            $btn.prop("disabled", false).text(originalText);
            if (response.success) {
              $status.html(
                '<span style="color: var(--nms-success);">Saved! Reloading...</span>',
              );
              // Reload to apply language changes
              setTimeout(function () {
                location.reload();
              }, 1000);
            } else {
              $status.html(
                '<span style="color: var(--nms-danger);">' +
                  (response.data || "Failed") +
                  "</span>",
              );
            }
          },
          error: function (jqXHR) {
            $btn.prop("disabled", false).text(originalText);
            var raw =
              jqXHR && typeof jqXHR.responseText === "string"
                ? jqXHR.responseText.trim()
                : "";
            $status.html(
              '<span style="color: var(--nms-danger);">' +
                (raw === "-1"
                  ? "Security check failed. Refresh and try again."
                  : raw === "0"
                    ? "Settings handler not available."
                    : "Connection error") +
                "</span>",
            );
          },
        });
      });

      // New Settings Form
      $("#nexifymy-settings-form").on("submit", function (e) {
        e.preventDefault();
        NexifymySecurity.saveAllSettings();
      });

      $("#reset-settings").on("click", function () {
        if (confirm("Reset all settings to defaults? This cannot be undone.")) {
          NexifymySecurity.resetSettings();
        }
      });

      // Quarantine
      $("#refresh-quarantine").on("click", function () {
        NexifymySecurity.loadQuarantinedFiles();
        NexifymySecurity.loadDeletedQuarantineFiles();
      });

      // Live Traffic
      $("#refresh-traffic").on("click", function () {
        NexifymySecurity.loadLiveTraffic();
        NexifymySecurity.loadTrafficStats();
      });

      // Scan buttons in dashboard tab
      $(document).on("click", ".scan-btn[data-mode]", function (e) {
        e.preventDefault();
        var mode = $(this).data("mode");
        NexifymySecurity.runScan(mode);
      });

      // CDN
      $("#save-cdn-settings").on("click", function () {
        NexifymySecurity.saveCdnSettings($(this), $("#cdn-settings-status"));
      });

      $("#test-cdn-connection").on("click", function () {
        NexifymySecurity.testCdnConnection($(this), $("#cdn-settings-status"));
      });

      $("#purge-cdn-cache").on("click", function () {
        if (confirm("Purge CDN cache now?")) {
          NexifymySecurity.purgeCdnCache($(this), $("#cdn-settings-status"));
        }
      });

      // Vulnerability Scanner
      $("#run-vuln-scan").on("click", function () {
        NexifymySecurity.runVulnerabilityScan($(this), $("#vuln-scan-status"));
      });

      $("#save-vuln-settings").on("click", function () {
        NexifymySecurity.saveVulnerabilitySettings(
          $(this),
          $("#vuln-settings-status"),
        );
      });

      // Core File Verification
      $("#verify-core").on("click", function () {
        NexifymySecurity.verifyCoreFiles($(this));
      });

      // Test Alert
      $("#test-alert").on("click", function () {
        NexifymySecurity.sendTestAlert();
      });

      // Notifications
      $("#mark-all-notifications-read").on("click", function () {
        NexifymySecurity.markAllNotificationsRead();
      });

      // Dashboard tab switching - works with both horizontal tabs and sidebar
      $(document).on(
        "click",
        ".nms-tabs .nms-tab[data-tab], .nms-sidebar-link[data-tab]",
        function (e) {
          e.preventDefault();
          var tabId = $(this).data("tab");
          var $wrapper = $(this).closest(".nexifymy-security-wrap");

          // Update active tab/sidebar link within this page
          $wrapper.find(".nms-tabs .nms-tab").removeClass("active");
          $wrapper.find(".nms-sidebar-link").removeClass("active");
          $(this).addClass("active");
          $wrapper
            .find('.nms-sidebar-link[data-tab="' + tabId + '"]')
            .addClass("active");

          // Show corresponding content within this page wrapper
          $wrapper.find(".nms-tab-content").removeClass("active");
          $wrapper.find("#nms-tab-" + tabId).addClass("active");
        },
      );

      // Module toggle switches
      // Dashboard Module Toggles - Track changes
      var moduleChanges = {};

      $(".nms-toggle input[data-module], .module-toggle[data-module]").on(
        "change",
        function () {
          var $this = $(this);
          var module = $this.data("module");
          var enabled = $this.is(":checked");
          var isModulesHubToggle = $this.hasClass("module-toggle");

          // Check if we're on modules hub page (immediate save) or dashboard page (track changes)
          var isModulesHub = $(".nms-modules-grid").length > 0;

          // Check if we're on dashboard page (has save button) and NOT on modules hub
          if ($("#save-module-toggles").length > 0 && !isModulesHub) {
            // Dashboard mode - just track changes
            moduleChanges[module] = enabled ? 1 : 0;
            $("#module-toggles-status").html(
              '<span style="color: #d63638;">●</span> Unsaved changes',
            );

            // Update card visual state
            var $card = $this.closest(".nms-module-card");
            if ($card.length) {
              if (enabled) {
                $card.addClass("active");
              } else {
                $card.removeClass("active");
              }
            }
            return;
          }

          // Modules hub page or other pages - auto-save immediately
          $.ajax({
            url: nexifymySecurity.ajaxUrl,
            type: "POST",
            dataType: "json",
            data: {
              action: "nexifymy_toggle_module",
              module: module,
              enabled: enabled ? 1 : 0,
              nonce: nexifymySecurity.nonce,
            },
            success: function (response) {
              if (
                response &&
                typeof response === "object" &&
                response.success
              ) {
                // Update card visual state
                var $card = $this.closest(".nms-card, .nms-module-card");
                if ($card.length) {
                  if (enabled) {
                    $card.addClass("active");
                  } else {
                    $card.removeClass("active");
                  }

                  // Update badge text and color
                  var $badge = $card.find(".nms-badge");
                  if ($badge.length) {
                    if (enabled) {
                      $badge
                        .removeClass("nms-badge-secondary")
                        .addClass("nms-badge-success")
                        .text("Active");
                    } else {
                      $badge
                        .removeClass("nms-badge-success")
                        .addClass("nms-badge-secondary")
                        .text("Inactive");
                    }
                  }

                  // Update icon color (modules hub page)
                  var $icon = $card.find(".nms-stat-icon");
                  if ($icon.length) {
                    if (enabled) {
                      $icon.removeClass("blue").addClass("green");
                    } else {
                      $icon.removeClass("green").addClass("blue");
                    }
                  }
                }

                // Show success notification for modules hub
                if (isModulesHub && typeof NexifymySecurity !== "undefined") {
                  NexifymySecurity.showNotice(
                    "success",
                    "Module " +
                      module +
                      " " +
                      (enabled ? "enabled" : "disabled"),
                  );
                }

                console.log(
                  "Module " + module + " " + (enabled ? "enabled" : "disabled"),
                );

                // Modules hub cards need a refresh so runtime module init/deinit is applied consistently.
                if (isModulesHubToggle) {
                  setTimeout(function () {
                    location.reload();
                  }, 350);
                }
              } else {
                // Revert toggle on error
                $this.prop("checked", !enabled);
                if (typeof NexifymySecurity !== "undefined") {
                  NexifymySecurity.showNotice(
                    "error",
                    "Error: " + (response.data || "Unknown error"),
                  );
                } else {
                  alert("Error: " + (response.data || "Unknown error"));
                }
              }
            },
            error: function (jqXHR) {
              $this.prop("checked", !enabled);
              if (typeof NexifymySecurity !== "undefined") {
                NexifymySecurity.showNotice(
                  "error",
                  "Failed to update module settings",
                );
              } else {
                alert("Failed to update module settings");
              }
            },
          });
        },
      );

      // Auto-update signatures toggle
      $("#auto-update-signatures").on("change", function () {
        var enabled = $(this).is(":checked") ? 1 : 0;

        $.ajax({
          url: nexifymySecurity.ajaxUrl,
          type: "POST",
          dataType: "json",
          data: {
            action: "nexifymy_toggle_auto_update",
            enabled: enabled,
            nonce: nexifymySecurity.nonce,
          },
          success: function (response) {
            if (response && typeof response === "object" && response.success) {
              NexifymySecurity.showNotice(
                "success",
                enabled ? "Auto-update enabled" : "Auto-update disabled",
              );
            } else {
              NexifymySecurity.showNotice(
                "error",
                "Auto-update failed: " +
                  ((response && response.data) || "Unknown error"),
              );
            }
          },
          error: function (jqXHR) {
            var raw =
              jqXHR && typeof jqXHR.responseText === "string"
                ? jqXHR.responseText.trim()
                : "";
            NexifymySecurity.showNotice(
              "error",
              raw === "-1"
                ? "Security check failed. Please refresh and try again."
                : raw === "0"
                  ? "Auto-update handler not available."
                  : "Network error during auto-update toggle.",
            );
          },
        });
      });

      // Update malware definitions button
      $("#update-definitions").on("click", function () {
        var $btn = $(this);
        var $status = $("#definition-status, #update-status");

        $btn.prop("disabled", true).find(".dashicons").addClass("spin");
        $status.html(
          '<span style="color: #666;"><i class="fa-solid fa-spinner fa-spin"></i> Fetching signatures from Wordfence Intelligence & PHP-Malware-Finder...</span>',
        );

        $.ajax({
          url: nexifymySecurity.ajaxUrl,
          type: "POST",
          dataType: "json",
          timeout: 120000, // 2 minute timeout for large fetches
          data: {
            action: "nexifymy_update_signatures",
            nonce: nexifymySecurity.nonce,
          },
          success: function (response) {
            $btn.prop("disabled", false).find(".dashicons").removeClass("spin");

            if (response && typeof response === "object" && response.success) {
              var data = response.data || {};

              // Build detailed success message
              var msg = '<i class="fa-solid fa-check-circle"></i> ';
              if (data.message) {
                msg += data.message;
              } else {
                msg +=
                  "Updated! Total: " + (data.total_count || 0) + " signatures";
              }

              // Show sources
              if (data.sources && data.sources.length > 0) {
                msg +=
                  '<br><small style="opacity: 0.8;">Sources: ' +
                  data.sources.join(", ") +
                  "</small>";
              }

              // Show any errors (partial success)
              if (data.errors && Object.keys(data.errors).length > 0) {
                msg +=
                  '<br><small style="color: #d63638;">Some sources failed: ' +
                  Object.keys(data.errors).join(", ") +
                  "</small>";
              }

              $status.html(
                '<span style="color: var(--nms-success);">' + msg + "</span>",
              );

              // Reload page to show new counts
              setTimeout(function () {
                location.reload();
              }, 3500);
            } else {
              var errMsg = "Update failed";
              if (response && response.data && response.data.errors) {
                errMsg = Object.values(response.data.errors).join("; ");
              } else if (response && response.data) {
                errMsg = response.data;
              }
              $status.html(
                '<span style="color: var(--nms-danger);"><i class="fa-solid fa-times-circle"></i> ' +
                  errMsg +
                  "</span>",
              );
            }
          },
          error: function (jqXHR, textStatus) {
            $btn.prop("disabled", false).find(".dashicons").removeClass("spin");

            var raw =
              jqXHR && typeof jqXHR.responseText === "string"
                ? jqXHR.responseText.trim()
                : "";

            if (textStatus === "timeout") {
              $status.html(
                '<span style="color: var(--nms-danger);"><i class="fa-solid fa-clock"></i> Request timed out. The signature database is large (~100MB). Try again.</span>',
              );
              return;
            }

            if (raw === "-1") {
              $status.html(
                '<span style="color: var(--nms-danger);">Security check failed. Please refresh and try again.</span>',
              );
              return;
            }

            if (raw === "0") {
              $status.html(
                '<span style="color: var(--nms-danger);">Update handler not available.</span>',
              );
              return;
            }
            $status.html(
              '<span style="color: var(--nms-danger);"><i class="fa-solid fa-exclamation-triangle"></i> Connection error</span>',
            );
          },
        });
      });

      // Generic module settings save function
      function saveModuleSettings(module, settings, $btn, $status) {
        $btn.prop("disabled", true);
        $status.html('<span style="color: #666;">Saving...</span>');

        $.ajax({
          url: nexifymySecurity.ajaxUrl,
          type: "POST",
          data: {
            action: "nexifymy_save_module_settings",
            module: module,
            settings: settings,
            nonce: nexifymySecurity.nonce,
          },
          success: function (response) {
            $btn.prop("disabled", false);
            if (response.success) {
              $status.html(
                '<span style="color: var(--nms-success);">Saved!</span>',
              );
              setTimeout(function () {
                $status.html("");
              }, 3000);
            } else {
              $status.html(
                '<span style="color: var(--nms-danger);">' +
                  (response.data || "Failed") +
                  "</span>",
              );
            }
          },
          error: function () {
            $btn.prop("disabled", false);
            $status.html(
              '<span style="color: var(--nms-danger);">Connection error</span>',
            );
          },
        });
      }

      // 2FA Settings Save
      $("#save-2fa-settings").on("click", function () {
        var mandatoryRoles = [];
        $('input[name="2fa-roles[]"]:checked').each(function () {
          mandatoryRoles.push($(this).val());
        });

        var settings = {
          enabled: $("#2fa-enabled").is(":checked") ? 1 : 0,
          force_admin: $("#2fa-force-admin").is(":checked") ? 1 : 0,
          force_all: $("#2fa-force-all").is(":checked") ? 1 : 0,
          email_backup:
            ($("#2fa-email-backup").length &&
              $("#2fa-email-backup").is(":checked")) ||
            ($("#2fa-email").length && $("#2fa-email").is(":checked"))
              ? 1
              : 0,
          remember_days:
            $("#2fa-remember-days").val() ||
            Math.max(
              1,
              Math.round(
                (parseInt($("#2fa-remember-duration").val(), 10) || 2592000) /
                  86400,
              ),
            ),
          totp_enabled: $("#2fa-totp").is(":checked") ? 1 : 0,
          email_enabled: $("#2fa-email").is(":checked") ? 1 : 0,
          backup_codes: $("#2fa-backup").is(":checked") ? 1 : 0,
          backup_code_count: $("#2fa-backup-count").val() || 10,
          mandatory_roles: mandatoryRoles,
          optional_all: $("#2fa-optional").is(":checked") ? 1 : 0,
          grace_period: $("#2fa-grace-period").val() || 7,
          remember_device: $("#2fa-remember").is(":checked") ? 1 : 0,
          remember_duration: $("#2fa-remember-duration").val() || 2592000,
          code_expiry: $("#2fa-code-expiry").val() || 300,
          max_attempts: $("#2fa-max-attempts").val() || 3,
          lockout_duration: $("#2fa-lockout").val() || 900,
          email_notify: $("#2fa-notify").is(":checked") ? 1 : 0,
        };
        saveModuleSettings("two_factor", settings, $(this), $("#2fa-status"));
      });

      // Hardening Settings Save
      $("#apply-hardening").on("click", function () {
        var settings = {};
        $("#hardening-options input[type=checkbox]").each(function () {
          settings[$(this).attr("name")] = $(this).is(":checked") ? 1 : 0;
        });
        saveModuleSettings(
          "hardening",
          settings,
          $(this),
          $("#hardening-status"),
        );
      });

      // Geo Blocking Settings Save
      // Geo Blocking: Add Countries to List
      $("#geo-add-countries").on("click", function () {
        var checkedBoxes = $(".geo-country-check:checked");
        if (checkedBoxes.length === 0) {
          alert("Please select at least one country to add.");
          return;
        }

        checkedBoxes.each(function () {
          var code = $(this).val();
          var label = $(this).parent().text().trim();
          // Add to selected list
          $("#geo-selected-list").append(
            '<label style="display: block; margin-bottom: 5px;"><input type="checkbox" class="geo-selected-check" value="' +
              code +
              '"> ' +
              label +
              "</label>",
          );
          // Remove from available list
          $(this).parent().remove();
        });

        // Remove "no countries" message if present
        $("#geo-selected-list p.description").remove();
      });

      // Geo Blocking: Remove Countries from List
      $("#geo-remove-countries").on("click", function () {
        var checkedBoxes = $(".geo-selected-check:checked");
        if (checkedBoxes.length === 0) {
          alert("Please select at least one country to remove.");
          return;
        }

        checkedBoxes.each(function () {
          var code = $(this).val();
          var label = $(this).parent().text().trim();
          // Add back to available list (alphabetically - simplified by just prepending)
          $(".geo-country-check")
            .first()
            .parent()
            .parent()
            .append(
              '<label style="display: block; margin-bottom: 5px;"><input type="checkbox" class="geo-country-check" value="' +
                code +
                '"> ' +
                label +
                "</label>",
            );
          // Remove from selected list
          $(this).parent().remove();
        });

        // Add "no countries" message if list is empty
        if ($(".geo-selected-check").length === 0) {
          $("#geo-selected-list").html(
            '<p class="description" style="margin: 0;">No countries selected yet.</p>',
          );
        }
      });

      $("#save-geo-settings").on("click", function () {
        var countries = [];
        $(".geo-selected-check").each(function () {
          countries.push($(this).val());
        });
        var settings = {
          enabled: $("#geo-enabled").is(":checked") ? 1 : 0,
          mode: $("#geo-mode").val(),
          countries: countries,
        };
        saveModuleSettings("geo_blocking", settings, $(this), $("#geo-status"));
      });

      // Save Module Hub Toggles (Modules Page)
      $("#save-module-hub-toggles").on("click", function () {
        var $btn = $(this);
        var $status = $("#module-hub-status");
        var changes = {};

        $(".module-toggle").each(function () {
          var module = $(this).data("module");
          var enabled = $(this).is(":checked") ? 1 : 0;
          changes[module] = enabled;
        });

        if (Object.keys(changes).length === 0) {
          $status.html(
            '<span style="color: #00a32a;">✓ No modules to save</span>',
          );
          setTimeout(function () {
            $status.html("");
          }, 3000);
          return;
        }

        $btn.prop("disabled", true).text("Saving...");
        $status.html('<span style="color: #999;">Saving modules...</span>');

        var promises = [];
        $.each(changes, function (module, enabled) {
          promises.push(
            $.ajax({
              url: nexifymySecurity.ajaxUrl,
              type: "POST",
              data: {
                action: "nexifymy_toggle_module",
                module: module,
                enabled: enabled,
                nonce: nexifymySecurity.nonce,
              },
            }),
          );
        });

        $.when
          .apply($, promises)
          .done(function () {
            $status.html(
              '<span style="color: #00a32a;">✓ All modules saved!</span>',
            );
            // Update badges and icons
            $(".module-toggle").each(function () {
              var $cardBody = $(this).closest(".nms-card-body");
              var $badge = $cardBody.find(".nms-badge");
              var $icon = $cardBody.find(".nms-stat-icon");
              if ($(this).is(":checked")) {
                $badge
                  .removeClass("nms-badge-secondary")
                  .addClass("nms-badge-success")
                  .text("Active");
                $icon.removeClass("blue").addClass("green");
              } else {
                $badge
                  .removeClass("nms-badge-success")
                  .addClass("nms-badge-secondary")
                  .text("Inactive");
                $icon.removeClass("green").addClass("blue");
              }
            });
            setTimeout(function () {
              $status.html("");
            }, 3000);
          })
          .fail(function () {
            $status.html(
              '<span style="color: #d63638;">✗ Error saving modules</span>',
            );
          })
          .always(function () {
            $btn
              .prop("disabled", false)
              .html(
                '<span class="dashicons dashicons-saved"></span> Save Module Settings',
              );
          });
      });

      // Save Module Toggles (Dashboard)
      $("#save-module-toggles").on("click", function () {
        var $btn = $(this);
        var $status = $("#module-toggles-status");

        if (Object.keys(moduleChanges).length === 0) {
          $status.html(
            '<span style="color: #00a32a;">✓ No changes to save</span>',
          );
          setTimeout(function () {
            $status.html("");
          }, 3000);
          return;
        }

        $btn.prop("disabled", true).text("Saving...");
        $status.html(
          '<span style="color: #999;">Saving ' +
            Object.keys(moduleChanges).length +
            " module(s)...</span>",
        );

        // Save each module toggle
        var promises = [];
        $.each(moduleChanges, function (module, enabled) {
          promises.push(
            $.ajax({
              url: nexifymySecurity.ajaxUrl,
              type: "POST",
              data: {
                action: "nexifymy_toggle_module",
                module: module,
                enabled: enabled,
                nonce: nexifymySecurity.nonce,
              },
            }),
          );
        });

        $.when
          .apply($, promises)
          .done(function () {
            $status.html(
              '<span style="color: #00a32a;">✓ All changes saved successfully!</span>',
            );
            moduleChanges = {}; // Clear changes

            // Update dashboard module cards visual state
            $(".nms-module-card").each(function () {
              var $card = $(this);
              var $toggle = $card.find("input[data-module]");
              if ($toggle.length) {
                if ($toggle.is(":checked")) {
                  $card.addClass("active");
                } else {
                  $card.removeClass("active");
                }
              }
            });

            setTimeout(function () {
              $status.html("");
            }, 3000);
          })
          .fail(function () {
            $status.html(
              '<span style="color: #d63638;">✗ Error saving some modules</span>',
            );
          })
          .always(function () {
            $btn
              .prop("disabled", false)
              .html(
                '<span class="dashicons dashicons-saved"></span> Save Module Settings',
              );
          });
      });

      // Hide Login Settings Save
      $("#save-hide-login-settings").on("click", function () {
        var settings = {
          enabled: $("#hide-login-enabled").is(":checked") ? 1 : 0,
          slug: $("#login-slug").val(),
          redirect: $("#hide-login-redirect").val(),
        };
        saveModuleSettings(
          "hide_login",
          settings,
          $(this),
          $("#hide-login-status"),
        );
      });

      // Captcha Settings Save
      $("#save-captcha-settings").on("click", function () {
        var settings = {
          enabled: $("#captcha-enabled").is(":checked") ? 1 : 0,
          provider: $("#captcha-provider").val(),
          nexifymy_type: $("#captcha-nexifymy-type").val(),
          difficulty: $("#captcha-difficulty").val(),
          site_key: $("#captcha-site-key").val(),
          secret_key: $("#captcha-secret-key").val(),
          enable_login: $("#captcha-enable-login").is(":checked") ? 1 : 0,
          enable_registration: $("#captcha-enable-registration").is(":checked")
            ? 1
            : 0,
          enable_reset: $("#captcha-enable-reset").is(":checked") ? 1 : 0,
          enable_comment: $("#captcha-enable-comment").is(":checked") ? 1 : 0,
        };
        saveModuleSettings("captcha", settings, $(this), $("#captcha-status"));
      });

      // Password Policy Settings Save
      $("#save-password-settings").on("click", function () {
        var settings = {
          min_length: $("#pass-min-length").val(),
          require_upper: $("#password-options input[name=require_upper]").is(
            ":checked",
          )
            ? 1
            : 0,
          require_lower: $("#password-options input[name=require_lower]").is(
            ":checked",
          )
            ? 1
            : 0,
          require_number: $("#password-options input[name=require_number]").is(
            ":checked",
          )
            ? 1
            : 0,
          require_special: $(
            "#password-options input[name=require_special]",
          ).is(":checked")
            ? 1
            : 0,
          block_common: $("#password-options input[name=block_common]").is(
            ":checked",
          )
            ? 1
            : 0,
          expiry_days: $("#pass-expiry").val(),
        };
        saveModuleSettings(
          "password",
          settings,
          $(this),
          $("#password-status"),
        );
      });

      // Firewall Settings Save
      $("#save-firewall-settings").on("click", function () {
        var settings = {
          enabled: $("#fw-enabled").is(":checked") ? 1 : 0,
          mode: $("#fw-mode").val(),
          sql_injection: $("#firewall-rules input[name=sql_injection]").is(
            ":checked",
          )
            ? 1
            : 0,
          xss_protection: $("#firewall-rules input[name=xss_protection]").is(
            ":checked",
          )
            ? 1
            : 0,
          file_inclusion: $("#firewall-rules input[name=file_inclusion]").is(
            ":checked",
          )
            ? 1
            : 0,
          bad_bots: $("#firewall-rules input[name=bad_bots]").is(":checked")
            ? 1
            : 0,
          directory_traversal: $(
            "#firewall-rules input[name=directory_traversal]",
          ).is(":checked")
            ? 1
            : 0,
          whitelist: $("#ip-whitelist").val(),
          blacklist: $("#ip-blacklist").val(),
        };
        saveModuleSettings(
          "firewall",
          settings,
          $(this),
          $("#firewall-status"),
        );
      });

      // Login Protection Settings Save
      $("#save-login-prot-settings").on("click", function () {
        var settings = {
          enabled: $("#login-prot-enabled").is(":checked") ? 1 : 0,
          max_attempts: $("#login-prot-attempts").val(),
          lockout_duration: $("#login-prot-duration").val(),
          ban_threshold: $("#login-prot-ban").val(),
        };
        saveModuleSettings(
          "login_protection",
          settings,
          $(this),
          $("#login-prot-status"),
        );
      });

      // Rate Limiter Settings Save
      $("#save-rate-settings").on("click", function () {
        var maxAttempts = $("#rate-login-attempts").length
          ? $("#rate-login-attempts").val() || 5
          : $("#rate-requests").val() || 5;
        var loginWindowMinutes = $("#rate-login-window").length
          ? $("#rate-login-window").val() || 15
          : 15;
        var lockoutDuration = $("#rate-login-lockout").length
          ? $("#rate-login-lockout").val() || 1800
          : $("#rate-duration").val() || 900;
        var whitelistValue = $("#rate-whitelist").val() || "";

        var settings = {
          enabled: $("#rate-enabled").is(":checked") ? 1 : 0,
          max_attempts: maxAttempts,
          max_login_attempts: maxAttempts,
          login_window: loginWindowMinutes,
          attempt_window_minutes: loginWindowMinutes,
          attempt_window: (parseInt(loginWindowMinutes, 10) || 15) * 60,
          lockout_duration: lockoutDuration,
          login_lockout: lockoutDuration,
          block_duration: lockoutDuration,
          whitelist: whitelistValue,
          whitelist_ips: whitelistValue,
          requests_per_minute: $("#rate-requests").val() || 60,
          login_notify: $("#rate-login-notify").is(":checked") ? 1 : 0,
          api_requests_per_minute: $("#rate-api-requests").val() || 60,
          api_burst: $("#rate-api-burst").val() || 10,
          api_block: $("#rate-api-block").is(":checked") ? 1 : 0,
          page_requests_per_minute: $("#rate-page-requests").val() || 120,
          ajax_requests_per_minute: $("#rate-ajax-requests").val() || 200,
          search_requests_per_minute: $("#rate-search-requests").val() || 10,
          comment_requests_per_minute:
            $("#rate-comment-requests").val() || 5,
          trust_proxy: $("#rate-trust-proxy").is(":checked") ? 1 : 0,
          log_violations: $("#rate-log-violations").is(":checked") ? 1 : 0,
          response_code: $("#rate-response-code").val() || 429,
        };
        saveModuleSettings(
          "rate_limiter",
          settings,
          $(this),
          $("#rate-status"),
        );
      });

      // WAF Module Settings Save (from Modules page)
      $("#save-waf-module-settings").on("click", function () {
        var settings = {
          block_sqli: $("#waf-block-sqli").is(":checked") ? 1 : 0,
          block_xss: $("#waf-block-xss").is(":checked") ? 1 : 0,
          block_lfi: $("#waf-block-lfi").is(":checked") ? 1 : 0,
          block_bad_bots: $("#waf-block-bots").is(":checked") ? 1 : 0,
          log_only_mode: $("#waf-log-only").is(":checked") ? 1 : 0,
        };
        saveModuleSettings("waf", settings, $(this), $("#waf-module-status"));
      });

      // Scanner Module Settings Save (from Modules page)
      $("#save-scanner-module-settings").on("click", function () {
        var settings = {
          enabled: $("#scanner-module-enabled").is(":checked") ? 1 : 0,
          default_mode: $("#scanner-default-mode").val(),
          max_file_size_kb: $("#scanner-max-size").val(),
          excluded_paths: $("#scanner-excluded-paths").val(),
          excluded_extensions: $("#scanner-excluded-ext").val(),
          quarantine_mode:
            $("#scanner-quarantine-mode").val() ||
            ($("#scanner-auto-quarantine").is(":checked") ? "auto" : "manual"),
          schedule: $("#scanner-schedule").val(),
          background_enabled: $("#scanner-background-enabled").is(":checked")
            ? 1
            : 0,
        };
        saveModuleSettings(
          "scanner",
          settings,
          $(this),
          $("#scanner-module-status"),
        );
      });

      // Quarantine policy save button on scanner > quarantine tab
      $("#save-quarantine-policy").on("click", function () {
        var settings = {
          quarantine_mode: $("#scanner-quarantine-mode").val() || "manual",
        };
        saveModuleSettings(
          "scanner",
          settings,
          $(this),
          $("#quarantine-policy-status"),
        );
      });

      // =========================================================================
      // INTEGRATIONS PAGE HANDLERS
      // =========================================================================

      function getCheckedValues(selector) {
        var values = [];
        $(selector + ":checked").each(function () {
          values.push($(this).val());
        });
        return values;
      }

      function collectCustomWebhooks() {
        var webhooks = [];
        var parseError = "";

        $("#webhooks-list .nms-webhook-item").each(function () {
          var $item = $(this);
          var name = $.trim($item.find('input[name="webhook_name[]"]').val());
          var url = $.trim($item.find('input[name="webhook_url[]"]').val());
          var method =
            $item.find('select[name="webhook_method[]"]').val() || "POST";
          var headersRaw = $.trim(
            $item.find('textarea[name="webhook_headers[]"]').val() || "",
          );
          var headers = {};

          if (!url) {
            return;
          }

          if (headersRaw) {
            try {
              var parsedHeaders = JSON.parse(headersRaw);
              if (parsedHeaders && typeof parsedHeaders === "object") {
                headers = parsedHeaders;
              } else {
                parseError = "Webhook headers must be a valid JSON object.";
                return false;
              }
            } catch (e) {
              parseError = "Webhook headers must be valid JSON.";
              return false;
            }
          }

          var events = [];
          $item
            .find('input[type="checkbox"][name^="webhook_events_"]:checked')
            .each(function () {
              events.push($(this).val());
            });

          if (!events.length) {
            events = ["all"];
          }

          webhooks.push({
            name: name,
            url: url,
            method: method,
            headers: headers,
            events: events,
          });
        });

        if (parseError) {
          return { error: parseError, webhooks: [] };
        }

        return { error: "", webhooks: webhooks };
      }

      function buildIntegrationsPayload() {
        var webhookResult = collectCustomWebhooks();
        if (webhookResult.error) {
          return { error: webhookResult.error };
        }

        return {
          enabled: 1,
          slack_enabled: $("#slack-enabled").is(":checked") ? 1 : 0,
          slack_webhook_url: $("#slack-webhook").val() || "",
          slack_channel: $("#slack-channel").val() || "#security",
          slack_events: getCheckedValues('input[name="slack-events[]"]'),

          discord_enabled: $("#discord-enabled").is(":checked") ? 1 : 0,
          discord_webhook_url: $("#discord-webhook").val() || "",
          discord_events: getCheckedValues('input[name="discord-events[]"]'),

          teams_enabled: $("#teams-enabled").is(":checked") ? 1 : 0,
          teams_webhook_url: $("#teams-webhook").val() || "",
          teams_events: getCheckedValues('input[name="teams-events[]"]'),

          siem_enabled: $("#siem-enabled").is(":checked") ? 1 : 0,
          siem_type: $("#siem-type").val() || "splunk",
          siem_endpoint: $("#siem-endpoint").val() || "",
          siem_token: $("#siem-token").val() || "",
          siem_index: $("#siem-index").val() || "wordpress_security",
          siem_format: $("#siem-format").val() || "json",
          siem_ssl_verify: $("#siem-ssl-verify").is(":checked") ? 1 : 0,
          siem_events: getCheckedValues('input[name="siem-events[]"]'),

          jira_enabled: $("#jira-enabled").is(":checked") ? 1 : 0,
          jira_url: $("#jira-url").val() || "",
          jira_email: $("#jira-email").val() || "",
          jira_api_token: $("#jira-token").val() || "",
          jira_project_key: $("#jira-project").val() || "",
          jira_issue_type: $("#jira-issue-type").val() || "Bug",
          jira_priority: $("#jira-priority").val() || "High",
          jira_events: getCheckedValues('input[name="jira-events[]"]'),

          servicenow_enabled: $("#servicenow-enabled").is(":checked") ? 1 : 0,
          servicenow_instance: $("#servicenow-instance").val() || "",
          servicenow_username: $("#servicenow-username").val() || "",
          servicenow_password: $("#servicenow-password").val() || "",
          servicenow_table: $("#servicenow-table").val() || "incident",
          servicenow_impact: $("#servicenow-impact").val() || "2",
          servicenow_urgency: $("#servicenow-urgency").val() || "2",

          cicd_enabled: $("#cicd-enabled").is(":checked") ? 1 : 0,
          cicd_webhook_url: $("#cicd-webhook-url").val() || "",
          cicd_fail_on_malware: $("#cicd-fail-on-malware").is(":checked")
            ? 1
            : 0,
          cicd_fail_on_vulnerabilities: $("#cicd-fail-on-vuln").is(":checked")
            ? 1
            : 0,
          cicd_min_severity: $("#cicd-min-severity").val() || "high",

          custom_webhooks_enabled: $("#webhooks-enabled").is(":checked")
            ? 1
            : 0,
          custom_webhooks: webhookResult.webhooks,
        };
      }

      function saveIntegrations($btn, $status) {
        var payload = buildIntegrationsPayload();
        var originalText = $btn.text();

        if (payload.error) {
          $status.html(
            '<span style="color: var(--nms-danger);">' +
              payload.error +
              "</span>",
          );
          return;
        }

        $btn.prop("disabled", true).text("Saving...");
        $status.html('<span style="color: #666;">Saving...</span>');

        $.ajax({
          url: nexifymySecurity.ajaxUrl,
          type: "POST",
          dataType: "json",
          data: {
            action: "nexifymy_save_settings",
            settings: { integrations: payload },
            nonce: nexifymySecurity.nonce,
          },
          success: function (response) {
            $btn.prop("disabled", false).text(originalText);
            if (response.success) {
              $status.html(
                '<span style="color: var(--nms-success);">Saved!</span>',
              );
            } else {
              $status.html(
                '<span style="color: var(--nms-danger);">' +
                  (response.data || "Failed") +
                  "</span>",
              );
            }
          },
          error: function () {
            $btn.prop("disabled", false).text(originalText);
            $status.html(
              '<span style="color: var(--nms-danger);">Connection error</span>',
            );
          },
        });
      }

      function testIntegration(type, $btn, $status) {
        var originalText = $btn.text();
        $btn.prop("disabled", true).text("Testing...");
        $status.html('<span style="color: #666;">Testing...</span>');

        $.ajax({
          url: nexifymySecurity.ajaxUrl,
          type: "POST",
          dataType: "json",
          data: {
            action: "nexifymy_test_integration",
            type: type,
            nonce: nexifymySecurity.nonce,
          },
          success: function (response) {
            $btn.prop("disabled", false).text(originalText);
            if (response.success) {
              $status.html(
                '<span style="color: var(--nms-success);">' +
                  (response.data && response.data.message
                    ? response.data.message
                    : "Test successful") +
                  "</span>",
              );
            } else {
              $status.html(
                '<span style="color: var(--nms-danger);">' +
                  (response.data || "Test failed") +
                  "</span>",
              );
            }
          },
          error: function () {
            $btn.prop("disabled", false).text(originalText);
            $status.html(
              '<span style="color: var(--nms-danger);">Connection error</span>',
            );
          },
        });
      }

      $("#save-siem-settings").on("click", function () {
        saveIntegrations($(this), $("#siem-status"));
      });
      $("#save-jira-settings").on("click", function () {
        saveIntegrations($(this), $("#jira-status"));
      });
      $("#save-servicenow-settings").on("click", function () {
        saveIntegrations($(this), $("#servicenow-status"));
      });
      $("#save-slack-settings").on("click", function () {
        saveIntegrations($(this), $("#slack-status"));
      });
      $("#save-discord-settings").on("click", function () {
        saveIntegrations($(this), $("#discord-status"));
      });
      $("#save-teams-settings").on("click", function () {
        saveIntegrations($(this), $("#teams-status"));
      });
      $("#save-cicd-settings").on("click", function () {
        saveIntegrations($(this), $("#cicd-status"));
      });
      $("#save-webhooks-settings").on("click", function () {
        saveIntegrations($(this), $("#webhooks-status"));
      });

      $("#test-siem").on("click", function () {
        testIntegration("siem", $(this), $("#siem-status"));
      });
      $("#test-jira").on("click", function () {
        testIntegration("jira", $(this), $("#jira-status"));
      });
      $("#test-servicenow").on("click", function () {
        testIntegration("servicenow", $(this), $("#servicenow-status"));
      });
      $("#test-slack").on("click", function () {
        testIntegration("slack", $(this), $("#slack-status"));
      });
      $("#test-discord").on("click", function () {
        testIntegration("discord", $(this), $("#discord-status"));
      });
      $("#test-teams").on("click", function () {
        testIntegration("teams", $(this), $("#teams-status"));
      });

      $("#add-webhook").on("click", function () {
        var index = $("#webhooks-list .nms-webhook-item").length;
        var eventsName = "webhook_events_new_" + index + "[]";
        var html = "";
        html +=
          '<div class="nms-webhook-item nms-card" style="margin-top: 20px; background: #f5f5f5;">';
        html +=
          '<div class="nms-card-header" style="display: flex; justify-content: space-between;">';
        html += "<h4>Webhook " + (index + 1) + "</h4>";
        html +=
          '<button type="button" class="button remove-webhook">Remove</button>';
        html += "</div>";
        html += '<div class="nms-card-body"><table class="form-table">';
        html +=
          '<tr><th>Name</th><td><input type="text" name="webhook_name[]" class="regular-text"></td></tr>';
        html +=
          '<tr><th>URL</th><td><input type="url" name="webhook_url[]" class="large-text"></td></tr>';
        html +=
          '<tr><th>Method</th><td><select name="webhook_method[]" class="regular-text"><option value="POST">POST</option><option value="PUT">PUT</option><option value="PATCH">PATCH</option></select></td></tr>';
        html +=
          '<tr><th>Headers</th><td><textarea name="webhook_headers[]" rows="3" class="large-text code">{}</textarea></td></tr>';
        html += "<tr><th>Events</th><td>";
        html +=
          '<label><input type="checkbox" name="' +
          eventsName +
          '" value="all" checked> All Events</label><br>';
        html +=
          '<label><input type="checkbox" name="' +
          eventsName +
          '" value="threat_detected"> Threat Detected</label><br>';
        html +=
          '<label><input type="checkbox" name="' +
          eventsName +
          '" value="malware_found"> Malware Found</label>';
        html += "</td></tr>";
        html += "</table></div></div>";
        $("#webhooks-list").append(html);
      });

      $(document).on("click", ".remove-webhook", function () {
        $(this).closest(".nms-webhook-item").remove();
      });

      // =========================================================================
      // QUARANTINE PAGE HANDLERS
      // =========================================================================

      // Load quarantine files on page load
      if ($("#quarantine-table").length) {
        NexifymySecurity.loadQuarantineFiles();
      }

      // Refresh quarantine list
      $("#refresh-quarantine").on("click", function () {
        NexifymySecurity.loadQuarantineFiles();
        NexifymySecurity.loadDeletedQuarantineFiles();
      });

      // Modal cancel button
      $("#modal-cancel").on("click", function () {
        NexifymySecurity.closeModal();
      });

      // Close modal on overlay click
      $("#nms-confirm-modal").on("click", function (e) {
        if (e.target === this) {
          NexifymySecurity.closeModal();
        }
      });

      // Delegated handlers for quarantine actions
      $(document).on("click", ".quarantine-restore", function () {
        var filename = $(this).data("filename");
        var path = $(this).data("path");
        NexifymySecurity.showModal(
          "warning",
          "Restore File",
          "Are you sure you want to restore this file to its original location?",
          path,
          function () {
            NexifymySecurity.restoreFile(filename);
          },
        );
      });

      $(document).on("click", ".quarantine-delete", function () {
        var filename = $(this).data("filename");
        var path = $(this).data("path");
        NexifymySecurity.showModal(
          "warning",
          "Move To Deleted Files",
          "The file will be moved to recoverable deleted storage. You can still restore it later.",
          path,
          function () {
            NexifymySecurity.deleteQuarantined(filename);
          },
        );
      });

      // =========================================================================
      // TAB NAVIGATION HANDLERS
      // =========================================================================

      // Handle tab clicks
      $(document).on("click", ".nms-page-tab", function (e) {
        e.preventDefault();
        var $tab = $(this);
        var tabId = $tab.data("tab");
        var $container = $tab.closest(".nms-tabbed-page");

        // Update active tab
        $container.find(".nms-page-tab").removeClass("active");
        $tab.addClass("active");

        // Show corresponding panel - hide all then show active
        $container
          .find(".nms-tab-panel")
          .removeClass("active")
          .css("display", "none");
        $container
          .find("#tab-" + tabId)
          .addClass("active")
          .css("display", "block");

        // Update URL hash
        if (history.pushState) {
          history.pushState(null, null, "#" + tabId);
        }
      });

      // Load tab from URL hash on page load
      if (window.location.hash && $(".nms-page-tabs").length) {
        var hash = window.location.hash.substring(1);
        var $targetTab = $('.nms-page-tab[data-tab="' + hash + '"]');
        if ($targetTab.length) {
          $targetTab.trigger("click");
        }
      }
    },

    loadDashboardData: function () {
      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        data: {
          action: "nexifymy_get_dashboard_data",
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          if (response.success) {
            NexifymySecurity.updateStats(response.data.stats);
          }
        },
      });
    },

    updateStats: function (stats) {
      if (!stats) return;

      $("#stat-total").text(stats.total_events || 0);
      $("#stat-critical").text(
        (stats.by_severity && stats.by_severity.critical) || 0,
      );
      $("#stat-warning").text(
        (stats.by_severity && stats.by_severity.warning) || 0,
      );
      $("#stat-info").text((stats.by_severity && stats.by_severity.info) || 0);
    },

    // =========================================================================
    // QUARANTINE UTILITY METHODS
    // =========================================================================

    pendingConfirmCallback: null,

    loadQuarantineFiles: function () {
      var $tbody = $("#quarantine-tbody");
      $tbody.html('<tr><td colspan="5">Loading quarantined files...</td></tr>');

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        data: {
          action: "nexifymy_get_quarantined_files",
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          if (response.success) {
            var files = response.data.files;
            if (files.length === 0) {
              $tbody.html(
                '<tr><td colspan="5" style="text-align: center; color: #64748b;">No files in quarantine. Your site is clean!</td></tr>',
              );
              NexifymySecurity.loadDeletedQuarantineFiles();
              return;
            }

            var html = "";
            files.forEach(function (file) {
              html += "<tr>";
              html +=
                '<td><code style="font-size: 12px;">' +
                file.original_path +
                "</code></td>";
              html += "<td>" + file.size_formatted + "</td>";
              html += "<td>" + (file.reason || "Threat detected") + "</td>";
              html += "<td>" + file.quarantined_at + "</td>";
              html += '<td class="quarantine-actions">';
              html +=
                '<button class="nms-btn nms-btn-restore quarantine-restore" data-filename="' +
                file.quarantine_name +
                '" data-path="' +
                file.original_path +
                '">Restore</button>';
              html +=
                '<button class="nms-btn nms-btn-delete quarantine-delete" data-filename="' +
                file.quarantine_name +
                '" data-path="' +
                file.original_path +
                '">Delete</button>';
              html += "</td>";
              html += "</tr>";
            });
            $tbody.html(html);
          } else {
            $tbody.html(
              '<tr><td colspan="5" style="color: #dc2626;">Error loading files: ' +
                response.data +
                "</td></tr>",
            );
          }
          NexifymySecurity.loadDeletedQuarantineFiles();
        },
        error: function () {
          $tbody.html(
            '<tr><td colspan="5" style="color: #dc2626;">Failed to load quarantine files.</td></tr>',
          );
        },
      });
    },

    showModal: function (type, title, message, filePath, onConfirm) {
      var $modal = $("#nms-confirm-modal");
      var $header = $("#modal-header");
      var $confirmBtn = $("#modal-confirm");

      // Set modal type (danger or warning)
      $header.removeClass("danger warning").addClass(type);
      $confirmBtn
        .removeClass("nms-modal-btn-danger nms-modal-btn-warning")
        .addClass("nms-modal-btn-" + type);

      // Set content
      $("#modal-title").text(title);
      $("#modal-message").text(message);
      $("#modal-file-path").text(filePath);

      // Store callback
      this.pendingConfirmCallback = onConfirm;

      // Show modal
      $modal.addClass("active");

      // Bind confirm button
      $("#modal-confirm")
        .off("click")
        .on("click", function () {
          if (NexifymySecurity.pendingConfirmCallback) {
            NexifymySecurity.pendingConfirmCallback();
          }
          NexifymySecurity.closeModal();
        });
    },

    closeModal: function () {
      $("#nms-confirm-modal").removeClass("active");
      this.pendingConfirmCallback = null;
    },

    restoreFile: function (filename) {
      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        data: {
          action: "nexifymy_restore_file",
          filename: filename,
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          if (response.success) {
            NexifymySecurity.showNotice(
              "success",
              "File restored successfully!",
            );
            NexifymySecurity.loadQuarantineFiles();
          } else {
            NexifymySecurity.showNotice(
              "error",
              "Restore failed: " + response.data,
            );
          }
        },
        error: function () {
          NexifymySecurity.showNotice("error", "Network error during restore.");
        },
      });
    },

    deleteQuarantined: function (filename) {
      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        data: {
          action: "nexifymy_delete_quarantined",
          filename: filename,
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          if (response.success) {
            NexifymySecurity.showNotice("success", "File permanently deleted.");
            NexifymySecurity.loadQuarantineFiles();
          } else {
            NexifymySecurity.showNotice(
              "error",
              "Delete failed: " + response.data,
            );
          }
        },
        error: function () {
          NexifymySecurity.showNotice("error", "Network error during delete.");
        },
      });
    },

    showNotice: function (type, message) {
      var bgColor = type === "success" ? "#059669" : "#dc2626";
      var $notice = $(
        '<div class="nms-toast" style="position: fixed; top: 50px; right: 20px; background: ' +
          bgColor +
          '; color: white; padding: 12px 20px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.15); z-index: 100001; animation: nmsModalSlideIn 0.2s ease-out;">' +
          message +
          "</div>",
      );
      $("body").append($notice);
      setTimeout(function () {
        $notice.fadeOut(300, function () {
          $(this).remove();
        });
      }, 3000);
    },

    runScan: function (mode) {
      var $progress = $("#scan-progress, #scanner-progress");
      var $results = $("#scan-results, #scanner-results");
      var $progressFill = $progress.find(".progress-fill, .nms-progress-fill");
      var $status = $progress.find(".scan-status, #scan-status-text");
      var $percent = $progress.find(".nms-progress-percent");
      var $currentFile = $progress.find("#scan-current-file");
      var $threatCounts = $progress.find("#scan-threat-counts");

      // Store requested mode and last progress for fallback
      var requestedMode = mode;
      var lastProgress = null;

      $progress.show();
      $results.hide();
      $progressFill.css("width", "5%");
      $status.text("Initializing " + mode + " scan...");
      if ($percent.length) $percent.text("5%");

      // Start the scan
      var scanComplete = false;

      // Function to fetch and display saved results (fallback)
      var fetchSavedResults = function () {
        $.ajax({
          url: nexifymySecurity.ajaxUrl,
          type: "POST",
          dataType: "json",
          data: {
            action: "nexifymy_scan_results",
            nonce: nexifymySecurity.nonce,
          },
          success: function (response) {
            if (response.success && response.data) {
              NexifymySecurity.displayScanResults(response.data);
            } else if (lastProgress && lastProgress.files_scanned > 0) {
              // Use last progress data if we have it
              NexifymySecurity.displayScanResults({
                mode: requestedMode,
                mode_name: lastProgress.mode || requestedMode,
                files_scanned: lastProgress.files_scanned,
                threats_found: lastProgress.threats_found || 0,
                threats: [],
                threat_counts: {
                  critical: lastProgress.critical || 0,
                  high: lastProgress.high || 0,
                  medium: lastProgress.medium || 0,
                  low: lastProgress.low || 0,
                },
              });
            }
          },
        });
      };

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        dataType: "json",
        timeout: 3600000, // 1 hour timeout for deep scans
        data: {
          action: "nexifymy_scan",
          mode: mode,
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          if (
            !response ||
            typeof response !== "object" ||
            !("success" in response)
          ) {
            scanComplete = true;
            $progress.hide();
            $results.show();
            // Try to fetch saved results instead
            fetchSavedResults();
            return;
          }

          scanComplete = true;
          $progressFill.css("width", "100%");
          $status.text("Scan complete!");
          if ($percent.length) $percent.text("100%");

          setTimeout(function () {
            $progress.hide();
            $results.show();

            if (response.success) {
              var data = response.data;

              // Verify we got results for the mode we requested
              // If mode mismatch or suspiciously low results, fetch saved results
              if (data && data.mode && data.mode !== requestedMode) {
                console.warn(
                  "Mode mismatch! Expected:",
                  requestedMode,
                  "Got:",
                  data.mode,
                );
                fetchSavedResults();
                return;
              }

              // If we tracked progress showing more data than response, use saved results
              if (
                lastProgress &&
                lastProgress.files_scanned > (data.files_scanned || 0) * 2
              ) {
                console.warn(
                  "Response has fewer files than progress showed, fetching saved results",
                );
                fetchSavedResults();
                return;
              }

              NexifymySecurity.displayScanResults(data);
            } else {
              // Extract error message properly
              var errorMsg = response.data || "Unknown error occurred";
              if (typeof errorMsg === "object" && errorMsg.message) {
                errorMsg = errorMsg.message;
              }
              console.error("Scanner error:", errorMsg);
              $("#results-content, #scan-results").html(
                '<p class="error"><strong>Scan Error:</strong> ' +
                  errorMsg +
                  "</p>",
              );
            }
          }, 500);
        },
        error: function (jqXHR, textStatus, errorThrown) {
          scanComplete = true;
          $progress.hide();
          $results.show();

          console.error(
            "Scanner AJAX error:",
            textStatus,
            errorThrown,
            jqXHR.responseText,
          );

          // If we had progress, try to get saved results
          if (lastProgress && lastProgress.files_scanned > 0) {
            fetchSavedResults();
            return;
          }

          var raw =
            jqXHR && typeof jqXHR.responseText === "string"
              ? jqXHR.responseText.trim()
              : "";
          var msg;
          if (raw === "-1") {
            msg =
              "Security check failed. Please refresh the page and try again.";
          } else if (raw === "0") {
            msg =
              "Scanner handler not available. Please check if the plugin is properly loaded.";
          } else if (textStatus === "timeout") {
            msg =
              "Scan timed out. The scan may have completed - try refreshing the page.";
          } else if (raw) {
            // Try to parse JSON error
            try {
              var parsed = JSON.parse(raw);
              msg = parsed.data || raw;
            } catch (e) {
              msg = raw.substring(0, 200);
            }
          } else {
            msg = "Network error: " + (errorThrown || textStatus);
          }
          $results.html(
            '<p class="error"><strong>Scan Failed:</strong> ' + msg + "</p>",
          );
        },
      });

      // Poll for real progress updates
      var progressPoll = setInterval(function () {
        if (scanComplete) {
          clearInterval(progressPoll);
          return;
        }

        $.ajax({
          url: nexifymySecurity.ajaxUrl,
          type: "POST",
          dataType: "json",
          data: {
            action: "nexifymy_scan_progress",
            nonce: nexifymySecurity.nonce,
          },
          success: function (response) {
            if (response.success && response.data) {
              var data = response.data;
              lastProgress = data; // Store for fallback

              $progressFill.css("width", data.percent + "%");
              $status.text(data.status || "Scanning...");
              if ($percent.length) $percent.text(data.percent + "%");

              // Update current file display
              if ($currentFile.length && data.current_file) {
                $currentFile.text(data.current_file);
              }

              // Update threat counts
              if ($threatCounts.length && data.threats_found > 0) {
                var countsHtml =
                  '<span class="critical">' +
                  data.critical +
                  " Critical</span> ";
                countsHtml +=
                  '<span class="high">' + data.high + " High</span> ";
                countsHtml +=
                  '<span class="medium">' + data.medium + " Medium</span> ";
                countsHtml += '<span class="low">' + data.low + " Low</span>";
                $threatCounts.html(countsHtml);
              }

              // Update files scanned count
              var $filesCount = $progress.find("#scan-files-count");
              if ($filesCount.length) {
                $filesCount.text(
                  data.files_scanned + " / " + data.total_files + " files",
                );
              }
            }
          },
          error: function () {
            clearInterval(progressPoll);
          },
        });
      }, 1500); // Poll every 1.5 seconds
    },

    // Store scan results globally for filtering
    scanResultsData: null,

    displayScanResults: function (data) {
      // Store data for filtering
      this.scanResultsData = data;

      var html = '<div class="scan-results-summary">';
      html +=
        "<p><strong>Mode:</strong> " +
        (data.mode_name || data.mode || "Unknown") +
        "</p>";
      html +=
        "<p><strong>Files Scanned:</strong> " +
        (data.files_scanned || 0) +
        "</p>";
      html +=
        '<p><strong>Threats Found:</strong> <span class="' +
        (data.threats_found > 0 ? "threat-count" : "clean-count") +
        '">' +
        (data.threats_found || 0) +
        "</span></p>";
      html += "</div>";

      if (data.threats && data.threats.length > 0) {
        // Collect unique severities and categories for filters
        var severities = {};
        var categories = {};
        data.threats.forEach(function (threat) {
          if (threat.threats) {
            threat.threats.forEach(function (t) {
              severities[t.severity || "unknown"] = true;
              categories[t.category || "malware"] = true;
            });
          }
        });

        // Build filter bar
        html +=
          '<div class="nms-scan-filters" style="margin: 15px 0; padding: 15px; background: #f8f9fa; border-radius: 6px; display: flex; gap: 15px; flex-wrap: wrap; align-items: center;">';
        html +=
          '<strong style="margin-right: 10px;"><i class="fa-solid fa-filter"></i> Filter Results:</strong>';

        // Severity filter
        html += '<select id="scan-filter-severity" style="min-width: 130px;">';
        html += '<option value="all">All Severities</option>';
        if (severities["critical"])
          html += '<option value="critical">Critical</option>';
        if (severities["high"]) html += '<option value="high">High</option>';
        if (severities["medium"])
          html += '<option value="medium">Medium</option>';
        if (severities["low"]) html += '<option value="low">Low</option>';
        html += "</select>";

        // Category filter
        html += '<select id="scan-filter-category" style="min-width: 150px;">';
        html += '<option value="all">All Categories</option>';
        var categoryLabels = {
          command_execution: "Command Execution",
          obfuscation: "Obfuscation",
          file_operation: "File Operation",
          file_inclusion: "File Inclusion",
          sql_injection: "SQL Injection",
          webshell: "Webshell",
          backdoor: "Backdoor",
          network: "Network",
          spam: "Spam/SEO",
          cryptominer: "Crypto Miner",
          injection: "Code Injection",
          redirect: "Redirect",
          reconnaissance: "Reconnaissance",
          evasion: "Evasion",
          vulnerability: "Vulnerability",
          community_malware: "Community Pattern",
          malware: "Malware",
        };
        Object.keys(categories)
          .sort()
          .forEach(function (cat) {
            html +=
              '<option value="' +
              cat +
              '">' +
              (categoryLabels[cat] || cat) +
              "</option>";
          });
        html += "</select>";

        // Search box
        html +=
          '<input type="text" id="scan-filter-search" placeholder="Search file or threat..." style="min-width: 200px; padding: 5px 10px;">';

        // Count display
        html +=
          '<span id="scan-filter-count" style="margin-left: auto; color: #666;"></span>';
        html += "</div>";

        // Results table
        html += '<table class="widefat striped" id="scan-results-table">';
        html +=
          "<thead><tr><th>File</th><th>Threat</th><th>Category</th><th>Classification</th><th>Severity</th><th>Confidence</th><th>Action</th></tr></thead>";
        html += "<tbody>";

        data.threats.forEach(function (threat) {
          if (threat.threats) {
            threat.threats.forEach(function (t) {
              var category = t.category || "malware";
              var confidence = t.confidence || threat.confidence || 70;
              var classification = t.classification || "SUSPICIOUS_CODE";
              var classificationLabel = {
                CONFIRMED_MALWARE: "Confirmed Malware",
                SUSPICIOUS_CODE: "Suspicious Code",
                SECURITY_VULNERABILITY: "Security Vulnerability",
                CODE_SMELL: "Code Smell",
              }[classification] || classification;
              html +=
                '<tr data-severity="' +
                (t.severity || "unknown") +
                '" data-category="' +
                category +
                '">';
              html +=
                '<td><code title="' +
                (threat.file || "") +
                '">' +
                NexifymySecurity.truncatePath(threat.file || "", 50) +
                "</code></td>";
              html +=
                "<td>" +
                (t.description || t.title || "Unknown threat") +
                "</td>";
              html +=
                '<td><span class="nms-badge nms-badge-info" style="font-size: 11px;">' +
                (categoryLabels[category] || category) +
                "</span></td>";
              html +=
                '<td><span class="nms-badge nms-badge-secondary" style="font-size: 11px;">' +
                classificationLabel +
                "</span></td>";
              html +=
                '<td><span class="severity-' +
                (t.severity || "medium") +
                '">' +
                (t.severity || "medium") +
                "</span></td>";
              html +=
                '<td><span class="confidence-' +
                (confidence >= 70
                  ? "high"
                  : confidence >= 50
                    ? "medium"
                    : "low") +
                '">' +
                confidence +
                "%</span></td>";
              html +=
                '<td><button class="button button-small delete-file" data-file="' +
                (threat.file || "") +
                '">Quarantine</button></td>';
              html += "</tr>";
            });
          }
        });

        html += "</tbody></table>";
      } else {
        html +=
          '<p class="all-good"><span class="dashicons dashicons-yes-alt"></span> No threats detected!</p>';
      }

      $("#results-content, #scan-results").html(html).show();

      // Bind filter events
      $("#scan-filter-severity, #scan-filter-category").on(
        "change",
        function () {
          NexifymySecurity.filterScanResults();
        },
      );
      $("#scan-filter-search").on("keyup", function () {
        NexifymySecurity.filterScanResults();
      });

      // Update initial count
      this.filterScanResults();

      // Bind delete button
      $(".delete-file").on("click", function () {
        var file = $(this).data("file");
        if (confirm("Quarantine this file?")) {
          NexifymySecurity.deleteFile(file, $(this));
        }
      });
    },

    truncatePath: function (path, maxLen) {
      if (!path || path.length <= maxLen) return path;
      var filename = path.split(/[/\\]/).pop();
      if (filename.length >= maxLen - 3) {
        return "..." + filename.substring(filename.length - maxLen + 3);
      }
      return "..." + path.substring(path.length - maxLen + 3);
    },

    filterScanResults: function () {
      var severity = $("#scan-filter-severity").val();
      var category = $("#scan-filter-category").val();
      var search = $("#scan-filter-search").val().toLowerCase();

      var visible = 0;
      var total = 0;

      $("#scan-results-table tbody tr").each(function () {
        var $row = $(this);
        var rowSeverity = $row.data("severity");
        var rowCategory = $row.data("category");
        var rowText = $row.text().toLowerCase();

        total++;
        var show = true;

        if (severity !== "all" && rowSeverity !== severity) {
          show = false;
        }
        if (category !== "all" && rowCategory !== category) {
          show = false;
        }
        if (search && rowText.indexOf(search) === -1) {
          show = false;
        }

        if (show) {
          $row.show();
          visible++;
        } else {
          $row.hide();
        }
      });

      $("#scan-filter-count").text(
        "Showing " + visible + " of " + total + " threats",
      );
    },

    deleteFile: function (filePath, $button) {
      $button.prop("disabled", true).text("Quarantining...");

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        data: {
          action: "nexifymy_delete_file",
          file_path: filePath,
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          if (response.success) {
            $button.closest("tr").fadeOut();
          } else {
            alert("Error: " + response.data);
            $button.prop("disabled", false).text("Quarantine");
          }
        },
      });
    },

    loadLogs: function () {
      var severity = $("#log-severity-filter").val();
      var $tbody = $("#logs-tbody");

      $tbody.html('<tr><td colspan="5">Loading logs...</td></tr>');

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        data: {
          action: "nexifymy_get_logs",
          severity: severity,
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          if (response.success && response.data.logs) {
            var html = "";

            if (response.data.logs.length === 0) {
              html = '<tr><td colspan="5">No logs found.</td></tr>';
            } else {
              response.data.logs.forEach(function (log) {
                html += "<tr>";
                html += "<td>" + log.created_at + "</td>";
                html += "<td>" + log.event_type + "</td>";
                html +=
                  '<td><span class="severity-' +
                  log.severity +
                  '">' +
                  log.severity +
                  "</span></td>";
                html += "<td>" + log.message + "</td>";
                html += "<td>" + (log.ip_address || "-") + "</td>";
                html += "</tr>";
              });
            }

            $tbody.html(html);
          }
        },
      });
    },

    loadNotifications: function () {
      var $tbody = $("#notifications-tbody");
      if (!$tbody.length) return;

      $tbody.html('<tr><td colspan="5">Loading alerts...</td></tr>');

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        data: {
          action: "nexifymy_get_notifications",
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          if (!response.success) {
            $tbody.html('<tr><td colspan="5">Failed to load alerts.</td></tr>');
            return;
          }

          var data = response.data || {};
          var alerts = data.alerts || [];
          var count = data.unread_count || 0;

          var $count = $("#notifications-unread-count");
          if ($count.length) {
            $count.text(count > 0 ? "(" + count + ")" : "");
          }

          if (alerts.length === 0) {
            $tbody.html('<tr><td colspan="5">No unread alerts.</td></tr>');
            return;
          }

          var html = "";
          alerts.forEach(function (alert) {
            html += "<tr>";
            html += "<td>" + (alert.created_at || "-") + "</td>";
            html += "<td>" + (alert.event_type || "-") + "</td>";
            html +=
              '<td><span class="severity-' +
              (alert.severity || "info") +
              '">' +
              (alert.severity || "info") +
              "</span></td>";
            html += "<td>" + (alert.message || "-") + "</td>";
            html += "<td>" + (alert.ip_address || "-") + "</td>";
            html += "</tr>";
          });

          $tbody.html(html);
        },
        error: function (jqXHR, textStatus, errorThrown) {
          console.error("Notifications AJAX error:", textStatus, errorThrown);
          $tbody.html(
            '<tr><td colspan="5">Error loading alerts. Please try refreshing the page.</td></tr>',
          );
        },
      });
    },

    markAllNotificationsRead: function () {
      var $button = $("#mark-all-notifications-read");
      if (!$button.length) return;

      $button.prop("disabled", true).text("Marking...");

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        data: {
          action: "nexifymy_mark_all_notifications_read",
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          $button.prop("disabled", false).text("Mark All as Read");
          if (response.success) {
            NexifymySecurity.loadNotifications();
          } else {
            alert("Error: " + response.data);
          }
        },
        error: function () {
          $button.prop("disabled", false).text("Mark All as Read");
          alert("Failed to mark alerts as read.");
        },
      });
    },

    loadBlockedIPs: function () {
      var $container = $("#blocked-ips-list");
      if (!$container.length) return;

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        data: {
          action: "nexifymy_get_blocked_ips",
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          if (response.success) {
            var html = "";

            if (response.data.blocked_count === 0) {
              html = "<p>No IPs are currently blocked.</p>";
            } else {
              html = '<table class="widefat striped">';
              html +=
                "<thead><tr><th>Locked At</th><th>Expires At</th><th>Remaining</th><th>Action</th></tr></thead>";
              html += "<tbody>";

              response.data.blocked_ips.forEach(function (ip) {
                var mins = Math.ceil(ip.remaining / 60);
                html += "<tr>";
                html += "<td>" + ip.locked_at + "</td>";
                html += "<td>" + ip.expires_at + "</td>";
                html += "<td>" + mins + " min(s)</td>";
                html +=
                  '<td><button class="button button-small unblock-ip" data-transient="' +
                  ip.transient +
                  '">Unblock</button></td>';
                html += "</tr>";
              });

              html += "</tbody></table>";
            }

            $container.html(html);

            // Bind unblock button
            $(".unblock-ip").on("click", function () {
              NexifymySecurity.unblockIP($(this).data("transient"), $(this));
            });
          }
        },
      });
    },

    unblockIP: function (transient, $button) {
      $button.prop("disabled", true).text("Unblocking...");

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        data: {
          action: "nexifymy_unblock_ip",
          transient: transient,
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          if (response.success) {
            $button.closest("tr").fadeOut();
          } else {
            alert("Error: " + response.data);
            $button.prop("disabled", false).text("Unblock");
          }
        },
      });
    },

    saveSchedule: function () {
      var frequency = $("#scan-schedule").val();

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        data: {
          action: "nexifymy_set_scan_schedule",
          frequency: frequency,
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          if (response.success) {
            alert(
              "Schedule saved! Next scan: " +
                (response.data.next_run || "Disabled"),
            );
          } else {
            alert("Error: " + response.data);
          }
        },
      });
    },

    // Quarantine Functions
    loadQuarantinedFiles: function () {
      var $tbody = $("#quarantine-tbody");
      if (!$tbody.length) return;

      $tbody.html('<tr><td colspan="5">Loading quarantined files...</td></tr>');

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        data: {
          action: "nexifymy_get_quarantined_files",
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          if (!response.success) return;

          var html = "";
          if (response.data.count === 0) {
            html =
              '<tr><td colspan="5">No files in quarantine. Your site is clean!</td></tr>';
          } else {
            response.data.files.forEach(function (file) {
              html += "<tr>";
              html += "<td><code>" + file.original_path + "</code></td>";
              html += "<td>" + file.size_formatted + "</td>";
              html += "<td>" + (file.reason || "-") + "</td>";
              html += "<td>" + file.quarantined_at + "</td>";
              html += '<td class="quarantine-actions">';
              html +=
                '<button class="button button-small restore-file" data-filename="' +
                file.quarantine_name +
                '">Restore</button> ';
              html +=
                '<button class="button button-small button-link-delete delete-quarantined" data-filename="' +
                file.quarantine_name +
                '">Delete</button>';
              html += "</td>";
              html += "</tr>";
            });
          }

          $tbody.html(html);

          $(".restore-file").on("click", function () {
            var filename = $(this).data("filename");
            if (confirm("Restore this file to its original location?")) {
              NexifymySecurity.restoreFile(filename, $(this));
            }
          });

          $(".delete-quarantined").on("click", function () {
            var filename = $(this).data("filename");
            if (
              confirm(
                "Move this file to recoverable deleted storage? You can restore it later.",
              )
            ) {
              NexifymySecurity.deleteQuarantined(filename, $(this));
            }
          });
        },
      });
    },

    loadDeletedQuarantineFiles: function () {
      var $tbody = $("#deleted-quarantine-tbody");
      if (!$tbody.length) return;

      $tbody.html('<tr><td colspan="4">Loading deleted files...</td></tr>');

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        data: {
          action: "nexifymy_get_deleted_quarantined_files",
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          if (!response.success) return;

          var html = "";
          if (response.data.count === 0) {
            html =
              '<tr><td colspan="4">No deleted files. Nothing pending permanent deletion.</td></tr>';
          } else {
            response.data.files.forEach(function (file) {
              html += "<tr>";
              html += "<td><code>" + (file.original_path || "-") + "</code></td>";
              html += "<td>" + (file.size_formatted || "-") + "</td>";
              html += "<td>" + (file.deleted_at || "-") + "</td>";
              html += '<td class="quarantine-actions">';
              html +=
                '<button class="button button-small restore-deleted-quarantined" data-deleted-name="' +
                (file.deleted_name || "") +
                '">Restore to Quarantine</button> ';
              html +=
                '<button class="button button-small button-link-delete permanent-delete-quarantined" data-deleted-name="' +
                (file.deleted_name || "") +
                '">Delete Permanently</button>';
              html += "</td>";
              html += "</tr>";
            });
          }

          $tbody.html(html);

          $(".restore-deleted-quarantined").on("click", function () {
            var deletedName = $(this).data("deleted-name");
            NexifymySecurity.restoreDeletedQuarantined(deletedName, $(this));
          });

          $(".permanent-delete-quarantined").on("click", function () {
            var deletedName = $(this).data("deleted-name");
            if (
              confirm(
                "Permanently delete this file? This cannot be undone.",
              )
            ) {
              NexifymySecurity.deleteQuarantinedPermanently(
                deletedName,
                $(this),
              );
            }
          });
        },
      });
    },

    restoreFile: function (filename, $button) {
      var hasButton = !!($button && $button.length);
      if (hasButton) $button.prop("disabled", true).text("Restoring...");

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        data: {
          action: "nexifymy_restore_file",
          filename: filename,
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          if (response.success) {
            if (hasButton) {
              $button.closest("tr").fadeOut(function () {
                $(this).remove();
              });
            }
            NexifymySecurity.showNotice("success", "File restored successfully.");
            NexifymySecurity.loadQuarantinedFiles();
          } else {
            NexifymySecurity.showNotice("error", "Restore failed: " + response.data);
            if (hasButton) $button.prop("disabled", false).text("Restore");
          }
        },
      });
    },

    deleteQuarantined: function (filename, $button) {
      var hasButton = !!($button && $button.length);
      if (hasButton) $button.prop("disabled", true).text("Deleting...");

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        data: {
          action: "nexifymy_delete_quarantined",
          filename: filename,
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          if (response.success) {
            if (hasButton) {
              $button.closest("tr").fadeOut(function () {
                $(this).remove();
              });
            }
            NexifymySecurity.showNotice(
              "success",
              "File moved to recoverable deleted storage.",
            );
            NexifymySecurity.loadQuarantinedFiles();
            NexifymySecurity.loadDeletedQuarantineFiles();
          } else {
            NexifymySecurity.showNotice("error", "Delete failed: " + response.data);
            if (hasButton) $button.prop("disabled", false).text("Delete");
          }
        },
      });
    },

    restoreDeletedQuarantined: function (deletedName, $button) {
      if ($button && $button.length) {
        $button.prop("disabled", true).text("Restoring...");
      }

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        data: {
          action: "nexifymy_restore_deleted_quarantined",
          deleted_name: deletedName,
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          if (response.success) {
            NexifymySecurity.showNotice(
              "success",
              "File restored to quarantine.",
            );
            NexifymySecurity.loadDeletedQuarantineFiles();
            NexifymySecurity.loadQuarantinedFiles();
          } else {
            NexifymySecurity.showNotice(
              "error",
              "Restore failed: " + response.data,
            );
            if ($button && $button.length) {
              $button.prop("disabled", false).text("Restore to Quarantine");
            }
          }
        },
      });
    },

    deleteQuarantinedPermanently: function (deletedName, $button) {
      if ($button && $button.length) {
        $button.prop("disabled", true).text("Deleting...");
      }

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        data: {
          action: "nexifymy_delete_quarantined_permanently",
          deleted_name: deletedName,
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          if (response.success) {
            NexifymySecurity.showNotice(
              "success",
              "File permanently deleted.",
            );
            NexifymySecurity.loadDeletedQuarantineFiles();
          } else {
            NexifymySecurity.showNotice(
              "error",
              "Permanent delete failed: " + response.data,
            );
            if ($button && $button.length) {
              $button.prop("disabled", false).text("Delete Permanently");
            }
          }
        },
      });
    },

    // Settings Functions
    saveAllSettings: function () {
      var $form = $("#nexifymy-settings-form");
      var $button = $("#save-settings");

      $button.prop("disabled", true).text("Saving...");

      // Serialize form data as nested object
      var formData = {};
      $form.find("input, select, textarea").each(function () {
        var name = $(this).attr("name");
        if (!name) return;

        var value;
        if ($(this).attr("type") === "checkbox") {
          value = $(this).is(":checked") ? "1" : "";
        } else {
          value = $(this).val();
        }

        // Parse nested names like modules[waf_enabled]
        var match = name.match(/^(\w+)\[(\w+)\](\[\])?$/);
        if (match) {
          if (!formData[match[1]]) formData[match[1]] = {};
          if (match[3]) {
            // Array field like alerts[alert_types][]
            if (!formData[match[1]][match[2]])
              formData[match[1]][match[2]] = [];
            if (value) formData[match[1]][match[2]].push(value);
          } else {
            formData[match[1]][match[2]] = value;
          }
        } else {
          formData[name] = value;
        }
      });

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        data: {
          action: "nexifymy_save_settings",
          settings: formData,
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          $button.prop("disabled", false).text("Save Settings");
          if (response.success) {
            alert("Settings saved successfully!");
          } else {
            alert("Error: " + response.data);
          }
        },
        error: function () {
          $button.prop("disabled", false).text("Save Settings");
          alert("Failed to save settings. Please try again.");
        },
      });

      // Also save alert settings if present
      if (formData.alerts) {
        $.ajax({
          url: nexifymySecurity.ajaxUrl,
          type: "POST",
          data: {
            action: "nexifymy_save_alert_settings",
            enabled: formData.alerts.enabled || "",
            recipient_email: formData.alerts.recipient_email || "",
            alert_types: formData.alerts.alert_types || [],
            throttle_minutes: formData.alerts.throttle_minutes || 60,
            daily_summary: formData.alerts.daily_summary || "",
            nonce: nexifymySecurity.nonce,
          },
        });
      }
    },

    resetSettings: function () {
      var $button = $("#reset-settings");
      $button.prop("disabled", true).text("Resetting...");

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        data: {
          action: "nexifymy_reset_settings",
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          if (response.success) {
            alert("Settings reset to defaults. Reloading page...");
            location.reload();
          } else {
            alert("Error: " + response.data);
            $button.prop("disabled", false).text("Reset to Defaults");
          }
        },
      });
    },

    // Database Functions
    loadDatabaseInfo: function () {
      var $container = $("#database-info");
      if (!$container.length) return;

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        data: {
          action: "nexifymy_get_database_info",
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          if (response.success) {
            var info = response.data.info;
            var html = '<table class="widefat">';
            html +=
              "<tr><th>Database Name</th><td>" +
              info.database_name +
              "</td></tr>";
            html += "<tr><th>Table Prefix</th><td>" + info.prefix;
            if (info.is_default_prefix) {
              html +=
                ' <span class="notice notice-warning" style="margin-left:10px;display:inline-block;padding:2px 8px;">Using default prefix - consider changing for security</span>';
            }
            html += "</td></tr>";
            html +=
              "<tr><th>Database Size</th><td>" +
              info.database_size_formatted +
              "</td></tr>";
            html +=
              "<tr><th>Table Count</th><td>" + info.table_count + "</td></tr>";
            html += "</table>";
            $container.html(html);
          }
        },
      });
    },

    loadBackups: function () {
      var $tbody = $("#backups-tbody");
      if (!$tbody.length) return;

      $tbody.html('<tr><td colspan="4">Loading backups...</td></tr>');

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        data: {
          action: "nexifymy_get_backups",
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          if (response.success) {
            var html = "";
            if (response.data.backups.length === 0) {
              html =
                '<tr><td colspan="4">No backups found. Create your first backup above.</td></tr>';
            } else {
              response.data.backups.forEach(function (backup) {
                html += "<tr>";
                html += "<td>" + backup.filename + "</td>";
                html += "<td>" + backup.size_formatted + "</td>";
                html += "<td>" + backup.created_at_formatted + "</td>";
                html += "<td>";
                html +=
                  '<a href="' +
                  nexifymySecurity.ajaxUrl +
                  "?action=nexifymy_download_backup&filename=" +
                  encodeURIComponent(backup.filename) +
                  "&nonce=" +
                  nexifymySecurity.nonce +
                  '" class="button button-small">Download</a> ';
                html +=
                  '<button class="button button-small button-link-delete delete-backup" data-filename="' +
                  backup.filename +
                  '">Delete</button>';
                html += "</td>";
                html += "</tr>";
              });
            }
            $tbody.html(html);

            // Bind delete button
            $(".delete-backup").on("click", function () {
              var filename = $(this).data("filename");
              if (confirm("Delete this backup?")) {
                NexifymySecurity.deleteBackup(filename, $(this));
              }
            });
          }
        },
      });
    },

    createBackup: function () {
      var $button = $("#create-backup");
      var $status = $("#backup-status");

      $button.prop("disabled", true);
      $status.text("Creating backup...").css("color", "#666");

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        data: {
          action: "nexifymy_create_backup",
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          $button.prop("disabled", false);
          if (response.success) {
            $status.text("Backup created successfully!").css("color", "green");
            NexifymySecurity.loadBackups();
          } else {
            $status.text("Error: " + response.data).css("color", "red");
          }
        },
        error: function () {
          $button.prop("disabled", false);
          $status.text("Failed to create backup").css("color", "red");
        },
      });
    },

    deleteBackup: function (filename, $button) {
      $button.prop("disabled", true).text("Deleting...");

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        data: {
          action: "nexifymy_delete_backup",
          filename: filename,
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          if (response.success) {
            $button.closest("tr").fadeOut();
          } else {
            alert("Error: " + response.data);
            $button.prop("disabled", false).text("Delete");
          }
        },
      });
    },

    loadOptimizationStats: function () {
      var $container = $("#optimization-stats");
      if (!$container.length) return;

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        data: {
          action: "nexifymy_get_optimization_stats",
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          if (response.success) {
            var stats = response.data.stats;
            var html = '<table class="widefat">';
            html +=
              "<tr><th>Transients</th><td>" + stats.transients + "</td></tr>";
            html +=
              "<tr><th>Post Revisions</th><td>" +
              stats.revisions +
              "</td></tr>";
            html +=
              "<tr><th>Spam Comments</th><td>" +
              stats.spam_comments +
              "</td></tr>";
            html +=
              "<tr><th>Trashed Comments</th><td>" +
              stats.trash_comments +
              "</td></tr>";
            html +=
              "<tr><th>Trashed Posts</th><td>" +
              stats.trash_posts +
              "</td></tr>";
            html +=
              "<tr><th>Orphaned Meta</th><td>" +
              stats.orphan_meta +
              "</td></tr>";
            html +=
              "<tr><th><strong>Total Cleanable Items</strong></th><td><strong>" +
              stats.total +
              "</strong></td></tr>";
            html += "</table>";
            $container.html(html);
          }
        },
      });
    },

    optimizeDatabase: function () {
      var $button = $("#optimize-database");
      var $status = $("#optimize-status");

      if (
        !confirm(
          "This will permanently delete transients, revisions, spam, and trashed items. Continue?",
        )
      ) {
        return;
      }

      $button.prop("disabled", true);
      $status.text("Optimizing...").css("color", "#666");

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        data: {
          action: "nexifymy_optimize_database",
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          $button.prop("disabled", false);
          if (response.success) {
            $status.text(response.data.message).css("color", "green");
            NexifymySecurity.loadOptimizationStats();
          } else {
            $status.text("Error: " + response.data).css("color", "red");
          }
        },
        error: function () {
          $button.prop("disabled", false);
          $status.text("Failed to optimize database").css("color", "red");
        },
      });
    },

    sendTestAlert: function () {
      var $button = $("#test-alert");
      var $result = $("#test-alert-result");

      $button.prop("disabled", true);
      $result.text("Sending...");

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        data: {
          action: "nexifymy_test_alert",
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          $button.prop("disabled", false);
          if (response.success) {
            $result.text("Success: " + response.data).css("color", "green");
          } else {
            $result.text("Error: " + response.data).css("color", "red");
          }
        },
        error: function () {
          $button.prop("disabled", false);
          $result.text("Error: Failed to send test alert").css("color", "red");
        },
      });
    },

    // Live Traffic Functions
    loadLiveTraffic: function () {
      var $tbody = $("#traffic-tbody");
      if (!$tbody.length) return;

      $tbody.html('<tr><td colspan="5">Loading traffic...</td></tr>');

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        dataType: "json",
        data: {
          action: "nexifymy_get_live_traffic",
          limit: 100,
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          if (!response || typeof response !== "object" || !response.success) {
            $tbody.html(
              '<tr><td colspan="5">Error: ' +
                ((response && response.data) || "Failed to load traffic") +
                "</td></tr>",
            );
            return;
          }

          var traffic = response.data.traffic || [];
          if (traffic.length === 0) {
            $tbody.html(
              '<tr><td colspan="5">No traffic entries yet.</td></tr>',
            );
            return;
          }

          var html = "";
          traffic.forEach(function (entry) {
            html += "<tr>";
            html += "<td>" + (entry.request_time_formatted || "") + "</td>";
            html += "<td><code>" + (entry.ip_address || "") + "</code></td>";
            html += "<td>" + (entry.request_method || "") + "</td>";
            html +=
              "<td><code>" +
              (entry.request_uri || "").toString().substring(0, 120) +
              "</code></td>";
            html += "<td>" + (entry.response_code || "") + "</td>";
            html += "</tr>";
          });
          $tbody.html(html);
        },
        error: function (jqXHR) {
          var raw =
            jqXHR && typeof jqXHR.responseText === "string"
              ? jqXHR.responseText.trim()
              : "";
          var msg =
            raw === "0"
              ? "Live Traffic module handler not available."
              : raw === "-1"
                ? "Security check failed. Refresh and try again."
                : "Failed to load traffic.";
          $tbody.html('<tr><td colspan="5">' + msg + "</td></tr>");
        },
      });
    },

    loadTrafficStats: function () {
      var $container = $("#traffic-stats");
      if (!$container.length) return;

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        dataType: "json",
        data: {
          action: "nexifymy_get_traffic_stats",
          hours: 24,
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          if (!response || typeof response !== "object" || !response.success) {
            $container.html(
              "<p>Error: " +
                ((response && response.data) || "Failed to load stats") +
                "</p>",
            );
            return;
          }

          var stats = response.data.stats || {};
          var html = '<table class="widefat">';
          html +=
            "<tr><th>Total Requests</th><td>" +
            (stats.total_requests || 0) +
            "</td></tr>";
          html +=
            "<tr><th>Unique IPs</th><td>" +
            (stats.unique_ips || 0) +
            "</td></tr>";
          html +=
            "<tr><th>Blocked</th><td>" +
            (stats.blocked_count || 0) +
            "</td></tr>";
          html += "</table>";
          $container.html(html);
        },
        error: function (jqXHR) {
          var raw =
            jqXHR && typeof jqXHR.responseText === "string"
              ? jqXHR.responseText.trim()
              : "";
          var msg =
            raw === "0"
              ? "Live Traffic stats handler not available."
              : raw === "-1"
                ? "Security check failed. Refresh and try again."
                : "Failed to load traffic stats.";
          $container.html("<p>" + msg + "</p>");
        },
      });
    },

    // Geo Blocking / Country list
    loadCountryList: function () {
      var $select = $("#geo-countries");
      if (!$select.length) return;

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        dataType: "json",
        data: {
          action: "nexifymy_get_country_list",
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          if (!response || typeof response !== "object" || !response.success) {
            $select.html('<option value="">Failed to load countries</option>');
            return;
          }

          var countries = response.data.countries || {};
          var options = "";
          Object.keys(countries).forEach(function (code) {
            options +=
              '<option value="' + code + '">' + countries[code] + "</option>";
          });
          $select.html(options);

          // After country list loads, load current geo settings so selections are applied.
          NexifymySecurity.loadGeoSettings();
        },
        error: function () {
          $select.html('<option value="">Failed to load countries</option>');
        },
      });
    },

    loadGeoSettings: function () {
      if (!$("#geo-enabled").length) return;

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        dataType: "json",
        data: {
          action: "nexifymy_get_geo_settings",
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          if (!response || typeof response !== "object" || !response.success) {
            return;
          }

          var settings = response.data.settings || {};
          $("#geo-enabled").prop("checked", !!settings.enabled);
          if (settings.mode) {
            $("#geo-mode").val(settings.mode);
          }
          if (typeof settings.block_message === "string") {
            $("#geo-message").val(settings.block_message);
          }

          var selected = settings.countries || [];
          $("#geo-countries")
            .find("option")
            .each(function () {
              $(this).prop("selected", selected.indexOf($(this).val()) !== -1);
            });
        },
      });
    },

    // Hardening status
    loadHardeningStatus: function () {
      var $table = $("#hardening-options");
      if (!$table.length) return;

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        dataType: "json",
        data: {
          action: "nexifymy_get_hardening_status",
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          if (!response || typeof response !== "object" || !response.success) {
            return;
          }

          var settings = response.data.settings || {};
          $table.find("input[type=checkbox][name]").each(function () {
            var name = $(this).attr("name");
            if (name in settings) {
              $(this).prop("checked", !!settings[name]);
            }
          });
        },
      });
    },

    // CDN status + settings
    loadCdnStatus: function () {
      var $status = $("#cdn-status");
      var hasForm =
        $("#cdn-enabled").length ||
        $("#cf-api-key").length ||
        $("#cf-zone-id").length;
      if (!$status.length && !hasForm) return;

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        dataType: "json",
        data: {
          action: "nexifymy_get_cdn_status",
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          if (!response || typeof response !== "object" || !response.success) {
            if ($status.length) {
              $status.html(
                "<p>Error: " +
                  ((response && response.data) || "Failed to load CDN status") +
                  "</p>",
              );
            }
            return;
          }

          var status = response.data.status || {};
          var settings = response.data.settings || {};

          if ($status.length) {
            var html = '<table class="widefat">';
            html +=
              "<tr><th>Enabled</th><td>" +
              (settings.enabled ? "Yes" : "No") +
              "</td></tr>";
            html +=
              "<tr><th>Detected Provider</th><td>" +
              (status.provider_name || "Unknown") +
              "</td></tr>";
            html +=
              "<tr><th>Provider Key</th><td>" +
              (status.detected_provider || settings.provider || "auto") +
              "</td></tr>";
            html +=
              "<tr><th>Cloudflare Configured</th><td>" +
              (status.cloudflare_configured ? "Yes" : "No") +
              "</td></tr>";
            html += "</table>";
            $status.html(html);
          }

          if ($("#cdn-enabled").length)
            $("#cdn-enabled").prop("checked", !!settings.enabled);
          if ($("#cdn-provider").length && settings.provider)
            $("#cdn-provider").val(settings.provider);
          if ($("#cdn-trust-proxy").length)
            $("#cdn-trust-proxy").prop(
              "checked",
              !!settings.trust_proxy_headers,
            );
          if (
            $("#cf-api-key").length &&
            typeof settings.cloudflare_api_key === "string"
          )
            $("#cf-api-key").val(settings.cloudflare_api_key);
          if (
            $("#cf-zone-id").length &&
            typeof settings.cloudflare_zone_id === "string"
          )
            $("#cf-zone-id").val(settings.cloudflare_zone_id);
        },
      });
    },

    saveCdnSettings: function ($button, $status) {
      if (!$button || !$button.length) return;

      $button.prop("disabled", true);
      if ($status && $status.length)
        $status.text("Saving...").css("color", "#666");

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        dataType: "json",
        data: {
          action: "nexifymy_save_cdn_settings",
          enabled: $("#cdn-enabled").is(":checked") ? 1 : 0,
          provider: $("#cdn-provider").length
            ? $("#cdn-provider").val()
            : "cloudflare",
          cloudflare_api_key: $("#cf-api-key").val(),
          cloudflare_zone_id: $("#cf-zone-id").val(),
          trust_proxy_headers: $("#cdn-trust-proxy").is(":checked") ? 1 : 0,
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          $button.prop("disabled", false);
          if (response && response.success) {
            if ($status && $status.length)
              $status
                .text(response.data.message || "Saved.")
                .css("color", "green");
            NexifymySecurity.loadCdnStatus();
          } else {
            if ($status && $status.length)
              $status
                .text(
                  "Error: " + ((response && response.data) || "Save failed"),
                )
                .css("color", "red");
          }
        },
        error: function () {
          $button.prop("disabled", false);
          if ($status && $status.length)
            $status.text("Failed to save CDN settings").css("color", "red");
        },
      });
    },

    testCdnConnection: function ($button, $status) {
      $button.prop("disabled", true);
      if ($status && $status.length)
        $status.text("Testing...").css("color", "#666");

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        dataType: "json",
        data: {
          action: "nexifymy_test_cdn_connection",
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          $button.prop("disabled", false);
          if (response && response.success) {
            if ($status && $status.length)
              $status
                .text(response.data.message || "Connection OK")
                .css("color", "green");
          } else {
            if ($status && $status.length)
              $status
                .text(
                  "Error: " + ((response && response.data) || "Test failed"),
                )
                .css("color", "red");
          }
        },
        error: function () {
          $button.prop("disabled", false);
          if ($status && $status.length)
            $status.text("Failed to test connection").css("color", "red");
        },
      });
    },

    purgeCdnCache: function ($button, $status) {
      $button.prop("disabled", true);
      if ($status && $status.length)
        $status.text("Purging...").css("color", "#666");

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        dataType: "json",
        data: {
          action: "nexifymy_purge_cdn_cache",
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          $button.prop("disabled", false);
          if (response && response.success) {
            if ($status && $status.length)
              $status
                .text(response.data.message || "Cache purged.")
                .css("color", "green");
          } else {
            if ($status && $status.length)
              $status
                .text(
                  "Error: " + ((response && response.data) || "Purge failed"),
                )
                .css("color", "red");
          }
        },
        error: function () {
          $button.prop("disabled", false);
          if ($status && $status.length)
            $status.text("Failed to purge cache").css("color", "red");
        },
      });
    },

    // Vulnerability Scanner
    loadVulnerabilityResults: function () {
      var $container = $("#vuln-results");
      if (!$container.length) return;

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        dataType: "json",
        data: {
          action: "nexifymy_get_vulnerability_results",
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          if (!response || typeof response !== "object" || !response.success) {
            return;
          }

          var results = response.data.results;
          if (!results) {
            return;
          }

          NexifymySecurity.renderVulnerabilityResults(results);
        },
      });
    },

    renderVulnerabilityResults: function (results) {
      var $container = $("#vuln-results");
      if (!$container.length || !results) return;

      var html =
        "<p><strong>Scan Time:</strong> " + (results.scan_time || "") + "</p>";
      html +=
        "<p><strong>Vulnerable Items:</strong> " +
        (results.vulnerable_count || 0) +
        " &nbsp; <strong>Outdated Items:</strong> " +
        (results.outdated_count || 0) +
        "</p>";

      $container.html(html);
    },

    runVulnerabilityScan: function ($button, $status) {
      if (!$button || !$button.length) return;

      $button.prop("disabled", true);
      if ($status && $status.length)
        $status.text("Running scan...").css("color", "#666");

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        dataType: "json",
        data: {
          action: "nexifymy_run_vulnerability_scan",
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          $button.prop("disabled", false);
          if (response && response.success) {
            if ($status && $status.length)
              $status.text("Scan complete.").css("color", "green");
            var results = response.data.results;
            NexifymySecurity.renderVulnerabilityResults(results);
          } else {
            if ($status && $status.length)
              $status
                .text(
                  "Error: " + ((response && response.data) || "Scan failed"),
                )
                .css("color", "red");
          }
        },
        error: function () {
          $button.prop("disabled", false);
          if ($status && $status.length)
            $status.text("Scan failed").css("color", "red");
        },
      });
    },

    verifyCoreFiles: function ($button) {
      if (!$button || !$button.length) return;

      var $resultsDiv = $("#verify-core-results");
      if (!$resultsDiv.length) {
        $button.after(
          '<div id="verify-core-results" style="margin-top: 15px;"></div>',
        );
        $resultsDiv = $("#verify-core-results");
      }

      $button.prop("disabled", true).text("Verifying...");
      $resultsDiv.html(
        '<p style="color: #666;">Checking core file integrity...</p>',
      );

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        dataType: "json",
        data: {
          action: "nexifymy_check_core_integrity",
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          $button.prop("disabled", false).text("Verify Core Files");
          if (response && response.success) {
            var data = response.data;
            var hasIssues = data.modified_count > 0 || data.missing_count > 0;
            var html =
              '<div class="nms-alert nms-alert-' +
              (hasIssues ? "warning" : "success") +
              '">';
            html += "<p><strong>Verification Complete:</strong></p>";
            html += '<ul style="margin: 10px 0; padding-left: 20px;">';
            html += "<li>Total files checked: " + data.total_files + "</li>";
            html += "<li>Verified files: " + data.verified + "</li>";
            html += "<li>Modified files: " + data.modified_count + "</li>";
            html += "<li>Missing files: " + data.missing_count + "</li>";
            html += "</ul>";
            if (hasIssues) {
              html +=
                '<p style="margin-top: 10px;"><em>Some core files have been modified or are missing. This could indicate a security issue or customization.</em></p>';
            } else {
              html +=
                '<p style="margin-top: 10px;"><em>All WordPress core files are intact and match official checksums.</em></p>';
            }
            html += "</div>";
            $resultsDiv.html(html);
          } else {
            $resultsDiv.html(
              '<div class="nms-alert nms-alert-error"><p>Error: ' +
                (response.data || "Verification failed") +
                "</p></div>",
            );
          }
        },
        error: function () {
          $button.prop("disabled", false).text("Verify Core Files");
          $resultsDiv.html(
            '<div class="nms-alert nms-alert-error"><p>Verification failed. Please try again.</p></div>',
          );
        },
      });
    },

    loadVulnerabilitySettings: function () {
      if (!$("#save-vuln-settings").length) return;

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        dataType: "json",
        data: {
          action: "nexifymy_get_settings",
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          if (!response || typeof response !== "object" || !response.success)
            return;

          var vulnerability = response.data.vulnerability || {};
          if ($("#vuln-enabled").length && "enabled" in vulnerability) {
            $("#vuln-enabled").prop("checked", !!vulnerability.enabled);
          }
          if (
            $("#wpscan-api-token").length &&
            typeof vulnerability.wpscan_api_token === "string"
          ) {
            $("#wpscan-api-token").val(vulnerability.wpscan_api_token);
          }
          if ($("#vuln-auto-scan").length && "auto_scan" in vulnerability) {
            $("#vuln-auto-scan").prop("checked", !!vulnerability.auto_scan);
          }
          if (
            $("#vuln-email-alerts").length &&
            "email_alerts" in vulnerability
          ) {
            $("#vuln-email-alerts").prop(
              "checked",
              !!vulnerability.email_alerts,
            );
          }
          if ($("#vuln-scan-schedule").length && vulnerability.scan_schedule) {
            $("#vuln-scan-schedule").val(vulnerability.scan_schedule);
          }
        },
      });
    },

    saveVulnerabilitySettings: function ($button, $status) {
      $button.prop("disabled", true);
      if ($status && $status.length)
        $status.text("Saving...").css("color", "#666");

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        dataType: "json",
        data: {
          action: "nexifymy_save_vuln_settings",
          enabled: $("#vuln-enabled").length
            ? $("#vuln-enabled").is(":checked")
              ? 1
              : 0
            : 1,
          wpscan_api_token: $("#wpscan-api-token").val(),
          auto_scan: $("#vuln-auto-scan").is(":checked") ? 1 : 0,
          scan_schedule: $("#vuln-scan-schedule").length
            ? $("#vuln-scan-schedule").val()
            : "weekly",
          email_alerts: $("#vuln-email-alerts").is(":checked") ? 1 : 0,
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          $button.prop("disabled", false);
          if (response && response.success) {
            if ($status && $status.length)
              $status.text("Saved.").css("color", "green");
          } else {
            if ($status && $status.length)
              $status
                .text(
                  "Error: " + ((response && response.data) || "Save failed"),
                )
                .css("color", "red");
          }
        },
        error: function () {
          $button.prop("disabled", false);
          if ($status && $status.length)
            $status.text("Save failed").css("color", "red");
        },
      });
    },

    // Password settings prefill (stored under `password` group in main settings option)
    loadPasswordSettings: function () {
      if (!$("#save-password-settings").length) return;

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        dataType: "json",
        data: {
          action: "nexifymy_get_settings",
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          if (!response || typeof response !== "object" || !response.success)
            return;

          var password = response.data.password || {};
          if ($("#pass-min-length").length && password.min_length) {
            $("#pass-min-length").val(password.min_length);
          }
          $("#password-options input[type=checkbox][name=require_upper]").prop(
            "checked",
            !!password.require_upper,
          );
          $("#password-options input[type=checkbox][name=require_lower]").prop(
            "checked",
            !!password.require_lower,
          );
          $("#password-options input[type=checkbox][name=require_number]").prop(
            "checked",
            !!password.require_number,
          );
          $(
            "#password-options input[type=checkbox][name=require_special]",
          ).prop("checked", !!password.require_special);
          $("#password-options input[type=checkbox][name=block_common]").prop(
            "checked",
            !!password.block_common,
          );
          if ($("#pass-expiry").length && "expiry_days" in password) {
            $("#pass-expiry").val(password.expiry_days);
          }
        },
      });
    },
    /**
     * Load Analytics Dashboard.
     */
    loadAnalyticsDashboard: function () {
      var $container = $("#analytics-dashboard");
      if ($container.length === 0) {
        return;
      }

      var self = this;
      var $loading = $("#analytics-loading");
      var $rangeSelect = $("#analytics-range");
      var $refreshBtn = $("#refresh-analytics");

      // Charts instances
      var charts = {};

      // Load data function
      function fetchAnalytics(days) {
        $container.css("opacity", "0.5");
        $loading.show();
        $refreshBtn.prop("disabled", true).find(".dashicons").addClass("spin");

        $.ajax({
          url: nexifymySecurity.ajaxUrl,
          type: "POST",
          dataType: "json",
          data: {
            action: "nexifymy_get_traffic_analytics",
            days: days,
            nonce: nexifymySecurity.nonce,
          },
          success: function (response) {
            $container.css("opacity", "1");
            $loading.hide();
            $refreshBtn
              .prop("disabled", false)
              .find(".dashicons")
              .removeClass("spin");

            if (response.success && response.data) {
              updateDashboard(response.data);
            }
          },
          error: function () {
            $container.css("opacity", "1");
            $loading.hide();
            $refreshBtn
              .prop("disabled", false)
              .find(".dashicons")
              .removeClass("spin");
            alert("Failed to load analytics data.");
          },
        });
      }

      // Update dashboard UI
      function updateDashboard(data) {
        // Update summary cards
        if (data.totals) {
          $("#stats-total-views").text(formatNumber(data.totals.total_views));
          $("#stats-unique-visitors").text(
            formatNumber(data.totals.unique_visitors),
          );
          $("#stats-blocked-requests").text(formatNumber(data.totals.blocked));
        }

        // Top Country
        if (data.geo_distribution && data.geo_distribution.length > 0) {
          $("#stats-top-country").text(data.geo_distribution[0].country_name);
        } else {
          $("#stats-top-country").text("-");
        }

        // 1. Traffic Overview Chart
        renderChart(
          "chart-traffic-overview",
          "line",
          {
            labels: data.chart_data.labels,
            datasets: [
              {
                label: "Page Views",
                data: data.chart_data.page_views,
                borderColor: "#4f46e5",
                backgroundColor: "rgba(79, 70, 229, 0.1)",
                borderWidth: 2,
                fill: true,
                tension: 0.4,
              },
              {
                label: "Unique Visitors",
                data: data.chart_data.unique_visitors,
                borderColor: "#06b6d4",
                backgroundColor: "rgba(6, 182, 212, 0.1)",
                borderWidth: 2,
                fill: true,
                tension: 0.4,
              },
            ],
          },
          {
            scales: {
              y: { beginAtZero: true, grid: { color: "#f1f5f9" } },
              x: { grid: { display: false } },
            },
            interaction: { mode: "index", intersect: false },
          },
        );

        // 2. Browser Distribution (Doughnut)
        var browserLabels = Object.keys(data.browser_distribution);
        var browserData = Object.values(data.browser_distribution);
        renderChart(
          "chart-browsers",
          "doughnut",
          {
            labels: browserLabels,
            datasets: [
              {
                data: browserData,
                backgroundColor: [
                  "#4f46e5",
                  "#ec4899",
                  "#f59e0b",
                  "#10b981",
                  "#ef4444",
                  "#cbd5e1",
                ],
                borderWidth: 0,
              },
            ],
          },
          { cutout: "60%", plugins: { legend: { position: "right" } } },
        );

        // 3. OS Distribution (Pie)
        var osLabels = Object.keys(data.os_distribution);
        var osData = Object.values(data.os_distribution);
        renderChart(
          "chart-os",
          "pie",
          {
            labels: osLabels,
            datasets: [
              {
                data: osData,
                backgroundColor: [
                  "#3b82f6",
                  "#8b5cf6",
                  "#6366f1",
                  "#14b8a6",
                  "#f97316",
                  "#cbd5e1",
                ],
                borderWidth: 0,
              },
            ],
          },
          { plugins: { legend: { position: "right" } } },
        );

        // 4. Device Distribution (Bar)
        var deviceLabels = Object.keys(data.device_distribution);
        var deviceData = Object.values(data.device_distribution);
        renderChart(
          "chart-devices",
          "bar",
          {
            labels: deviceLabels,
            datasets: [
              {
                label: "Devices",
                data: deviceData,
                backgroundColor: ["#6366f1", "#10b981", "#f59e0b", "#ef4444"],
                borderRadius: 4,
              },
            ],
          },
          {
            indexAxis: "y",
            plugins: { legend: { display: false } },
            scales: {
              x: { display: false, grid: { display: false } },
              y: { grid: { display: false } },
            },
          },
        );

        // 5. Geo Chart (Doughnut for now, effectively same data as map list)
        var geoLabels = data.geo_distribution
          .map(function (item) {
            return item.country_name;
          })
          .slice(0, 5);
        var geoData = data.geo_distribution
          .map(function (item) {
            return item.count;
          })
          .slice(0, 5);
        renderChart(
          "chart-geo",
          "doughnut",
          {
            labels: geoLabels,
            datasets: [
              {
                data: geoData,
                backgroundColor: [
                  "#0ea5e9",
                  "#22c55e",
                  "#eab308",
                  "#f43f5e",
                  "#a855f7",
                ],
                borderWidth: 0,
              },
            ],
          },
          { cutout: "50%", plugins: { legend: { position: "right" } } },
        );

        // Update Tables
        updateTable("#table-top-pages", data.top_pages, ["url", "count"]);
        updateTable("#table-top-referrers", data.top_referrers, [
          "referrer",
          "count",
        ]);
        updateGeoTable("#table-geo", data.geo_distribution);
      }

      // Helper: Render Chart
      function renderChart(id, type, data, options) {
        var ctx = document.getElementById(id);
        if (!ctx) return;

        if (charts[id]) {
          charts[id].destroy();
        }

        charts[id] = new Chart(ctx, {
          type: type,
          data: data,
          options: $.extend(
            true,
            {
              responsive: true,
              maintainAspectRatio: false,
              plugins: {
                legend: { labels: { usePointStyle: true, boxWidth: 8 } },
              },
            },
            options,
          ),
        });
      }

      // Helper: Update Table
      function updateTable(selector, data, columns) {
        var $body = $(selector).find("tbody");
        $body.empty();

        if (!data || data.length === 0) {
          $body.append(
            '<tr><td colspan="' +
              columns.length +
              '" style="text-align:center; color: #999;">No data available</td></tr>',
          );
          return;
        }

        data.forEach(function (row) {
          var html = "<tr>";
          columns.forEach(function (col, index) {
            var val = row[col];
            if (col === "url")
              val =
                '<a href="' +
                val +
                '" target="_blank">' +
                val.substring(0, 50) +
                (val.length > 50 ? "..." : "") +
                "</a>";
            var style =
              index === columns.length - 1
                ? "text-align: right; font-weight: 600;"
                : "";
            html +=
              '<td style="' +
              style +
              '">' +
              (index === columns.length - 1 ? formatNumber(val) : val) +
              "</td>";
          });
          html += "</tr>";
          $body.append(html);
        });
      }

      // Helper: Update Geo Table
      function updateGeoTable(selector, data) {
        var $body = $(selector).find("tbody");
        $body.empty();

        if (!data || data.length === 0) {
          $body.append(
            '<tr><td colspan="3" style="text-align:center; color: #999;">No data available</td></tr>',
          );
          return;
        }

        data.slice(0, 10).forEach(function (row) {
          var html = "<tr>";
          html += "<td>" + row.country_name + "</td>";
          html += "<td><code>" + row.country_code + "</code></td>";
          html +=
            '<td style="text-align: right; font-weight: 600;">' +
            formatNumber(row.count) +
            "</td>";
          html += "</tr>";
          $body.append(html);
        });
      }

      // Helper: Format Number
      function formatNumber(num) {
        return num.toString().replace(/(\d)(?=(\d{3})+(?!\d))/g, "$1,");
      }

      // Handle Range Change
      $rangeSelect.on("change", function () {
        fetchAnalytics($(this).val());
      });

      // Handle Refresh
      $refreshBtn.on("click", function () {
        fetchAnalytics($rangeSelect.val());
      });

      // Initial Load
      fetchAnalytics(30);
    },
  };

  $(document).ready(function () {
    NexifymySecurity.init();
  });
})(jQuery);
