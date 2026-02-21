/**
 * NexifyMy Security Admin JavaScript
 */

(function ($) {
  "use strict";

  var NexifymySecurity = {
    getString: function (key, fallback) {
      var strings =
        nexifymySecurity && typeof nexifymySecurity.strings === "object"
          ? nexifymySecurity.strings
          : {};
      var value = strings[key];
      if (typeof value === "string" && value.length > 0) {
        return value;
      }
      return fallback || key;
    },

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
      this.loadSecurityAnalyticsTab();
    },

    reloadAfterSettingsSave: function ($status, delayMs, message) {
      var delay = typeof delayMs === "number" ? delayMs : 800;
      var text =
        message ||
        this.getString("savedReloading", "Settings saved. Reloading...");

      if ($status && $status.length) {
        $status.html(
          '<span style="color: var(--nms-success);">' + text + "</span>",
        );
      }

      setTimeout(function () {
        window.location.reload();
      }, delay);
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

      $("#clear-logs").on("click", function () {
        if (!window.confirm("Clear all security logs? This cannot be undone.")) {
          return;
        }

        var $btn = $(this);
        $btn.prop("disabled", true).text("Clearing...");

        $.ajax({
          url: nexifymySecurity.ajaxUrl,
          type: "POST",
          dataType: "json",
          data: {
            action: "nexifymy_clear_logs",
            nonce: nexifymySecurity.nonce,
          },
          success: function (response) {
            $btn.prop("disabled", false).text("Clear Logs");
            if (response && response.success) {
              NexifymySecurity.loadLogs();
            } else {
              alert((response && response.data) || "Failed to clear logs.");
            }
          },
          error: function () {
            $btn.prop("disabled", false).text("Clear Logs");
            alert("Connection error while clearing logs.");
          },
        });
      });

      // Activity dashboard quick refresh
      $("#refresh-stats").on("click", function (e) {
        e.preventDefault();
        var $btn = $(this);
        $btn.prop("disabled", true);
        $btn.find(".dashicons").addClass("spin");
        window.location.reload();
      });

      $("#log-severity-filter").on("change", function () {
        NexifymySecurity.loadLogs();
      });

      // Settings
      $("#save-schedule").on("click", function () {
        NexifymySecurity.saveSchedule();
      });

      $("#optimize-db").on("click", function () {
        NexifymySecurity.optimizeDatabase();
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
          modules: {
            sandbox_enabled: $("#settings-sandbox-enabled").is(":checked")
              ? 1
              : 0,
            sandbox_console_enabled: $("#settings-sandbox-console-enabled").is(
              ":checked",
            )
              ? 1
              : 0,
          },
          sandbox_enabled: $("#settings-sandbox-enabled").is(":checked")
            ? 1
            : 0,
          sandbox_console_enabled: $("#settings-sandbox-console-enabled").is(
            ":checked",
          )
            ? 1
            : 0,
          sandbox_timeout: $("#settings-sandbox-timeout").val() || 5,
          sandbox_dynamic_analysis: $("#settings-sandbox-dynamic-analysis").is(
            ":checked",
          )
            ? 1
            : 0,
        };

        $btn
          .prop("disabled", true)
          .text(NexifymySecurity.getString("saving", "Saving..."));
        $status.html(
          '<span style="color: #666;">' +
            NexifymySecurity.getString("saving", "Saving...") +
            "</span>",
        );

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
              NexifymySecurity.reloadAfterSettingsSave(
                $status,
                900,
                NexifymySecurity.getString(
                  "savedReloading",
                  "Settings saved. Reloading...",
                ),
              );
            } else {
              $status.html(
                '<span style="color: var(--nms-danger);">' +
                  (response.data ||
                    NexifymySecurity.getString("failed", "Failed")) +
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
                  ? NexifymySecurity.getString(
                      "securityCheckFailed",
                      "Security check failed. Refresh and try again.",
                    )
                  : raw === "0"
                    ? NexifymySecurity.getString(
                        "settingsHandlerMissing",
                        "Settings handler not available.",
                      )
                    : NexifymySecurity.getString(
                        "connectionError",
                        "Connection error",
                      )) +
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
        if (
          confirm(
            NexifymySecurity.getString(
              "confirmResetSettings",
              "Reset all settings to defaults? This cannot be undone.",
            ),
          )
        ) {
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
        if (
          confirm(
            NexifymySecurity.getString(
              "confirmPurgeCdn",
              "Purge CDN cache now?",
            ),
          )
        ) {
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
      $("#mark-all-notifications-read, #mark-all-read").on("click", function () {
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

                // Reload after immediate settings save to ensure runtime config propagates.
                setTimeout(
                  function () {
                    window.location.reload();
                  },
                  isModulesHubToggle ? 350 : 700,
                );
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
              NexifymySecurity.reloadAfterSettingsSave(
                $status,
                700,
                "Saved! Reloading...",
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
            $btn.prop("disabled", false);
            $status.html(
              '<span style="color: var(--nms-danger);">Connection error</span>',
            );
          },
        });
      }

      function toBool($el, fallback) {
        if (!$el || !$el.length) {
          return fallback ? 1 : 0;
        }
        return $el.is(":checked") ? 1 : 0;
      }

      function toInt($el, fallback) {
        if (!$el || !$el.length) {
          return fallback;
        }
        var parsed = parseInt($el.val(), 10);
        return Number.isFinite(parsed) ? parsed : fallback;
      }

      function csvTextFromRows(rows) {
        if (!Array.isArray(rows)) {
          return "";
        }
        return rows
          .map(function (row) {
            var values = Array.isArray(row) ? row : [row];
            return values
              .map(function (value) {
                var text = value == null ? "" : String(value);
                text = text.replace(/"/g, '""');
                return '"' + text + '"';
              })
              .join(",");
          })
          .join("\n");
      }

      function downloadTextFile(filename, mimeType, content) {
        var blob = new Blob([content || ""], { type: mimeType });
        var url = URL.createObjectURL(blob);
        var link = document.createElement("a");
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        setTimeout(function () {
          URL.revokeObjectURL(url);
        }, 0);
      }

      // WAF page (Tools > Firewall tab)
      $("#save-waf-settings").on("click", function () {
        var settings = {
          enabled: toBool($("#waf-enabled"), true),
          level: $("#waf-level").length ? $("#waf-level").val() : "medium",
        };
        saveModuleSettings("waf", settings, $(this), $("#waf-status"));
      });

      // Login protection page (Tools > Login tab)
      $("#save-login-settings").on("click", function () {
        var settings = {
          enabled: toBool($("#login-enabled"), false),
          max_attempts: toInt($("#login-max-attempts"), 5),
          lockout_duration: toInt($("#login-lockout"), 30),
        };
        saveModuleSettings(
          "login_protection",
          settings,
          $(this),
          $("#login-status"),
        );
      });

      // Settings > Email Alerts
      $("#save-email-settings").on("click", function () {
        var $btn = $(this);
        var $status = $("#email-status");
        var emailSettings = {
          enabled: toBool($("#email-enabled"), 0),
          recipient: $("#email-recipient").val() || "",
          from_name: $("#email-from-name").val() || "",
          from_email: $("#email-from-email").val() || "",
          alert_threats: toBool($("#alert-threats"), 1),
          alert_lockouts: toBool($("#alert-lockouts"), 1),
          alert_waf: toBool($("#alert-waf"), 0),
          alert_login: toBool($("#alert-login"), 0),
          daily_summary: toBool($("#daily-summary"), 0),
          weekly_report: toBool($("#weekly-report"), 1),
          throttle_minutes: toInt($("#throttle-minutes"), 60),
        };

        // Save to central plugin settings.
        saveModuleSettings("email_alerts", emailSettings, $btn, $status);

        // Also sync legacy alerts module settings used by test-alert endpoint.
        var alertTypes = [];
        if (emailSettings.alert_threats) {
          alertTypes.push("threat_detected");
        }
        if (emailSettings.alert_lockouts) {
          alertTypes.push("ip_lockout");
        }
        if (emailSettings.alert_waf) {
          alertTypes.push("waf_block");
        }
        if (!alertTypes.length) {
          alertTypes = ["threat_detected"];
        }

        $.ajax({
          url: nexifymySecurity.ajaxUrl,
          type: "POST",
          dataType: "json",
          data: {
            action: "nexifymy_save_alert_settings",
            enabled: emailSettings.enabled,
            recipient_email: emailSettings.recipient,
            alert_types: alertTypes,
            throttle_minutes: emailSettings.throttle_minutes,
            daily_summary: emailSettings.daily_summary,
            daily_summary_time: "08:00",
            nonce: nexifymySecurity.nonce,
          },
        });
      });

      $("#test-email").on("click", function () {
        var $btn = $(this);
        var $status = $("#email-status");
        var originalText = $btn.text();

        $btn.prop("disabled", true).text("Sending...");
        $status.html('<span style="color: #666;">Sending test email...</span>');

        $.ajax({
          url: nexifymySecurity.ajaxUrl,
          type: "POST",
          dataType: "json",
          data: {
            action: "nexifymy_test_alert",
            nonce: nexifymySecurity.nonce,
          },
          success: function (response) {
            $btn.prop("disabled", false).text(originalText);
            if (response && response.success) {
              $status.html(
                '<span style="color: var(--nms-success);">' +
                  (response.data || "Test email sent.") +
                  "</span>",
              );
            } else {
              $status.html(
                '<span style="color: var(--nms-danger);">' +
                  ((response && response.data) || "Failed to send test email.") +
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
                (raw === "0"
                  ? "Email test handler is not available."
                  : "Connection error while sending test email.") +
                "</span>",
            );
          },
        });
      });

      // Settings > Import/Export
      $("#export-settings").on("click", function () {
        var $btn = $(this);
        var includeLogs = $("#export-logs").is(":checked");
        var includeIpLists = $("#export-ip-lists").is(":checked");
        var includeScanResults = $("#export-scan-results").is(":checked");

        $btn.prop("disabled", true);

        $.ajax({
          url: nexifymySecurity.ajaxUrl,
          type: "POST",
          dataType: "json",
          data: {
            action: "nexifymy_get_settings",
            nonce: nexifymySecurity.nonce,
          },
          success: function (response) {
            $btn.prop("disabled", false);
            if (!response || !response.success) {
              alert("Unable to export settings.");
              return;
            }

            var payload = {
              exported_at: new Date().toISOString(),
              plugin: "nexifymy-security",
              settings: response.data || {},
            };

            if (!includeIpLists && payload.settings) {
              if (payload.settings.ip) {
                delete payload.settings.ip.whitelist;
                delete payload.settings.ip.trusted_proxies;
              }
              if (payload.settings.waf) {
                delete payload.settings.waf.whitelist_ips;
                delete payload.settings.waf.blacklist_ips;
              }
              if (payload.settings.rate_limiter) {
                delete payload.settings.rate_limiter.whitelist;
                delete payload.settings.rate_limiter.whitelist_ips;
              }
            }

            var exportPromises = [];

            if (includeLogs) {
              exportPromises.push(
                $.ajax({
                  url: nexifymySecurity.ajaxUrl,
                  type: "POST",
                  dataType: "json",
                  data: {
                    action: "nexifymy_export_activity_log",
                    per_page: 10000,
                    nonce: nexifymySecurity.nonce,
                  },
                }).then(function (logResponse) {
                  if (logResponse && logResponse.success && logResponse.data) {
                    payload.activity_log_export = {
                      total: logResponse.data.total || 0,
                      csv_rows: logResponse.data.csv || [],
                    };
                  }
                }),
              );
            }

            if (includeScanResults) {
              exportPromises.push(
                $.ajax({
                  url: nexifymySecurity.ajaxUrl,
                  type: "POST",
                  dataType: "json",
                  data: {
                    action: "nexifymy_scan_results",
                    nonce: nexifymySecurity.nonce,
                  },
                }).then(function (scanResponse) {
                  if (scanResponse && scanResponse.success) {
                    payload.last_scan_results = scanResponse.data || {};
                  }
                }),
              );
            }

            $.when
              .apply($, exportPromises)
              .always(function () {
                var date = new Date();
                var filename =
                  "nexifymy-security-settings-" +
                  date.getFullYear() +
                  ("0" + (date.getMonth() + 1)).slice(-2) +
                  ("0" + date.getDate()).slice(-2) +
                  ".json";
                downloadTextFile(
                  filename,
                  "application/json;charset=utf-8",
                  JSON.stringify(payload, null, 2),
                );
              });
          },
          error: function () {
            $btn.prop("disabled", false);
            alert("Unable to export settings due to a connection error.");
          },
        });
      });

      $("#import-settings").on("click", function () {
        var $btn = $(this);
        var $status = $("#import-status");
        var fileInput = $("#import-file")[0];

        if (!fileInput || !fileInput.files || !fileInput.files[0]) {
          $status.html(
            '<span style="color: var(--nms-danger);">Please select a JSON file first.</span>',
          );
          return;
        }

        var file = fileInput.files[0];
        var reader = new FileReader();

        reader.onload = function (event) {
          var parsed;
          try {
            parsed = JSON.parse(event.target.result);
          } catch (err) {
            $status.html(
              '<span style="color: var(--nms-danger);">Invalid JSON file.</span>',
            );
            return;
          }

          var importedSettings =
            parsed && typeof parsed === "object" && parsed.settings
              ? parsed.settings
              : parsed;

          if (!importedSettings || typeof importedSettings !== "object") {
            $status.html(
              '<span style="color: var(--nms-danger);">No settings found in file.</span>',
            );
            return;
          }

          $btn.prop("disabled", true);
          $status.html('<span style="color: #666;">Importing settings...</span>');

          $.ajax({
            url: nexifymySecurity.ajaxUrl,
            type: "POST",
            dataType: "json",
            data: {
              action: "nexifymy_save_settings",
              settings: importedSettings,
              nonce: nexifymySecurity.nonce,
            },
            success: function (response) {
              if (!response || !response.success) {
                $btn.prop("disabled", false);
                $status.html(
                  '<span style="color: var(--nms-danger);">' +
                    ((response && response.data) || "Failed to import settings.") +
                    "</span>",
                );
                return;
              }

              // Persist groups that are managed via module settings endpoint.
              var moduleImports = [];
              ["advanced", "email_alerts", "activity_log", "password"].forEach(
                function (groupKey) {
                  if (
                    importedSettings[groupKey] &&
                    typeof importedSettings[groupKey] === "object"
                  ) {
                    moduleImports.push(
                      $.ajax({
                        url: nexifymySecurity.ajaxUrl,
                        type: "POST",
                        dataType: "json",
                        data: {
                          action: "nexifymy_save_module_settings",
                          module: groupKey,
                          settings: importedSettings[groupKey],
                          nonce: nexifymySecurity.nonce,
                        },
                      }),
                    );
                  }
                },
              );

              $.when
                .apply($, moduleImports)
                .always(function () {
                  NexifymySecurity.reloadAfterSettingsSave(
                    $status,
                    900,
                    "Settings imported. Reloading...",
                  );
                });
            },
            error: function () {
              $btn.prop("disabled", false);
              $status.html(
                '<span style="color: var(--nms-danger);">Connection error while importing.</span>',
              );
            },
          });
        };

        reader.onerror = function () {
          $status.html(
            '<span style="color: var(--nms-danger);">Unable to read the selected file.</span>',
          );
        };

        reader.readAsText(file);
      });

      // Settings > Advanced
      $("#save-advanced-settings").on("click", function () {
        var settings = {
          disable_xmlrpc: toBool($("#disable-xmlrpc"), 1),
          disable_rest_users: toBool($("#disable-rest-users"), 1),
          hide_wp_version: toBool($("#hide-wp-version"), 1),
          disable_file_editor: toBool($("#disable-file-editor"), 1),
          block_author_scans: toBool($("#block-author-scans"), 1),
          block_bad_requests: toBool($("#block-bad-requests"), 1),
          block_empty_ua: toBool($("#block-empty-ua"), 0),
          performance_mode: $("#performance-mode").val() || "balanced",
          scan_timeout: toInt($("#scan-timeout"), 300),
          request_size_limit: toInt($("#request-size-limit"), 10240),
          debug_mode: toBool($("#debug-mode"), 0),
          delete_on_uninstall: toBool($("#delete-on-uninstall"), 0),
        };
        saveModuleSettings("advanced", settings, $(this), $("#advanced-status"));
      });

      // Legacy self-protection page
      function loadProtectionStatus() {
        if (!$("#protection-status").length) {
          return;
        }

        $.ajax({
          url: nexifymySecurity.ajaxUrl,
          type: "POST",
          dataType: "json",
          data: {
            action: "nexifymy_get_protection_status",
            nonce: nexifymySecurity.nonce,
          },
          success: function (response) {
            if (!response || !response.success || !response.data) {
              $("#protection-status").html(
                '<p style="color: #d63638;">Unable to load integrity status.</p>',
              );
              return;
            }

            var data = response.data;
            var status = data.status || {};
            var isTampered = status.status === "tampered";
            var html = "";
            html +=
              '<p><strong>Status:</strong> <span style="color:' +
              (isTampered ? "#d63638" : "#00a32a") +
              ';">' +
              (isTampered ? "Tampering Detected" : "Protected") +
              "</span></p>";
            html +=
              "<p><strong>Last Check:</strong> " +
              (status.last_check || "Never") +
              "</p>";
            html +=
              "<p><strong>Baseline Files:</strong> " +
              (data.baseline_files || 0) +
              "</p>";

            if (isTampered) {
              var modifiedCount = Array.isArray(status.modified)
                ? status.modified.length
                : 0;
              var deletedCount = Array.isArray(status.deleted)
                ? status.deleted.length
                : 0;
              html +=
                '<p style="color:#d63638;"><strong>Modified:</strong> ' +
                modifiedCount +
                " | <strong>Deleted:</strong> " +
                deletedCount +
                "</p>";
            }

            $("#protection-status").html(html);
          },
          error: function () {
            $("#protection-status").html(
              '<p style="color: #d63638;">Failed to load protection status.</p>',
            );
          },
        });
      }

      $("#run-integrity-check").on("click", function () {
        var $btn = $(this);
        var $status = $("#integrity-status");
        $btn.prop("disabled", true);
        $status.text("Running integrity check...").css("color", "#666");

        $.ajax({
          url: nexifymySecurity.ajaxUrl,
          type: "POST",
          dataType: "json",
          data: {
            action: "nexifymy_run_integrity_check",
            nonce: nexifymySecurity.nonce,
          },
          success: function (response) {
            $btn.prop("disabled", false);
            if (response && response.success) {
              var result = response.data || {};
              var message =
                result.message ||
                (result.status === "tampered"
                  ? "Tampering detected."
                  : "Integrity check completed.");
              $status
                .text(message)
                .css("color", result.status === "tampered" ? "#d63638" : "#00a32a");
              loadProtectionStatus();
            } else {
              $status
                .text("Integrity check failed.")
                .css("color", "#d63638");
            }
          },
          error: function () {
            $btn.prop("disabled", false);
            $status
              .text("Integrity check request failed.")
              .css("color", "#d63638");
          },
        });
      });

      $("#regenerate-hashes").on("click", function () {
        var $btn = $(this);
        var $status = $("#integrity-status");
        $btn.prop("disabled", true);
        $status.text("Regenerating baseline...").css("color", "#666");

        $.ajax({
          url: nexifymySecurity.ajaxUrl,
          type: "POST",
          dataType: "json",
          data: {
            action: "nexifymy_generate_hashes",
            nonce: nexifymySecurity.nonce,
          },
          success: function (response) {
            $btn.prop("disabled", false);
            if (response && response.success) {
              $status
                .text(
                  (response.data && response.data.message) ||
                    "Baseline regenerated successfully.",
                )
                .css("color", "#00a32a");
              loadProtectionStatus();
            } else {
              $status.text("Failed to regenerate baseline.").css("color", "#d63638");
            }
          },
          error: function () {
            $btn.prop("disabled", false);
            $status.text("Request failed.").css("color", "#d63638");
          },
        });
      });

      // Legacy core repair page
      function renderCoreIntegrityResults(data) {
        if (!$("#results-content").length) {
          return;
        }

        var modified = Array.isArray(data.modified) ? data.modified : [];
        var missing = Array.isArray(data.missing) ? data.missing : [];
        var html = "";
        html += "<p><strong>Total files:</strong> " + (data.total_files || 0) + "</p>";
        html += "<p><strong>Verified:</strong> " + (data.verified || 0) + "</p>";
        html += "<p><strong>Modified:</strong> " + (data.modified_count || 0) + "</p>";
        html += "<p><strong>Missing:</strong> " + (data.missing_count || 0) + "</p>";

        if (modified.length || missing.length) {
          html += '<table class="widefat striped" style="margin-top: 12px;">';
          html += "<thead><tr><th>File</th><th>Status</th><th>Last Modified</th></tr></thead><tbody>";

          modified.forEach(function (item) {
            html += "<tr>";
            html += "<td><code>" + (item.file || "") + "</code></td>";
            html += '<td><span style="color:#d63638;">Modified</span></td>';
            html += "<td>" + (item.modified || "-") + "</td>";
            html += "</tr>";
          });

          missing.forEach(function (item) {
            html += "<tr>";
            html += "<td><code>" + (item.file || "") + "</code></td>";
            html += '<td><span style="color:#d63638;">Missing</span></td>';
            html += "<td>-</td>";
            html += "</tr>";
          });

          html += "</tbody></table>";
        } else {
          html += '<p style="color:#00a32a;"><strong>All core files are intact.</strong></p>';
        }

        $("#results-content").html(html);
      }

      $("#check-core-integrity").on("click", function () {
        var $btn = $(this);
        var $status = $("#repair-status");

        $btn.prop("disabled", true);
        $status.text("Checking core integrity...").css("color", "#666");

        $.ajax({
          url: nexifymySecurity.ajaxUrl,
          type: "POST",
          dataType: "json",
          data: {
            action: "nexifymy_check_core_integrity",
            nonce: nexifymySecurity.nonce,
          },
          success: function (response) {
            $btn.prop("disabled", false);
            if (response && response.success && response.data) {
              var data = response.data;
              var hasIssues =
                (data.modified_count || 0) > 0 || (data.missing_count || 0) > 0;
              $("#core-status").text(hasIssues ? "Issues detected" : "Clean");
              $status
                .text(
                  hasIssues
                    ? "Modified or missing core files detected."
                    : "Core integrity check passed.",
                )
                .css("color", hasIssues ? "#d63638" : "#00a32a");
              renderCoreIntegrityResults(data);
            } else {
              $status.text("Integrity check failed.").css("color", "#d63638");
            }
          },
          error: function () {
            $btn.prop("disabled", false);
            $status.text("Request failed.").css("color", "#d63638");
          },
        });
      });

      $("#repair-all-core").on("click", function () {
        var $btn = $(this);
        var $status = $("#repair-status");

        if (
          !window.confirm(
            "Repair all modified core files? This will overwrite affected WordPress core files.",
          )
        ) {
          return;
        }

        $btn.prop("disabled", true);
        $status.text("Repairing core files...").css("color", "#666");

        $.ajax({
          url: nexifymySecurity.ajaxUrl,
          type: "POST",
          dataType: "json",
          data: {
            action: "nexifymy_repair_all_core",
            nonce: nexifymySecurity.nonce,
          },
          success: function (response) {
            $btn.prop("disabled", false);
            if (response && response.success && response.data) {
              var data = response.data;
              if (data.success === false) {
                $status
                  .text(data.error || "Core repair failed.")
                  .css("color", "#d63638");
                return;
              }

              var repairedCount = data.repaired_count || data.repaired || 0;
              var failedCount = data.failed_count || 0;
              $status
                .text(
                  "Repair complete. Repaired: " +
                    repairedCount +
                    ", Failed: " +
                    failedCount,
                )
                .css("color", failedCount > 0 ? "#d63638" : "#00a32a");

              $("#check-core-integrity").trigger("click");
            } else {
              $status.text("Repair request failed.").css("color", "#d63638");
            }
          },
          error: function () {
            $btn.prop("disabled", false);
            $status.text("Repair request failed.").css("color", "#d63638");
          },
        });
      });

      loadProtectionStatus();

      // Activity log page controls
      function renderLoginActivityResults(data) {
        var $container = $("#login-activity-results");
        if (!$container.length) {
          return;
        }

        if (!data || !Array.isArray(data.entries) || data.entries.length === 0) {
          $container.html(
            '<p class="description">No login activity found for the selected filters.</p>',
          );
          return;
        }

        var html = "";
        html += '<table class="widefat striped">';
        html += "<thead><tr>";
        html += "<th>Date/Time</th>";
        html += "<th>Username</th>";
        html += "<th>Status</th>";
        html += "<th>IP Address</th>";
        html += "<th>User Agent</th>";
        html += "</tr></thead><tbody>";

        data.entries.forEach(function (entry) {
          var eventType = entry.event_type || "";
          var label = "Login";
          var badgeClass = "nms-badge-success";
          if (eventType === "login_failed") {
            label = "Failed";
            badgeClass = "nms-badge-danger";
          } else if (eventType === "logout") {
            label = "Logout";
            badgeClass = "nms-badge-secondary";
          }

          html += "<tr>";
          html += "<td><small>" + (entry.created_at || "") + "</small></td>";
          html += "<td><strong>" + (entry.username || "") + "</strong></td>";
          html +=
            '<td><span class="nms-badge ' +
            badgeClass +
            '">' +
            label +
            "</span></td>";
          html += "<td><code>" + (entry.ip_address || "") + "</code></td>";
          html +=
            "<td><small>" +
            ((entry.user_agent || "").substring(0, 120) || "-") +
            "</small></td>";
          html += "</tr>";
        });

        html += "</tbody></table>";
        html +=
          '<div class="nms-auto-s148"><span class="description">Showing ' +
          data.entries.length +
          " of " +
          (data.total || data.entries.length) +
          " entries</span></div>";

        $container.html(html);
      }

      function fetchLoginActivity(page) {
        var statusFilter = $("#login-filter-status").val() || "";
        var username = $("#login-filter-username").val() || "";
        var dateFrom = $("#login-filter-date-from").val() || "";
        var dateTo = $("#login-filter-date-to").val() || "";

        $.ajax({
          url: nexifymySecurity.ajaxUrl,
          type: "POST",
          dataType: "json",
          data: {
            action: "nexifymy_get_activity_log",
            event_group: "authentication",
            event_type: statusFilter,
            username: username,
            date_from: dateFrom,
            date_to: dateTo,
            page: page || 1,
            per_page: 25,
            nonce: nexifymySecurity.nonce,
          },
          success: function (response) {
            if (response && response.success) {
              renderLoginActivityResults(response.data || {});
            }
          },
        });
      }

      $("#login-filter-apply").on("click", function () {
        fetchLoginActivity(1);
      });

      $("#login-filter-reset").on("click", function () {
        $("#login-filter-username").val("");
        $("#login-filter-status").val("");
        $("#login-filter-date-from").val("");
        $("#login-filter-date-to").val("");
        fetchLoginActivity(1);
      });

      $("#export-login-csv").on("click", function () {
        var $btn = $(this);
        var statusFilter = $("#login-filter-status").val() || "";
        var username = $("#login-filter-username").val() || "";
        var dateFrom = $("#login-filter-date-from").val() || "";
        var dateTo = $("#login-filter-date-to").val() || "";

        $btn.prop("disabled", true);

        $.ajax({
          url: nexifymySecurity.ajaxUrl,
          type: "POST",
          dataType: "json",
          data: {
            action: "nexifymy_export_activity_log",
            event_group: "authentication",
            event_type: statusFilter,
            username: username,
            date_from: dateFrom,
            date_to: dateTo,
            nonce: nexifymySecurity.nonce,
          },
          success: function (response) {
            $btn.prop("disabled", false);
            if (!response || !response.success || !response.data) {
              alert("Unable to export login activity.");
              return;
            }

            var csv = csvTextFromRows(response.data.csv || []);
            var date = new Date();
            var filename =
              "nexifymy-login-activity-" +
              date.getFullYear() +
              ("0" + (date.getMonth() + 1)).slice(-2) +
              ("0" + date.getDate()).slice(-2) +
              ".csv";
            downloadTextFile(filename, "text/csv;charset=utf-8", csv);
          },
          error: function () {
            $btn.prop("disabled", false);
            alert("Unable to export login activity due to a connection error.");
          },
        });
      });

      // Activity log settings
      $("#save-activity-log-settings").on("click", function () {
        var excludedUsers = ($("#activity-log-excluded-users").val() || "")
          .split(/\r?\n/)
          .map(function (item) {
            return $.trim(item);
          })
          .filter(function (item) {
            return item.length > 0;
          });

        var settings = {
          enabled: toBool($("#activity-log-enabled"), 1),
          log_logins: toBool($("#activity-log-logins"), 1),
          log_failed_logins: toBool($("#activity-log-failed-logins"), 1),
          log_logouts: toBool($("#activity-log-logouts"), 1),
          log_profile_changes: toBool($("#activity-log-profile"), 1),
          log_role_changes: toBool($("#activity-log-roles"), 1),
          log_user_creation: toBool($("#activity-log-users"), 1),
          log_user_deletion: toBool($("#activity-log-users"), 1),
          log_post_changes: toBool($("#activity-log-posts"), 1),
          log_page_changes: toBool($("#activity-log-posts"), 1),
          log_media_uploads: toBool($("#activity-log-media"), 1),
          log_plugin_changes: toBool($("#activity-log-plugins"), 1),
          log_theme_changes: toBool($("#activity-log-themes"), 1),
          log_option_changes: toBool($("#activity-log-options"), 1),
          retention_days: toInt($("#activity-log-retention"), 90),
          excluded_users: excludedUsers,
        };

        saveModuleSettings(
          "activity_log",
          settings,
          $(this),
          $("#activity-log-status"),
        );
      });

      $("#purge-activity-log").on("click", function () {
        if (!window.confirm("Purge all activity logs? This cannot be undone.")) {
          return;
        }

        var $btn = $(this);
        var $status = $("#activity-log-status");
        $btn.prop("disabled", true);
        $status.html('<span style="color: #666;">Purging logs...</span>');

        $.ajax({
          url: nexifymySecurity.ajaxUrl,
          type: "POST",
          dataType: "json",
          data: {
            action: "nexifymy_purge_activity_log",
            nonce: nexifymySecurity.nonce,
          },
          success: function (response) {
            $btn.prop("disabled", false);
            if (response && response.success) {
              $status.html(
                '<span style="color: var(--nms-success);">' +
                  ((response.data && response.data.message) || "Activity log purged.") +
                  "</span>",
              );
              fetchLoginActivity(1);
            } else {
              $status.html(
                '<span style="color: var(--nms-danger);">' +
                  ((response && response.data) || "Failed to purge activity log.") +
                  "</span>",
              );
            }
          },
          error: function () {
            $btn.prop("disabled", false);
            $status.html(
              '<span style="color: var(--nms-danger);">Connection error while purging logs.</span>',
            );
          },
        });
      });

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

      $("#save-hardening-settings").on("click", function () {
        var settings = {};
        var $scope = $(this).closest(".nms-card, .nexifymy-card");
        var $inputs = $scope.find('input[type="checkbox"][name]');

        if (!$inputs.length) {
          $inputs = $('#hardening-options input[type="checkbox"][name]');
        }

        $inputs.each(function () {
          var key = $(this).attr("name");
          if (!key) {
            return;
          }
          settings[key] = $(this).is(":checked") ? 1 : 0;
        });

        saveModuleSettings(
          "hardening",
          settings,
          $(this),
          $("#hardening-status"),
        );
      });

      // Geo Blocking: dual-list country transfer.
      function escapeHtml(value) {
        return String(value)
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          .replace(/\"/g, "&quot;")
          .replace(/'/g, "&#39;");
      }

      function normaliseCountryName(raw) {
        var text = String(raw || "").trim();
        return text.replace(/\s*\([A-Z]{2}\)\s*$/, "").trim();
      }

      function getCountryMeta($checkbox) {
        var code = String($checkbox.val() || "")
          .trim()
          .toUpperCase();
        var name =
          $checkbox.data("country-name") ||
          $checkbox.closest("label").data("country-name") ||
          normaliseCountryName($checkbox.closest("label").text());
        return {
          code: code,
          name: String(name || code).trim(),
        };
      }

      function buildCountryRow(typeClass, code, name) {
        return (
          '<label class="nms-geo-checkbox-row" data-country-code="' +
          escapeHtml(code) +
          '" data-country-name="' +
          escapeHtml(name) +
          '"><input type="checkbox" class="' +
          typeClass +
          '" value="' +
          escapeHtml(code) +
          '" data-country-code="' +
          escapeHtml(code) +
          '" data-country-name="' +
          escapeHtml(name) +
          '"> <span class="nms-geo-country-name">' +
          escapeHtml(name) +
          '</span> <span class="nms-geo-country-code">(' +
          escapeHtml(code) +
          ")</span></label>"
        );
      }

      function sortGeoList($container) {
        var $rows = $container.find("label.nms-geo-checkbox-row").get();
        $rows.sort(function (a, b) {
          var aName = ($(a).data("country-name") || "")
            .toString()
            .toLowerCase();
          var bName = ($(b).data("country-name") || "")
            .toString()
            .toLowerCase();
          if (aName < bName) return -1;
          if (aName > bName) return 1;
          var aCode = ($(a).data("country-code") || "")
            .toString()
            .toLowerCase();
          var bCode = ($(b).data("country-code") || "")
            .toString()
            .toLowerCase();
          if (aCode < bCode) return -1;
          if (aCode > bCode) return 1;
          return 0;
        });
        $.each($rows, function (_, row) {
          $container.append(row);
        });
      }

      function ensureGeoEmptyState() {
        var $selectedList = $("#geo-selected-list");
        var hasRows =
          $selectedList.find("label.nms-geo-checkbox-row").length > 0;
        $selectedList.find(".nms-geo-empty-text").remove();
        if (!hasRows) {
          $selectedList.append(
            '<p class="description nms-geo-empty-text">No countries selected yet.</p>',
          );
        }
      }

      $("#geo-add-countries").on("click", function () {
        var $checkedBoxes = $("#geo-available-list .geo-country-check:checked");
        if ($checkedBoxes.length === 0) {
          alert("Please select at least one country to add.");
          return;
        }

        var $selectedList = $("#geo-selected-list");
        $checkedBoxes.each(function () {
          var $checkbox = $(this);
          var meta = getCountryMeta($checkbox);
          if (!meta.code) return;

          if (
            $selectedList.find('.geo-selected-check[value="' + meta.code + '"]')
              .length === 0
          ) {
            $selectedList.append(
              buildCountryRow("geo-selected-check", meta.code, meta.name),
            );
          }
          $checkbox.closest("label.nms-geo-checkbox-row").remove();
        });

        sortGeoList($selectedList);
        ensureGeoEmptyState();
      });

      $("#geo-remove-countries").on("click", function () {
        var $checkedBoxes = $("#geo-selected-list .geo-selected-check:checked");
        if ($checkedBoxes.length === 0) {
          alert("Please select at least one country to remove.");
          return;
        }

        var $availableList = $("#geo-available-list");
        $checkedBoxes.each(function () {
          var $checkbox = $(this);
          var meta = getCountryMeta($checkbox);
          if (!meta.code) return;

          if (
            $availableList.find('.geo-country-check[value="' + meta.code + '"]')
              .length === 0
          ) {
            $availableList.append(
              buildCountryRow("geo-country-check", meta.code, meta.name),
            );
          }
          $checkbox.closest("label.nms-geo-checkbox-row").remove();
        });

        sortGeoList($availableList);
        ensureGeoEmptyState();
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

      // Deception Settings Save
      $("#save-deception-settings").on("click", function () {
        var $btn = $(this);
        var $status = $("#deception-status");

        $btn.prop("disabled", true).text("Saving...");
        $status.html('<span style="color: #666;">Saving...</span>');

        $.ajax({
          url: nexifymySecurity.ajaxUrl,
          type: "POST",
          dataType: "json",
          data: {
            action: "nexifymy_save_deception_settings",
            nonce: nexifymySecurity.nonce,
            deception_enabled: $("#deception-enabled").is(":checked") ? 1 : 0,
            deception_honeytrap_paths: $("#honeytrap-paths").val() || "",
            deception_enum_trap: $("#enum-trap-enabled").is(":checked") ? 1 : 0,
            deception_enum_block: $("#enum-hard-block").is(":checked") ? 1 : 0,
            deception_block_all_enum: $("#enum-block-all").is(":checked")
              ? 1
              : 0,
          },
          success: function (response) {
            $btn
              .prop("disabled", false)
              .html(
                '<span class="dashicons dashicons-saved"></span> Save Changes',
              );

            if (response && response.success) {
              NexifymySecurity.reloadAfterSettingsSave(
                $status,
                700,
                "Saved! Reloading...",
              );
              return;
            }

            $status.html(
              '<span style="color: var(--nms-danger);">' +
                ((response && response.data) || "Failed to save settings.") +
                "</span>",
            );
          },
          error: function () {
            $btn
              .prop("disabled", false)
              .html(
                '<span class="dashicons dashicons-saved"></span> Save Changes',
              );
            $status.html(
              '<span style="color: var(--nms-danger);">Connection error</span>',
            );
          },
        });
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
            NexifymySecurity.reloadAfterSettingsSave(
              $status,
              700,
              "All modules saved! Reloading...",
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
            NexifymySecurity.reloadAfterSettingsSave(
              $status,
              700,
              "All changes saved successfully! Reloading...",
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
        var loginSlug = $("#hide-login-url").length
          ? $("#hide-login-url").val()
          : $("#login-slug").val();
        var redirectSlug = $("#hide-login-redirect").length
          ? $("#hide-login-redirect").val()
          : "404";
        var settings = {
          enabled: $("#hide-login-enabled").is(":checked") ? 1 : 0,
          login_slug: loginSlug,
          slug: loginSlug,
          redirect_slug: redirectSlug,
          redirect: redirectSlug,
          redirect_url: $("#hide-login-redirect-url").val() || "",
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
      function collectPasswordSettings() {
        var enforceEnabled = $("#pass-enforce").is(":checked") ? 1 : 0;
        var usingLegacyOptions = $("#password-options").length > 0;

        return {
          enforce: enforceEnabled,
          min_length: $("#pass-min-length").val() || 12,
          require_upper: usingLegacyOptions
            ? $("#password-options input[name=require_upper]").is(":checked")
              ? 1
              : 0
            : enforceEnabled,
          require_lower: usingLegacyOptions
            ? $("#password-options input[name=require_lower]").is(":checked")
              ? 1
              : 0
            : enforceEnabled,
          require_number: usingLegacyOptions
            ? $("#password-options input[name=require_number]").is(":checked")
              ? 1
              : 0
            : enforceEnabled,
          require_special: usingLegacyOptions
            ? $("#password-options input[name=require_special]").is(":checked")
              ? 1
              : 0
            : enforceEnabled,
          block_common: usingLegacyOptions
            ? $("#password-options input[name=block_common]").is(":checked")
              ? 1
              : 0
            : enforceEnabled,
          expiry_days: $("#pass-expiry").length ? $("#pass-expiry").val() : 90,
        };
      }

      function savePasswordPolicy($btn) {
        var settings = collectPasswordSettings();
        var $status = $("#pass-status").length
          ? $("#pass-status")
          : $("#password-status");
        saveModuleSettings(
          "password",
          settings,
          $btn,
          $status,
        );
      }

      $("#save-password-settings").on("click", function () {
        savePasswordPolicy($(this));
      });

      $("#save-pass-settings").on("click", function () {
        savePasswordPolicy($(this));
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
          comment_requests_per_minute: $("#rate-comment-requests").val() || 5,
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
          enabled: $("#waf-module-enabled").is(":checked") ? 1 : 0,
          block_sqli: $("#waf-block-sqli").is(":checked") ? 1 : 0,
          block_xss: $("#waf-block-xss").is(":checked") ? 1 : 0,
          block_lfi: $("#waf-block-lfi").is(":checked") ? 1 : 0,
          block_rfi: $("#waf-block-rfi").is(":checked") ? 1 : 0,
          block_rce: $("#waf-block-rce").is(":checked") ? 1 : 0,
          block_csrf: $("#waf-block-csrf").is(":checked") ? 1 : 0,
          block_traversal: $("#waf-block-traversal").is(":checked") ? 1 : 0,
          block_bad_bots: $("#waf-block-bots").is(":checked") ? 1 : 0,
          block_empty_ua: $("#waf-block-empty-ua").is(":checked") ? 1 : 0,
          allowed_user_agents: $("#waf-allowed-ua").val() || "",
          blocked_user_agents: $("#waf-blocked-ua").val() || "",
          max_request_size: $("#waf-max-request-size").val() || 10,
          max_query_length: $("#waf-max-query-length").val() || 2048,
          block_suspicious_uploads: $("#waf-block-uploads").is(":checked")
            ? 1
            : 0,
          blocked_extensions: $("#waf-blocked-extensions").val() || "",
          whitelist_ips: $("#waf-whitelist-ips").val() || "",
          blacklist_ips: $("#waf-blacklist-ips").val() || "",
          auto_block_repeat: $("#waf-auto-block").is(":checked") ? 1 : 0,
          block_threshold: $("#waf-block-threshold").val() || 5,
          block_duration: $("#waf-block-duration").val() || 86400,
          log_blocked: $("#waf-log-blocked").is(":checked") ? 1 : 0,
          log_allowed: $("#waf-log-allowed").is(":checked") ? 1 : 0,
          email_alerts: $("#waf-email-alerts").is(":checked") ? 1 : 0,
          alert_threshold: $("#waf-alert-threshold").val() || 10,
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
          timeout: $("#scanner-timeout").val(),
          memory_limit: $("#scanner-memory").val(),
          sensitivity: $("#scanner-sensitivity").val(),
          scan_core: $("#scanner-scan-core").is(":checked") ? 1 : 0,
          scan_themes: $("#scanner-scan-themes").is(":checked") ? 1 : 0,
          scan_plugins: $("#scanner-scan-plugins").is(":checked") ? 1 : 0,
          scan_uploads: $("#scanner-scan-uploads").is(":checked") ? 1 : 0,
          custom_paths: $("#scanner-custom-paths").val() || "",
          use_signatures: $("#scanner-use-signatures").is(":checked") ? 1 : 0,
          use_heuristics: $("#scanner-use-heuristics").is(":checked") ? 1 : 0,
          check_integrity: $("#scanner-check-integrity").is(":checked") ? 1 : 0,
          check_backdoors: $("#scanner-check-backdoors").is(":checked") ? 1 : 0,
          check_obfuscation: $("#scanner-check-obfuscation").is(":checked")
            ? 1
            : 0,
          email_reports: $("#scanner-email-reports").is(":checked") ? 1 : 0,
          excluded_paths: $("#scanner-excluded-paths").val(),
          excluded_extensions: $("#scanner-excluded-ext").val(),
          excluded_patterns: $("#scanner-excluded-patterns").val() || "",
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

      // CI/CD API key regeneration
      $("#regenerate-api-key").on("click", function () {
        var $btn = $(this);
        var $status = $("#cicd-status");
        var originalText = $btn.text();

        $btn.prop("disabled", true).text("Regenerating...");

        $.ajax({
          url: nexifymySecurity.ajaxUrl,
          type: "POST",
          dataType: "json",
          data: {
            action: "nexifymy_regenerate_cicd_api_key",
            nonce: nexifymySecurity.nonce,
          },
          success: function (response) {
            $btn.prop("disabled", false).text(originalText);
            if (response && response.success && response.data) {
              if ($("#cicd-api-key").length && response.data.api_key) {
                $("#cicd-api-key").val(response.data.api_key);
              }
              if ($status.length) {
                $status.html(
                  '<span style="color: var(--nms-success);">' +
                    (response.data.message || "API key regenerated.") +
                    "</span>",
                );
              }
            } else if ($status.length) {
              $status.html(
                '<span style="color: var(--nms-danger);">' +
                  ((response && response.data) || "Failed to regenerate API key.") +
                  "</span>",
              );
            }
          },
          error: function () {
            $btn.prop("disabled", false).text(originalText);
            if ($status.length) {
              $status.html(
                '<span style="color: var(--nms-danger);">Connection error while regenerating API key.</span>',
              );
            }
          },
        });
      });

      // Sandbox console actions
      function renderSandboxResults(result, staticOnly) {
        var sandboxResult = result || {};
        var staticFindings = sandboxResult.static || {};
        var dynamic = sandboxResult.dynamic || null;
        var risk = parseInt(sandboxResult.risk || 0, 10);
        var riskClass = risk >= 70 ? "danger" : risk >= 30 ? "warning" : "success";
        var iconClass =
          risk >= 70
            ? "dashicons-warning"
            : risk >= 30
              ? "dashicons-shield"
              : "dashicons-yes-alt";

        $("#sandbox-result-title").text(
          staticOnly ? "Static Analysis Results" : "Execution Results",
        );
        $("#sandbox-result-icon")
          .attr("class", "dashicons " + iconClass)
          .removeClass("danger warning success")
          .addClass(riskClass);

        var metaHtml = "";
        metaHtml +=
          '<div class="nms-sandbox-meta-item"><span class="label">Risk Score</span><span class="value">' +
          risk +
          "</span></div>";
        if (dynamic && typeof dynamic.execution_time !== "undefined") {
          metaHtml +=
            '<div class="nms-sandbox-meta-item"><span class="label">Execution Time</span><span class="value">' +
            dynamic.execution_time +
            "s</span></div>";
        }
        metaHtml +=
          '<div class="nms-sandbox-meta-item"><span class="label">Mode</span><span class="value">' +
          (staticOnly ? "Static Only" : "Static + Dynamic") +
          "</span></div>";
        $("#sandbox-meta").html(metaHtml);

        var staticHtml = "";
        var hasStatic = false;
        Object.keys(staticFindings).forEach(function (category) {
          var values = Array.isArray(staticFindings[category])
            ? staticFindings[category]
            : [];
          if (!values.length) {
            return;
          }
          hasStatic = true;
          staticHtml += '<div class="nms-sandbox-static-group">';
          staticHtml += "<strong>" + category.replace(/_/g, " ") + "</strong>";
          staticHtml += "<ul>";
          values.forEach(function (value) {
            staticHtml += "<li><code>" + value + "</code></li>";
          });
          staticHtml += "</ul></div>";
        });
        if (!hasStatic) {
          staticHtml =
            '<p class="description">No suspicious static patterns detected.</p>';
        }
        $("#sandbox-static-content").html(staticHtml);

        if (dynamic) {
          $("#sandbox-output-section").show();
          $("#sandbox-output").text(dynamic.output || "");
          $("#sandbox-errors-section").show();
          if (Array.isArray(dynamic.errors) && dynamic.errors.length) {
            var errorsHtml = "<ul>";
            dynamic.errors.forEach(function (err) {
              if (typeof err === "string") {
                errorsHtml += "<li>" + err + "</li>";
                return;
              }
              errorsHtml +=
                "<li>" +
                (err.type ? "[" + err.type + "] " : "") +
                (err.message || "Unknown error") +
                "</li>";
            });
            errorsHtml += "</ul>";
            $("#sandbox-errors").html(errorsHtml);
          } else {
            $("#sandbox-errors").html(
              '<p class="description">No runtime errors captured.</p>',
            );
          }

          $("#sandbox-queries-section").show();
          if (Array.isArray(dynamic.queries) && dynamic.queries.length) {
            var queriesHtml = "<ol>";
            dynamic.queries.forEach(function (query) {
              if (query && query.sql) {
                queriesHtml += "<li><code>" + query.sql + "</code></li>";
              } else if (typeof query === "string") {
                queriesHtml += "<li><code>" + query + "</code></li>";
              }
            });
            queriesHtml += "</ol>";
            $("#sandbox-queries").html(queriesHtml);
          } else {
            $("#sandbox-queries").html(
              '<p class="description">No database queries executed.</p>',
            );
          }
        } else {
          $("#sandbox-output-section").hide();
          $("#sandbox-errors-section").hide();
          $("#sandbox-queries-section").hide();
        }
      }

      function executeSandbox(staticOnly) {
        var $code = $("#sandbox-code");
        if (!$code.length) {
          return;
        }

        var code = $code.val() || "";
        if (!$.trim(code)) {
          alert("Please enter PHP code first.");
          return;
        }

        var $runBtn = $("#sandbox-run");
        var $analyzeBtn = $("#sandbox-analyze");
        var timeout = parseInt($("#sandbox-timeout").val(), 10) || 5;
        var nonce = $code.data("nonce") || nexifymySecurity.nonce;

        $runBtn.prop("disabled", true);
        $analyzeBtn.prop("disabled", true);
        $("#sandbox-result-title").text(
          staticOnly ? "Analyzing..." : "Executing...",
        );

        $.ajax({
          url: nexifymySecurity.ajaxUrl,
          type: "POST",
          dataType: "json",
          data: {
            action: "nexifymy_sandbox_execute",
            code: code,
            timeout: timeout,
            static_only: staticOnly ? 1 : 0,
            nonce: nonce,
          },
          success: function (response) {
            $runBtn.prop("disabled", false);
            $analyzeBtn.prop("disabled", false);
            if (response && response.success) {
              renderSandboxResults(response.data || {}, staticOnly);
            } else {
              alert((response && response.data) || "Sandbox execution failed.");
            }
          },
          error: function (jqXHR) {
            $runBtn.prop("disabled", false);
            $analyzeBtn.prop("disabled", false);
            var raw =
              jqXHR && typeof jqXHR.responseText === "string"
                ? jqXHR.responseText.trim()
                : "";
            alert(raw || "Sandbox execution request failed.");
          },
        });
      }

      $("#sandbox-run").on("click", function () {
        executeSandbox(false);
      });
      $("#sandbox-analyze").on("click", function () {
        executeSandbox(true);
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
              NexifymySecurity.reloadAfterSettingsSave(
                $status,
                700,
                "Saved! Reloading...",
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
                fetchSavedResults();
                return;
              }

              // If we tracked progress showing more data than response, use saved results
              if (
                lastProgress &&
                lastProgress.files_scanned > (data.files_scanned || 0) * 2
              ) {
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
              var classificationLabel =
                {
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
                (response.data.next_run || "Disabled") +
                ". Reloading...",
            );
            window.location.reload();
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
              html +=
                "<td><code>" + (file.original_path || "-") + "</code></td>";
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
              confirm("Permanently delete this file? This cannot be undone.")
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
            NexifymySecurity.showNotice(
              "success",
              "File restored successfully.",
            );
            NexifymySecurity.loadQuarantinedFiles();
          } else {
            NexifymySecurity.showNotice(
              "error",
              "Restore failed: " + response.data,
            );
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
            NexifymySecurity.showNotice(
              "error",
              "Delete failed: " + response.data,
            );
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
            NexifymySecurity.showNotice("success", "File permanently deleted.");
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

      $button
        .prop("disabled", true)
        .text(this.getString("saving", "Saving..."));

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

      function finalizeSettingsSave() {
        alert(
          NexifymySecurity.getString(
            "settingsSavedReloading",
            "Settings saved successfully! Reloading...",
          ),
        );
        window.location.reload();
      }

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        data: {
          action: "nexifymy_save_settings",
          settings: formData,
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          $button
            .prop("disabled", false)
            .text(
              NexifymySecurity.getString("saveSettingsBtn", "Save Settings"),
            );
          if (!response.success) {
            alert(
              NexifymySecurity.getString("error", "Error") +
                ": " +
                response.data,
            );
            return;
          }

          // Also save alert settings if present, then reload after both saves complete.
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
              complete: function () {
                finalizeSettingsSave();
              },
            });
            return;
          }

          finalizeSettingsSave();
        },
        error: function () {
          $button
            .prop("disabled", false)
            .text(
              NexifymySecurity.getString("saveSettingsBtn", "Save Settings"),
            );
          alert(
            NexifymySecurity.getString(
              "failedToSaveSettings",
              "Failed to save settings. Please try again.",
            ),
          );
        },
      });
    },

    resetSettings: function () {
      var $button = $("#reset-settings");
      $button
        .prop("disabled", true)
        .text(this.getString("resetting", "Resetting..."));

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        data: {
          action: "nexifymy_reset_settings",
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          if (response.success) {
            alert(
              NexifymySecurity.getString(
                "settingsResetReloading",
                "Settings reset to defaults. Reloading page...",
              ),
            );
            location.reload();
          } else {
            alert(
              NexifymySecurity.getString("error", "Error") +
                ": " +
                response.data,
            );
            $button
              .prop("disabled", false)
              .text(
                NexifymySecurity.getString(
                  "resetToDefaultsBtn",
                  "Reset to Defaults",
                ),
              );
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
            NexifymySecurity.reloadAfterSettingsSave(
              $status,
              700,
              (response.data && response.data.message
                ? response.data.message
                : "Saved.") + " Reloading...",
            );
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
            NexifymySecurity.reloadAfterSettingsSave(
              $status,
              700,
              "Saved. Reloading...",
            );
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
      if (
        !$("#save-password-settings").length &&
        !$("#save-pass-settings").length
      )
        return;

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
          if ($("#pass-enforce").length) {
            var enforce =
              "enforce" in password
                ? !!password.enforce
                : !!(
                    password.require_upper &&
                    password.require_lower &&
                    password.require_number &&
                    password.require_special
                  );
            $("#pass-enforce").prop("checked", enforce);
          }

          if ($("#password-options").length) {
            $(
              "#password-options input[type=checkbox][name=require_upper]",
            ).prop("checked", !!password.require_upper);
            $(
              "#password-options input[type=checkbox][name=require_lower]",
            ).prop("checked", !!password.require_lower);
            $(
              "#password-options input[type=checkbox][name=require_number]",
            ).prop("checked", !!password.require_number);
            $(
              "#password-options input[type=checkbox][name=require_special]",
            ).prop("checked", !!password.require_special);
            $(
              "#password-options input[type=checkbox][name=block_common]",
            ).prop("checked", !!password.block_common);
          }
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
      function t(key, fallback) {
        return self.getString(key, fallback);
      }
      var $loading = $("#analytics-loading");
      var $rangeSelect = $("#analytics-range");
      var $refreshBtn = $("#refresh-analytics");

      // Charts instances
      var charts = {};
      var chartLibraryPromise = null;

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
            alert(
              t("failedLoadAnalytics", "Failed to load analytics data."),
            );
          },
        });
      }

      // Update dashboard UI
      function updateDashboard(data) {
        data = data || {};
        var chartData = data.chart_data || {};
        var browserDistribution = data.browser_distribution || {};
        var osDistribution = data.os_distribution || {};
        var deviceDistribution = data.device_distribution || {};
        var geoDistribution = Array.isArray(data.geo_distribution)
          ? data.geo_distribution
          : [];

        chartData.labels = Array.isArray(chartData.labels)
          ? chartData.labels
          : [];
        chartData.page_views = Array.isArray(chartData.page_views)
          ? chartData.page_views
          : [];
        chartData.unique_visitors = Array.isArray(chartData.unique_visitors)
          ? chartData.unique_visitors
          : [];

        // Update summary cards
        if (data.totals) {
          $("#stats-total-views").text(formatNumber(data.totals.total_views));
          $("#stats-unique-visitors").text(
            formatNumber(data.totals.unique_visitors),
          );
          $("#stats-blocked-requests").text(formatNumber(data.totals.blocked));
        }

        // Top Country
        if (geoDistribution.length > 0) {
          $("#stats-top-country").text(geoDistribution[0].country_name);
        } else {
          $("#stats-top-country").text("-");
        }

        // 1. Traffic Overview Chart
        renderChart(
          "chart-traffic-overview",
          "line",
          {
            labels: chartData.labels,
            datasets: [
              {
                label: t("pageViews", "Page Views"),
                data: chartData.page_views,
                borderColor: "#4f46e5",
                backgroundColor: "rgba(79, 70, 229, 0.1)",
                borderWidth: 2,
                fill: true,
                tension: 0.4,
              },
              {
                label: t("uniqueVisitors", "Unique Visitors"),
                data: chartData.unique_visitors,
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
        var browserSeries = compactDistribution(browserDistribution, 6);
        var browserLabels = browserSeries.labels;
        var browserData = browserSeries.values;
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
        var osSeries = compactDistribution(osDistribution, 6);
        var osLabels = osSeries.labels;
        var osData = osSeries.values;
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
        var deviceSeries = compactDistribution(deviceDistribution, 6);
        var deviceLabels = deviceSeries.labels;
        var deviceData = deviceSeries.values;
        renderChart(
          "chart-devices",
          "bar",
          {
            labels: deviceLabels,
            datasets: [
              {
                label: t("devices", "Devices"),
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
        var geoTop = geoDistribution
          .filter(function (item) {
            return toNumber(item && item.count) > 0;
          })
          .slice(0, 5);
        var geoLabels = geoTop.map(function (item) {
          return item.country_name;
        });
        var geoData = geoTop.map(function (item) {
          return item.count;
        });
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
        updateTable("#table-top-pages", data.top_pages || [], ["url", "count"]);
        updateTable("#table-top-referrers", data.top_referrers || [], [
          "referrer",
          "count",
        ]);
        updateGeoTable("#table-geo", geoDistribution);
      }

      // Helper: Render Chart
      function renderChart(id, type, data, options) {
        var canvas = document.getElementById(id);
        if (!canvas) return;

        var fallbackId = id + "-fallback";
        var fallbackEl = document.getElementById(fallbackId);
        var chartConstructor = resolveChartConstructor();

        if (!chartConstructor) {
          ensureChartLibrary()
            .done(function () {
              renderChart(id, type, data, options);
            })
            .fail(function () {
              renderChartFallback(canvas, fallbackId, type, data);
            });
          return;
        }

        if (!hasRenderableData(data)) {
          if (charts[id]) {
            charts[id].destroy();
            delete charts[id];
          }
          renderChartFallback(canvas, fallbackId, type, data);
          return;
        }

        if (charts[id]) {
          charts[id].destroy();
        }

        if (fallbackEl) {
          fallbackEl.remove();
        }
        $(canvas).show();

        charts[id] = new chartConstructor(canvas, {
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

      function resolveChartConstructor() {
        if (typeof window.Chart === "function") {
          return window.Chart;
        }

        if (window.Chart && typeof window.Chart.Chart === "function") {
          return window.Chart.Chart;
        }

        if (window.Chart && typeof window.Chart.default === "function") {
          return window.Chart.default;
        }

        return null;
      }

      function ensureChartLibrary() {
        var existingConstructor = resolveChartConstructor();
        if (existingConstructor) {
          return $.Deferred().resolve(existingConstructor).promise();
        }

        if (chartLibraryPromise) {
          return chartLibraryPromise;
        }

        var deferred = $.Deferred();
        var chartJsUrl =
          nexifymySecurity && typeof nexifymySecurity.chartJsUrl === "string"
            ? nexifymySecurity.chartJsUrl
            : "";

        if (!chartJsUrl) {
          deferred.reject();
          chartLibraryPromise = deferred.promise();
          return chartLibraryPromise;
        }

        // Re-use an existing script tag if one already targets the same source.
        var existingScript = document.querySelector(
          'script[src="' + chartJsUrl + '"]',
        );
        if (existingScript) {
          var settled = false;
          function resolveExisting(constructorValue) {
            if (settled) {
              return;
            }
            settled = true;
            deferred.resolve(constructorValue);
          }

          function rejectExisting() {
            if (settled) {
              return;
            }
            settled = true;
            deferred.reject();
          }

          existingScript.addEventListener("load", function () {
            var constructorAfterExistingLoad = resolveChartConstructor();
            if (constructorAfterExistingLoad) {
              resolveExisting(constructorAfterExistingLoad);
              return;
            }
            rejectExisting();
          });
          existingScript.addEventListener("error", function () {
            rejectExisting();
          });

          // If the script already loaded before listeners were attached,
          // confirm quickly and then fail fast.
          setTimeout(function () {
            var constructorAfterWait = resolveChartConstructor();
            if (constructorAfterWait) {
              resolveExisting(constructorAfterWait);
              return;
            }
            rejectExisting();
          }, 300);

          chartLibraryPromise = deferred.promise();
          return chartLibraryPromise;
        }

        var script = document.createElement("script");
        script.src = chartJsUrl;
        script.async = true;

        script.onload = function () {
          var constructorAfterLoad = resolveChartConstructor();
          if (constructorAfterLoad) {
            deferred.resolve(constructorAfterLoad);
            return;
          }

          deferred.reject();
        };

        script.onerror = function () {
          deferred.reject();
        };

        document.head.appendChild(script);
        chartLibraryPromise = deferred.promise();
        return chartLibraryPromise;
      }

      function renderChartFallback(canvas, fallbackId, type, data) {
        var $canvas = $(canvas);
        var $parent = $canvas.parent();
        var $fallback = $("#" + fallbackId);

        if ($fallback.length === 0) {
          $fallback = $(
            '<div class="nms-chart-fallback" id="' + fallbackId + '"></div>',
          );
          $parent.append($fallback);
        }

        $canvas.hide();
        $fallback.html(buildFallbackMarkup(type, data)).show();
        bindFallbackInteractions($fallback);
      }

      function bindFallbackInteractions($fallback) {
        var $tooltip = $fallback.find(".nms-fallback-tooltip");
        if ($tooltip.length === 0) {
          $tooltip = $('<div class="nms-fallback-tooltip"></div>');
          $fallback.append($tooltip);
        }

        function hideTooltip() {
          $tooltip.removeClass("is-visible").text("");
        }

        function placeTooltip(x, y) {
          $tooltip.css({
            left: Math.max(6, x + 12) + "px",
            top: Math.max(6, y + 12) + "px",
          });
        }

        function placeTooltipForElement($element) {
          var fallbackEl = $fallback.get(0);
          var elementEl = $element.get(0);
          if (!fallbackEl || !elementEl) {
            return;
          }

          var fallbackRect = fallbackEl.getBoundingClientRect();
          var rect = elementEl.getBoundingClientRect();
          placeTooltip(
            rect.left - fallbackRect.left + rect.width / 2,
            rect.top - fallbackRect.top + rect.height / 2,
          );
        }

        $fallback.off(".nmsFallback");
        $fallback.on(
          "mouseenter.nmsFallback focusin.nmsFallback",
          "[data-tooltip]",
          function () {
            var $target = $(this);
            var text = String($target.attr("data-tooltip") || "").trim();
            if (!text) {
              hideTooltip();
              return;
            }

            $tooltip.text(text).addClass("is-visible");
            placeTooltipForElement($target);
          },
        );
        $fallback.on("mousemove.nmsFallback", "[data-tooltip]", function (evt) {
          var fallbackEl = $fallback.get(0);
          if (!fallbackEl) {
            return;
          }
          var rect = fallbackEl.getBoundingClientRect();
          placeTooltip(evt.clientX - rect.left, evt.clientY - rect.top);
        });
        $fallback.on(
          "mouseleave.nmsFallback blur.nmsFallback",
          "[data-tooltip]",
          function () {
            hideTooltip();
          },
        );
      }

      function buildFallbackMarkup(type, data) {
        var labels = Array.isArray(data && data.labels) ? data.labels : [];
        var datasets = Array.isArray(data && data.datasets)
          ? data.datasets
          : [];

        if (!labels.length || !datasets.length) {
          return (
            '<p class="nms-chart-fallback-empty">' +
            escapeHtml(
              t("noDataForRange", "No data available for this range."),
            ) +
            "</p>"
          );
        }

        if (type === "line") {
          return buildLineInfographic(labels, datasets, 14);
        }

        if (type === "doughnut" || type === "pie") {
          return buildRadialInfographic(labels, datasets[0], type === "doughnut");
        }

        if (type === "bar") {
          return buildBarInfographic(labels, datasets[0]);
        }

        return buildBarInfographic(labels, datasets[0]);
      }

      function buildLineInfographic(labels, datasets, maxPoints) {
        var startIndex = Math.max(labels.length - maxPoints, 0);
        var activeLabels = labels.slice(startIndex);
        var activeDatasets = datasets.map(function (dataset, datasetIndex) {
          return {
            label:
              dataset && dataset.label
                ? dataset.label
                : t("series", "Series"),
            color: getChartColor(dataset, datasetIndex),
            values: Array.isArray(dataset && dataset.data)
              ? dataset.data.slice(startIndex).map(toNumber)
              : [],
          };
        });
        var maxValue = 0;

        activeDatasets.forEach(function (dataset) {
          dataset.values.forEach(function (value) {
            maxValue = Math.max(maxValue, value);
          });
        });

        if (maxValue < 1) {
          maxValue = 1;
        }

        var width = 760;
        var height = 280;
        var paddingTop = 20;
        var paddingBottom = 36;
        var paddingLeft = 42;
        var paddingRight = 18;
        var chartW = width - paddingLeft - paddingRight;
        var chartH = height - paddingTop - paddingBottom;
        var stepX =
          activeLabels.length > 1 ? chartW / (activeLabels.length - 1) : chartW;
        var html =
          '<div class="nms-fallback-surface nms-fallback-line-surface">';
        html +=
          '<svg class="nms-fallback-line-svg" viewBox="0 0 ' +
          width +
          " " +
          height +
          '" role="img" aria-label="' +
          escapeHtml(t("trafficTrendFallbackChart", "Traffic trend chart")) +
          '">';

        for (var g = 0; g <= 4; g++) {
          var y = paddingTop + (chartH / 4) * g;
          var valueLabel = Math.round(maxValue - (maxValue / 4) * g);
          html +=
            '<line class="nms-fallback-grid-line" x1="' +
            paddingLeft +
            '" y1="' +
            y.toFixed(2) +
            '" x2="' +
            (paddingLeft + chartW).toFixed(2) +
            '" y2="' +
            y.toFixed(2) +
            '"></line>';
          html +=
            '<text class="nms-fallback-axis-text" x="' +
            (paddingLeft - 8) +
            '" y="' +
            (y + 4).toFixed(2) +
            '" text-anchor="end">' +
            escapeHtml(formatNumber(valueLabel)) +
            "</text>";
        }

        activeDatasets.forEach(function (dataset) {
          var points = [];
          (dataset.values || []).forEach(function (value, index) {
            var x = paddingLeft + stepX * index;
            var y = paddingTop + chartH - (value / maxValue) * chartH;
            points.push(x.toFixed(2) + "," + y.toFixed(2));
          });

          if (!points.length) {
            return;
          }

          html +=
            '<polyline class="nms-fallback-line-path" points="' +
            points.join(" ") +
            '" style="stroke:' +
            escapeHtml(dataset.color) +
            ';"></polyline>';

          (dataset.values || []).forEach(function (value, index) {
            var px = paddingLeft + stepX * index;
            var py = paddingTop + chartH - (value / maxValue) * chartH;
            var tooltip =
              dataset.label +
              " - " +
              activeLabels[index] +
              ": " +
              formatNumber(value);
            html +=
              '<circle class="nms-fallback-point" cx="' +
              px.toFixed(2) +
              '" cy="' +
              py.toFixed(2) +
              '" r="4" tabindex="0" data-tooltip="' +
              escapeHtml(tooltip) +
              '" style="fill:' +
              escapeHtml(dataset.color) +
              ';"></circle>';
          });
        });

        var labelStep = Math.max(1, Math.ceil(activeLabels.length / 6));
        activeLabels.forEach(function (label, index) {
          if (index % labelStep !== 0 && index !== activeLabels.length - 1) {
            return;
          }

          var lx = paddingLeft + stepX * index;
          html +=
            '<text class="nms-fallback-axis-text" x="' +
            lx.toFixed(2) +
            '" y="' +
            (paddingTop + chartH + 18).toFixed(2) +
            '" text-anchor="middle">' +
            escapeHtml(label) +
            "</text>";
        });

        html += "</svg>";
        html += '<div class="nms-fallback-legend">';
        activeDatasets.forEach(function (dataset) {
          var lastValue = dataset.values.length
            ? dataset.values[dataset.values.length - 1]
            : 0;
          html +=
            '<div class="nms-fallback-legend-item" data-tooltip="' +
            escapeHtml(dataset.label + ": " + formatNumber(lastValue)) +
            '">';
          html +=
            '<span class="nms-fallback-swatch" style="background:' +
            escapeHtml(dataset.color) +
            ';"></span>';
          html +=
            '<span class="nms-fallback-legend-label">' +
            escapeHtml(dataset.label) +
            "</span>";
          html +=
            '<span class="nms-fallback-legend-value">' +
            escapeHtml(formatNumber(lastValue)) +
            "</span>";
          html += "</div>";
        });
        html += "</div>";
        html += "</div>";
        return html;
      }

      function buildBarInfographic(labels, dataset) {
        var values = Array.isArray(dataset && dataset.data) ? dataset.data : [];
        var maxValue = 1;
        var rows = [];
        var html = '<div class="nms-fallback-surface nms-fallback-bars-grid">';

        labels.forEach(function (label, index) {
          var value = toNumber(values[index]);
          maxValue = Math.max(maxValue, value);
          rows.push({ label: label, value: value });
        });

        rows.forEach(function (row, index) {
          var width =
            row.value > 0
              ? Math.max(2, Math.round((row.value / maxValue) * 100))
              : 0;
          var color = getChartColor(dataset, index);
          html += '<div class="nms-fallback-bar-item">';
          html +=
            '<div class="nms-fallback-bar-label">' +
            escapeHtml(row.label) +
            "</div>";
          html += '<div class="nms-fallback-bar-track">';
          html +=
            '<div class="nms-fallback-bar" tabindex="0" data-tooltip="' +
            escapeHtml(row.label + ": " + formatNumber(row.value)) +
            '" style="width:' +
            width +
            "%;background:" +
            escapeHtml(color) +
            ';"></div>';
          html += "</div>";
          html +=
            '<span class="nms-fallback-bar-value">' +
            formatNumber(row.value) +
            "</span>";
          html += "</div>";
        });

        html += "</div>";
        return html;
      }

      function buildRadialInfographic(labels, dataset, donutStyle) {
        var values = Array.isArray(dataset && dataset.data) ? dataset.data : [];
        var rows = [];
        var total = 0;
        var html = '<div class="nms-fallback-surface nms-fallback-radial">';

        labels.forEach(function (label, index) {
          var value = toNumber(values[index]);
          if (value <= 0) {
            return;
          }
          total += value;
          rows.push({
            label: label,
            value: value,
            color: getChartColor(dataset, index),
          });
        });

        if (!rows.length || total <= 0) {
          return (
            '<p class="nms-chart-fallback-empty">' +
            escapeHtml(
              t("noDataForRange", "No data available for this range."),
            ) +
            "</p>"
          );
        }

        var cx = 120;
        var cy = 120;
        var outerR = 90;
        var innerR = donutStyle ? 52 : 0;
        var start = -Math.PI / 2;

        html += '<div class="nms-fallback-radial-chart">';
        html +=
          '<svg class="nms-fallback-radial-svg" viewBox="0 0 240 240" role="img" aria-label="' +
          escapeHtml(
            t("distributionFallbackChart", "Distribution breakdown chart"),
          ) +
          '">';

        rows.forEach(function (row) {
          var ratio = row.value / total;
          var end = start + ratio * Math.PI * 2;
          var path = describeArcPath(cx, cy, outerR, innerR, start, end);
          var tooltip =
            row.label +
            ": " +
            formatNumber(row.value) +
            " (" +
            formatPercent(row.value, total) +
            ")";

          html +=
            '<path class="nms-fallback-segment" tabindex="0" d="' +
            path +
            '" fill="' +
            escapeHtml(row.color) +
            '" data-tooltip="' +
            escapeHtml(tooltip) +
            '"></path>';
          start = end;
        });

        html += "</svg>";
        html += '<div class="nms-fallback-center-label">';
        html +=
          '<span class="nms-fallback-center-value">' +
          escapeHtml(formatNumber(total)) +
          "</span>";
        html +=
          '<span class="nms-fallback-center-caption">' +
          escapeHtml(t("total", "Total")) +
          "</span>";
        html += "</div>";
        html += "</div>";

        html += '<div class="nms-fallback-legend">';
        rows.forEach(function (row) {
          html +=
            '<div class="nms-fallback-legend-item" data-tooltip="' +
            escapeHtml(
              row.label +
                ": " +
                formatNumber(row.value) +
                " (" +
                formatPercent(row.value, total) +
                ")",
            ) +
            '">';
          html +=
            '<span class="nms-fallback-swatch" style="background:' +
            escapeHtml(row.color) +
            ';"></span>';
          html +=
            '<span class="nms-fallback-legend-label">' +
            escapeHtml(row.label) +
            "</span>";
          html +=
            '<span class="nms-fallback-legend-value">' +
            escapeHtml(formatPercent(row.value, total)) +
            "</span>";
          html += "</div>";
        });
        html += "</div>";
        html += "</div>";

        return html;
      }

      function describeArcPath(cx, cy, outerR, innerR, startAngle, endAngle) {
        var outerStart = polarToCartesian(cx, cy, outerR, startAngle);
        var outerEnd = polarToCartesian(cx, cy, outerR, endAngle);
        var largeArcFlag = endAngle - startAngle <= Math.PI ? "0" : "1";

        if (innerR <= 0) {
          return (
            "M " +
            cx.toFixed(2) +
            " " +
            cy.toFixed(2) +
            " L " +
            outerStart.x.toFixed(2) +
            " " +
            outerStart.y.toFixed(2) +
            " A " +
            outerR.toFixed(2) +
            " " +
            outerR.toFixed(2) +
            " 0 " +
            largeArcFlag +
            " 1 " +
            outerEnd.x.toFixed(2) +
            " " +
            outerEnd.y.toFixed(2) +
            " Z"
          );
        }

        var innerEnd = polarToCartesian(cx, cy, innerR, endAngle);
        var innerStart = polarToCartesian(cx, cy, innerR, startAngle);
        return (
          "M " +
          outerStart.x.toFixed(2) +
          " " +
          outerStart.y.toFixed(2) +
          " A " +
          outerR.toFixed(2) +
          " " +
          outerR.toFixed(2) +
          " 0 " +
          largeArcFlag +
          " 1 " +
          outerEnd.x.toFixed(2) +
          " " +
          outerEnd.y.toFixed(2) +
          " L " +
          innerEnd.x.toFixed(2) +
          " " +
          innerEnd.y.toFixed(2) +
          " A " +
          innerR.toFixed(2) +
          " " +
          innerR.toFixed(2) +
          " 0 " +
          largeArcFlag +
          " 0 " +
          innerStart.x.toFixed(2) +
          " " +
          innerStart.y.toFixed(2) +
          " Z"
        );
      }

      function polarToCartesian(cx, cy, radius, angle) {
        return {
          x: cx + Math.cos(angle) * radius,
          y: cy + Math.sin(angle) * radius,
        };
      }

      function formatPercent(value, total) {
        if (!total) {
          return "0%";
        }
        return ((toNumber(value) / toNumber(total)) * 100).toFixed(1) + "%";
      }

      function getChartColor(dataset, index) {
        var palette = [
          "#4f46e5",
          "#06b6d4",
          "#10b981",
          "#f59e0b",
          "#ef4444",
          "#8b5cf6",
          "#0ea5e9",
          "#22c55e",
        ];

        var background = dataset && dataset.backgroundColor;
        if (Array.isArray(background) && background.length > 0) {
          return String(background[index % background.length]);
        }

        if (typeof background === "string" && background.trim() !== "") {
          return background;
        }

        if (
          dataset &&
          typeof dataset.borderColor === "string" &&
          dataset.borderColor.trim() !== ""
        ) {
          return dataset.borderColor;
        }

        return palette[index % palette.length];
      }

      function hasRenderableData(data) {
        var labels = Array.isArray(data && data.labels) ? data.labels : [];
        var datasets = Array.isArray(data && data.datasets)
          ? data.datasets
          : [];

        if (!labels.length || !datasets.length) {
          return false;
        }

        return datasets.some(function (dataset) {
          var values = Array.isArray(dataset && dataset.data)
            ? dataset.data
            : [];

          return values.length > 0;
        });
      }

      function compactDistribution(distribution, limit) {
        var entries = Object.keys(distribution || {})
          .map(function (label) {
            return {
              label: label,
              value: toNumber(distribution[label]),
            };
          })
          .filter(function (entry) {
            return entry.value > 0;
          })
          .sort(function (a, b) {
            return b.value - a.value;
          });

        if (limit > 0 && entries.length > limit) {
          entries = entries.slice(0, limit);
        }

        return {
          labels: entries.map(function (entry) {
            return entry.label;
          }),
          values: entries.map(function (entry) {
            return entry.value;
          }),
        };
      }

      function toNumber(value) {
        var num = Number(value);
        return Number.isFinite(num) ? num : 0;
      }

      function escapeHtml(value) {
        return String(value)
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          .replace(/\"/g, "&quot;")
          .replace(/'/g, "&#39;");
      }

      // Helper: Update Table
      function updateTable(selector, data, columns) {
        var $body = $(selector).find("tbody");
        $body.empty();

        if (!data || data.length === 0) {
          $body.append(
            '<tr><td colspan="' +
              columns.length +
              '" style="text-align:center; color: #999;">' +
              escapeHtml(t("noDataAvailable", "No data available")) +
              "</td></tr>",
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
            '<tr><td colspan="3" style="text-align:center; color: #999;">' +
              escapeHtml(t("noDataAvailable", "No data available")) +
              "</td></tr>",
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
        var safe = Number(num);
        if (!Number.isFinite(safe)) {
          safe = 0;
        }
        return safe.toLocaleString();
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

    /**
     * Load legacy Security Analytics tab charts.
     */
    loadSecurityAnalyticsTab: function () {
      var $data = $("#nms-analytics-chart-data");
      if ($data.length === 0) {
        return;
      }

      function resolveChartConstructor() {
        if (typeof window.Chart === "function") {
          return window.Chart;
        }
        if (window.Chart && typeof window.Chart.Chart === "function") {
          return window.Chart.Chart;
        }
        if (window.Chart && typeof window.Chart.default === "function") {
          return window.Chart.default;
        }
        return null;
      }

      function ensureChartLibrary() {
        var deferred = $.Deferred();
        var chartConstructor = resolveChartConstructor();
        if (chartConstructor) {
          deferred.resolve(chartConstructor);
          return deferred.promise();
        }

        var chartJsUrl =
          nexifymySecurity && typeof nexifymySecurity.chartJsUrl === "string"
            ? nexifymySecurity.chartJsUrl
            : "";
        if (!chartJsUrl) {
          deferred.reject();
          return deferred.promise();
        }

        var script = document.querySelector('script[src="' + chartJsUrl + '"]');
        if (!script) {
          script = document.createElement("script");
          script.src = chartJsUrl;
          script.async = true;
          document.head.appendChild(script);
        }

        var settled = false;
        function resolveIfAvailable() {
          if (settled) {
            return;
          }
          var ctor = resolveChartConstructor();
          if (ctor) {
            settled = true;
            deferred.resolve(ctor);
          }
        }
        function rejectOnce() {
          if (settled) {
            return;
          }
          settled = true;
          deferred.reject();
        }

        script.addEventListener("load", resolveIfAvailable);
        script.addEventListener("error", rejectOnce);
        setTimeout(function () {
          resolveIfAvailable();
          if (!settled) {
            rejectOnce();
          }
        }, 600);

        return deferred.promise();
      }

      function parseDataAttr(name) {
        var raw = $data.attr("data-" + name);
        if (!raw) {
          return [];
        }
        try {
          var parsed = JSON.parse(raw);
          return Array.isArray(parsed) ? parsed : [];
        } catch (e) {
          return [];
        }
      }

      function toNumberArray(values, size) {
        var list = Array.isArray(values) ? values : [];
        var output = [];
        for (var i = 0; i < size; i += 1) {
          var num = Number(list[i]);
          output.push(Number.isFinite(num) ? num : 0);
        }
        return output;
      }

      var labels = parseDataAttr("labels");
      if (!labels.length) {
        return;
      }

      var threats = toNumberArray(parseDataAttr("threats"), labels.length);
      var blocked = toNumberArray(parseDataAttr("blocked"), labels.length);
      var logins = toNumberArray(parseDataAttr("logins"), labels.length);

      var maxThreat = Math.max.apply(Math, threats.concat(blocked).concat(logins));
      if (!Number.isFinite(maxThreat) || maxThreat < 0) {
        maxThreat = 0;
      }

      function renderFallback($canvas, html) {
        var canvas = $canvas.get(0);
        if (!canvas) {
          return;
        }
        $canvas.hide();

        var fallbackId = canvas.id + "-legacy-fallback";
        var $fallback = $("#" + fallbackId);
        if ($fallback.length === 0) {
          $fallback = $('<div class="nms-chart-fallback"></div>').attr(
            "id",
            fallbackId,
          );
          $canvas.after($fallback);
        }
        $fallback.html(html).show();
      }

      function buildTrendFallback() {
        var width = 760;
        var height = 230;
        var left = 24;
        var right = 12;
        var top = 16;
        var bottom = 22;
        var usableW = width - left - right;
        var usableH = height - top - bottom;
        var stepX = labels.length > 1 ? usableW / (labels.length - 1) : usableW;
        var maxValue = Math.max(1, maxThreat);

        function pathFor(series) {
          var points = [];
          for (var i = 0; i < labels.length; i += 1) {
            var x = left + i * stepX;
            var y = top + usableH - (series[i] / maxValue) * usableH;
            points.push(x.toFixed(2) + "," + y.toFixed(2));
          }
          return points.join(" ");
        }

        return (
          '<div class="nms-fallback-surface">' +
          '<svg class="nms-fallback-line-svg" viewBox="0 0 ' +
          width +
          " " +
          height +
          '">' +
          '<polyline class="nms-fallback-line-path" points="' +
          pathFor(blocked) +
          '" stroke="#3b82f6"></polyline>' +
          '<polyline class="nms-fallback-line-path" points="' +
          pathFor(threats) +
          '" stroke="#ef4444"></polyline>' +
          '<polyline class="nms-fallback-line-path" points="' +
          pathFor(logins) +
          '" stroke="#10b981"></polyline>' +
          "</svg>" +
          '<div class="nms-fallback-legend">' +
          '<div class="nms-fallback-legend-item"><span class="nms-fallback-swatch" style="background:#3b82f6"></span><span class="nms-fallback-legend-label">Blocked</span><span class="nms-fallback-legend-value">' +
          blocked.reduce(function (sum, v) {
            return sum + v;
          }, 0) +
          "</span></div>" +
          '<div class="nms-fallback-legend-item"><span class="nms-fallback-swatch" style="background:#ef4444"></span><span class="nms-fallback-legend-label">Threats</span><span class="nms-fallback-legend-value">' +
          threats.reduce(function (sum, v) {
            return sum + v;
          }, 0) +
          "</span></div>" +
          '<div class="nms-fallback-legend-item"><span class="nms-fallback-swatch" style="background:#10b981"></span><span class="nms-fallback-legend-label">Logins</span><span class="nms-fallback-legend-value">' +
          logins.reduce(function (sum, v) {
            return sum + v;
          }, 0) +
          "</span></div>" +
          "</div>" +
          "</div>"
        );
      }

      function buildLoginFallback() {
        var total = logins.reduce(function (sum, v) {
          return sum + v;
        }, 0);
        var avg = labels.length ? Math.round((total / labels.length) * 10) / 10 : 0;
        var peak = Math.max.apply(Math, logins.concat([0]));

        return (
          '<div class="nms-fallback-surface nms-fallback-radial">' +
          '<div class="nms-fallback-radial-chart">' +
          '<svg class="nms-fallback-radial-svg" viewBox="0 0 240 240">' +
          '<circle cx="120" cy="120" r="78" fill="none" stroke="#e2e8f0" stroke-width="24"></circle>' +
          '<circle cx="120" cy="120" r="78" fill="none" stroke="#10b981" stroke-width="24" stroke-linecap="round" stroke-dasharray="' +
          Math.max(2, Math.min(490, (total / Math.max(1, maxThreat * labels.length)) * 490)) +
          ' 490" transform="rotate(-90 120 120)"></circle>' +
          "</svg>" +
          '<div class="nms-fallback-center-label"><span class="nms-fallback-center-value">' +
          total +
          '</span><span class="nms-fallback-center-caption">Total logins</span></div>' +
          "</div>" +
          '<div class="nms-fallback-legend">' +
          '<div class="nms-fallback-legend-item"><span class="nms-fallback-swatch" style="background:#10b981"></span><span class="nms-fallback-legend-label">Average / day</span><span class="nms-fallback-legend-value">' +
          avg +
          "</span></div>" +
          '<div class="nms-fallback-legend-item"><span class="nms-fallback-swatch" style="background:#0ea5e9"></span><span class="nms-fallback-legend-label">Peak day</span><span class="nms-fallback-legend-value">' +
          peak +
          "</span></div>" +
          "</div>" +
          "</div>"
        );
      }

      function renderWithChart(ChartCtor) {
        var threatCanvas = document.getElementById("nms-threats-chart");
        var loginsCanvas = document.getElementById("nms-logins-chart");
        if (!threatCanvas || !loginsCanvas) {
          return;
        }

        var chartStore = NexifymySecurity._legacyAnalyticsCharts || {};
        if (chartStore.threats) {
          chartStore.threats.destroy();
        }
        if (chartStore.logins) {
          chartStore.logins.destroy();
        }

        chartStore.threats = new ChartCtor(threatCanvas, {
          type: "line",
          data: {
            labels: labels,
            datasets: [
              {
                label: "Blocked",
                data: blocked,
                borderColor: "#3b82f6",
                backgroundColor: "rgba(59,130,246,.12)",
                borderWidth: 2,
                fill: true,
                tension: 0.35,
              },
              {
                label: "Threats",
                data: threats,
                borderColor: "#ef4444",
                backgroundColor: "rgba(239,68,68,.1)",
                borderWidth: 2,
                fill: true,
                tension: 0.35,
              },
              {
                label: "Logins",
                data: logins,
                borderColor: "#10b981",
                backgroundColor: "rgba(16,185,129,.08)",
                borderWidth: 2,
                fill: false,
                tension: 0.35,
              },
            ],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { mode: "index", intersect: false },
            plugins: { legend: { position: "bottom" } },
            scales: {
              x: { grid: { display: false } },
              y: { beginAtZero: true, grid: { color: "#e2e8f0" } },
            },
          },
        });

        chartStore.logins = new ChartCtor(loginsCanvas, {
          type: "radar",
          data: {
            labels: labels,
            datasets: [
              {
                label: "Login Attempts",
                data: logins,
                borderColor: "#10b981",
                backgroundColor: "rgba(16,185,129,.2)",
                borderWidth: 2,
                pointBackgroundColor: "#10b981",
                pointRadius: 3,
              },
            ],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { position: "bottom" } },
            scales: {
              r: {
                beginAtZero: true,
                angleLines: { color: "#e2e8f0" },
                grid: { color: "#e2e8f0" },
                pointLabels: { color: "#475569" },
              },
            },
          },
        });

        NexifymySecurity._legacyAnalyticsCharts = chartStore;
      }

      ensureChartLibrary()
        .done(function (chartCtor) {
          renderWithChart(chartCtor);
        })
        .fail(function () {
          renderFallback($("#nms-threats-chart"), buildTrendFallback());
          renderFallback($("#nms-logins-chart"), buildLoginFallback());
        });
    },
  };

  $(document).ready(function () {
    NexifymySecurity.init();
  });
})(jQuery);
