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
      this.loadDatabaseInfo();
      this.loadBackups();
      this.loadOptimizationStats();
      this.loadLiveTraffic();
      this.loadTrafficStats();
      this.loadCountryList();
      this.loadHardeningStatus();
      this.loadCdnStatus();
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
        var mode = $(this).closest(".scan-mode").data("mode");
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
      });

      // Test Alert
      $("#test-alert").on("click", function () {
        NexifymySecurity.sendTestAlert();
      });

      // Notifications
      $("#mark-all-notifications-read").on("click", function () {
        NexifymySecurity.markAllNotificationsRead();
      });

      // Dashboard tab switching
      $(".nms-tabs .nms-tab[data-tab]").on("click", function (e) {
        e.preventDefault();
        var tabId = $(this).data("tab");

        // Update active tab
        $(".nms-tabs .nms-tab").removeClass("active");
        $(this).addClass("active");

        // Show corresponding content
        $(".nms-tab-content").removeClass("active");
        $("#nms-tab-" + tabId).addClass("active");
      });

      // Module toggle switches
      $(".nms-toggle input[data-module]").on("change", function () {
        var $this = $(this);
        var module = $this.data("module");
        var enabled = $this.is(":checked");

        $.ajax({
          url: nexifymySecurity.ajaxUrl,
          type: "POST",
          data: {
            action: "nexifymy_toggle_module",
            module: module,
            enabled: enabled ? 1 : 0,
            nonce: nexifymySecurity.nonce,
          },
          success: function (response) {
            if (response.success) {
              // Update card visual state
              var $card = $this.closest(".nms-module-card");
              if ($card.length) {
                if (enabled) {
                  $card.addClass("active");
                } else {
                  $card.removeClass("active");
                }
              }
              console.log(
                "Module " + module + " " + (enabled ? "enabled" : "disabled"),
              );
            } else {
              // Revert toggle on error
              $this.prop("checked", !enabled);
              alert("Error: " + (response.data || "Unknown error"));
            }
          },
          error: function () {
            $this.prop("checked", !enabled);
            alert("Failed to update module settings");
          },
        });
      });

      // Update malware definitions button
      $("#update-definitions").on("click", function () {
        var $btn = $(this);
        var $status = $("#update-status");

        $btn.prop("disabled", true).find(".dashicons").addClass("spin");
        $status.html('<span style="color: #666;">Updating...</span>');

        $.ajax({
          url: nexifymySecurity.ajaxUrl,
          type: "POST",
          data: {
            action: "nexifymy_update_signatures",
            nonce: nexifymySecurity.nonce,
          },
          success: function (response) {
            $btn.prop("disabled", false).find(".dashicons").removeClass("spin");
            if (response.success) {
              $status.html(
                '<span style="color: var(--nms-success);">✓ Updated successfully!</span>',
              );
              // Reload page to show new version
              setTimeout(function () {
                location.reload();
              }, 1500);
            } else {
              $status.html(
                '<span style="color: var(--nms-danger);">✗ ' +
                  (response.data || "Update failed") +
                  "</span>",
              );
            }
          },
          error: function () {
            $btn.prop("disabled", false).find(".dashicons").removeClass("spin");
            $status.html(
              '<span style="color: var(--nms-danger);">✗ Connection error</span>',
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
                '<span style="color: var(--nms-success);">✓ Saved!</span>',
              );
              setTimeout(function () {
                $status.html("");
              }, 3000);
            } else {
              $status.html(
                '<span style="color: var(--nms-danger);">✗ ' +
                  (response.data || "Failed") +
                  "</span>",
              );
            }
          },
          error: function () {
            $btn.prop("disabled", false);
            $status.html(
              '<span style="color: var(--nms-danger);">✗ Connection error</span>',
            );
          },
        });
      }

      // 2FA Settings Save
      $("#save-2fa-settings").on("click", function () {
        var settings = {
          enabled: $("#2fa-enabled").is(":checked") ? 1 : 0,
          force_admin: $("#2fa-force-admin").is(":checked") ? 1 : 0,
          email_backup: $("#2fa-email-backup").is(":checked") ? 1 : 0,
          remember_days: $("#2fa-remember-days").val(),
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
      $("#save-geo-settings").on("click", function () {
        var countries = [];
        $("#geo-countries option:selected").each(function () {
          countries.push($(this).val());
        });
        var settings = {
          enabled: $("#geo-enabled").is(":checked") ? 1 : 0,
          mode: $("#geo-mode").val(),
          countries: countries,
          message: $("#geo-message").val(),
        };
        saveModuleSettings("geo_blocking", settings, $(this), $("#geo-status"));
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
          enabled: $("#captcha-settings input[name=captcha_enabled]").is(
            ":checked",
          )
            ? 1
            : 0,
          login: $("#captcha-settings input[name=enable_login]").is(":checked")
            ? 1
            : 0,
          registration: $(
            "#captcha-settings input[name=enable_registration]",
          ).is(":checked")
            ? 1
            : 0,
          reset: $("#captcha-settings input[name=enable_reset]").is(":checked")
            ? 1
            : 0,
          comment: $("#captcha-settings input[name=enable_comment]").is(
            ":checked",
          )
            ? 1
            : 0,
          difficulty: $("#captcha-difficulty").val(),
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
          expiry: $("#pass-expiry").val(),
        };
        saveModuleSettings(
          "password_policy",
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
        var settings = {
          enabled: $("#rate-enabled").is(":checked") ? 1 : 0,
          requests_per_minute: $("#rate-requests").val(),
          block_duration: $("#rate-duration").val(),
          whitelist: $("#rate-whitelist").val(),
        };
        saveModuleSettings(
          "rate_limiter",
          settings,
          $(this),
          $("#rate-status"),
        );
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
          "danger",
          "Permanently Delete",
          "This action cannot be undone. The file will be permanently deleted.",
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
      var $progressFill = $progress.find(".progress-fill");
      var $status = $progress.find(".scan-status");

      $progress.show();
      $results.hide();
      $progressFill.css("width", "10%");
      $status.text(nexifymySecurity.strings.scanning);

      // Simulate progress
      var progress = 10;
      var progressInterval = setInterval(function () {
        progress += Math.random() * 15;
        if (progress > 90) progress = 90;
        $progressFill.css("width", progress + "%");
      }, 500);

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        data: {
          action: "nexifymy_scan",
          mode: mode,
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          clearInterval(progressInterval);
          $progressFill.css("width", "100%");

          setTimeout(function () {
            $progress.hide();
            $results.show();

            if (response.success) {
              NexifymySecurity.displayScanResults(response.data);
            } else {
              $("#results-content, #scan-results").html(
                '<p class="error">' +
                  nexifymySecurity.strings.error +
                  ": " +
                  response.data +
                  "</p>",
              );
            }
          }, 500);
        },
        error: function () {
          clearInterval(progressInterval);
          $progress.hide();
          $results
            .show()
            .html(
              '<p class="error">' + nexifymySecurity.strings.error + "</p>",
            );
        },
      });
    },

    displayScanResults: function (data) {
      var html = '<div class="scan-results-summary">';
      html += "<p><strong>Mode:</strong> " + data.mode_name + "</p>";
      html +=
        "<p><strong>Files Scanned:</strong> " + data.files_scanned + "</p>";
      html +=
        '<p><strong>Threats Found:</strong> <span class="' +
        (data.threats_found > 0 ? "threat-count" : "clean-count") +
        '">' +
        data.threats_found +
        "</span></p>";
      html += "</div>";

      if (data.threats && data.threats.length > 0) {
        html += '<table class="widefat striped">';
        html +=
          "<thead><tr><th>File</th><th>Threat</th><th>Severity</th><th>Action</th></tr></thead>";
        html += "<tbody>";

        data.threats.forEach(function (threat) {
          threat.threats.forEach(function (t) {
            html += "<tr>";
            html += "<td><code>" + threat.file + "</code></td>";
            html += "<td>" + t.description + "</td>";
            html +=
              '<td><span class="severity-' +
              t.severity +
              '">' +
              t.severity +
              "</span></td>";
            html +=
              '<td><button class="button button-small delete-file" data-file="' +
              threat.file +
              '">Quarantine</button></td>';
            html += "</tr>";
          });
        });

        html += "</tbody></table>";
      } else {
        html +=
          '<p class="all-good"><span class="dashicons dashicons-yes-alt"></span> No threats detected!</p>';
      }

      $("#results-content, #scan-results").html(html);

      // Bind delete button
      $(".delete-file").on("click", function () {
        var file = $(this).data("file");
        if (confirm("Quarantine this file?")) {
          NexifymySecurity.deleteFile(file, $(this));
        }
      });
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
          if (response.success) {
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

            // Bind action buttons
            $(".restore-file").on("click", function () {
              var filename = $(this).data("filename");
              if (confirm("Restore this file to its original location?")) {
                NexifymySecurity.restoreFile(filename, $(this));
              }
            });

            $(".delete-quarantined").on("click", function () {
              var filename = $(this).data("filename");
              if (
                confirm("PERMANENTLY delete this file? This cannot be undone.")
              ) {
                NexifymySecurity.deleteQuarantined(filename, $(this));
              }
            });
          }
        },
      });
    },

    restoreFile: function (filename, $button) {
      $button.prop("disabled", true).text("Restoring...");

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
            $button.closest("tr").fadeOut(function () {
              $(this).remove();
            });
            alert("File restored successfully.");
          } else {
            alert("Error: " + response.data);
            $button.prop("disabled", false).text("Restore");
          }
        },
      });
    },

    deleteQuarantined: function (filename, $button) {
      $button.prop("disabled", true).text("Deleting...");

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
            $button.closest("tr").fadeOut(function () {
              $(this).remove();
            });
          } else {
            alert("Error: " + response.data);
            $button.prop("disabled", false).text("Delete");
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
  };

  $(document).ready(function () {
    NexifymySecurity.init();
  });
})(jQuery);
