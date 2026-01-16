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
      this.loadBlockedIPs();
      this.loadQuarantinedFiles();
      this.loadDatabaseInfo();
      this.loadBackups();
      this.loadOptimizationStats();
    },

    bindEvents: function () {
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
        (stats.by_severity && stats.by_severity.critical) || 0
      );
      $("#stat-warning").text(
        (stats.by_severity && stats.by_severity.warning) || 0
      );
      $("#stat-info").text((stats.by_severity && stats.by_severity.info) || 0);
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
                  "</p>"
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
              '<p class="error">' + nexifymySecurity.strings.error + "</p>"
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
                (response.data.next_run || "Disabled")
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
      var $container = $('#database-info');
      if (!$container.length) return;

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: 'POST',
        data: {
          action: 'nexifymy_get_database_info',
          nonce: nexifymySecurity.nonce
        },
        success: function (response) {
          if (response.success) {
            var info = response.data.info;
            var html = '<table class="widefat">';
            html += '<tr><th>Database Name</th><td>' + info.database_name + '</td></tr>';
            html += '<tr><th>Table Prefix</th><td>' + info.prefix;
            if (info.is_default_prefix) {
              html += ' <span class="notice notice-warning" style="margin-left:10px;display:inline-block;padding:2px 8px;">Using default prefix - consider changing for security</span>';
            }
            html += '</td></tr>';
            html += '<tr><th>Database Size</th><td>' + info.database_size_formatted + '</td></tr>';
            html += '<tr><th>Table Count</th><td>' + info.table_count + '</td></tr>';
            html += '</table>';
            $container.html(html);
          }
        }
      });
    },

    loadBackups: function () {
      var $tbody = $('#backups-tbody');
      if (!$tbody.length) return;

      $tbody.html('<tr><td colspan="4">Loading backups...</td></tr>');

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: 'POST',
        data: {
          action: 'nexifymy_get_backups',
          nonce: nexifymySecurity.nonce
        },
        success: function (response) {
          if (response.success) {
            var html = '';
            if (response.data.backups.length === 0) {
              html = '<tr><td colspan="4">No backups found. Create your first backup above.</td></tr>';
            } else {
              response.data.backups.forEach(function (backup) {
                html += '<tr>';
                html += '<td>' + backup.filename + '</td>';
                html += '<td>' + backup.size_formatted + '</td>';
                html += '<td>' + backup.created_at_formatted + '</td>';
                html += '<td>';
                html += '<a href="' + nexifymySecurity.ajaxUrl + '?action=nexifymy_download_backup&filename=' + encodeURIComponent(backup.filename) + '&nonce=' + nexifymySecurity.nonce + '" class="button button-small">Download</a> ';
                html += '<button class="button button-small button-link-delete delete-backup" data-filename="' + backup.filename + '">Delete</button>';
                html += '</td>';
                html += '</tr>';
              });
            }
            $tbody.html(html);

            // Bind delete button
            $('.delete-backup').on('click', function () {
              var filename = $(this).data('filename');
              if (confirm('Delete this backup?')) {
                NexifymySecurity.deleteBackup(filename, $(this));
              }
            });
          }
        }
      });
    },

    createBackup: function () {
      var $button = $('#create-backup');
      var $status = $('#backup-status');

      $button.prop('disabled', true);
      $status.text('Creating backup...').css('color', '#666');

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: 'POST',
        data: {
          action: 'nexifymy_create_backup',
          nonce: nexifymySecurity.nonce
        },
        success: function (response) {
          $button.prop('disabled', false);
          if (response.success) {
            $status.text('Backup created successfully!').css('color', 'green');
            NexifymySecurity.loadBackups();
          } else {
            $status.text('Error: ' + response.data).css('color', 'red');
          }
        },
        error: function () {
          $button.prop('disabled', false);
          $status.text('Failed to create backup').css('color', 'red');
        }
      });
    },

    deleteBackup: function (filename, $button) {
      $button.prop('disabled', true).text('Deleting...');

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: 'POST',
        data: {
          action: 'nexifymy_delete_backup',
          filename: filename,
          nonce: nexifymySecurity.nonce
        },
        success: function (response) {
          if (response.success) {
            $button.closest('tr').fadeOut();
          } else {
            alert('Error: ' + response.data);
            $button.prop('disabled', false).text('Delete');
          }
        }
      });
    },

    loadOptimizationStats: function () {
      var $container = $('#optimization-stats');
      if (!$container.length) return;

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: 'POST',
        data: {
          action: 'nexifymy_get_optimization_stats',
          nonce: nexifymySecurity.nonce
        },
        success: function (response) {
          if (response.success) {
            var stats = response.data.stats;
            var html = '<table class="widefat">';
            html += '<tr><th>Transients</th><td>' + stats.transients + '</td></tr>';
            html += '<tr><th>Post Revisions</th><td>' + stats.revisions + '</td></tr>';
            html += '<tr><th>Spam Comments</th><td>' + stats.spam_comments + '</td></tr>';
            html += '<tr><th>Trashed Comments</th><td>' + stats.trash_comments + '</td></tr>';
            html += '<tr><th>Trashed Posts</th><td>' + stats.trash_posts + '</td></tr>';
            html += '<tr><th>Orphaned Meta</th><td>' + stats.orphan_meta + '</td></tr>';
            html += '<tr><th><strong>Total Cleanable Items</strong></th><td><strong>' + stats.total + '</strong></td></tr>';
            html += '</table>';
            $container.html(html);
          }
        }
      });
    },

    optimizeDatabase: function () {
      var $button = $('#optimize-database');
      var $status = $('#optimize-status');

      if (!confirm('This will permanently delete transients, revisions, spam, and trashed items. Continue?')) {
        return;
      }

      $button.prop('disabled', true);
      $status.text('Optimizing...').css('color', '#666');

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: 'POST',
        data: {
          action: 'nexifymy_optimize_database',
          nonce: nexifymySecurity.nonce
        },
        success: function (response) {
          $button.prop('disabled', false);
          if (response.success) {
            $status.text(response.data.message).css('color', 'green');
            NexifymySecurity.loadOptimizationStats();
          } else {
            $status.text('Error: ' + response.data).css('color', 'red');
          }
        },
        error: function () {
          $button.prop('disabled', false);
          $status.text('Failed to optimize database').css('color', 'red');
        }
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
