/**
 * NexifyMy Security - Admin Page Specific JavaScript
 * Moves page-level handlers out of PHP templates.
 */

(function ($) {
  "use strict";

  function escapeHtml(value) {
    return String(value || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function parseJsonAttr($el, attrName, fallbackValue) {
    var raw = $el.attr(attrName);
    if (!raw) {
      return fallbackValue;
    }

    try {
      return JSON.parse(raw);
    } catch (e) {
      return fallbackValue;
    }
  }

  function clampInt(value, fallback, min, max) {
    var parsed = parseInt(value, 10);
    if (isNaN(parsed)) {
      parsed = fallback;
    }
    if (typeof min === "number") {
      parsed = Math.max(min, parsed);
    }
    if (typeof max === "number") {
      parsed = Math.min(max, parsed);
    }
    return parsed;
  }

  function initTrafficAnalyticsWidget() {
    if (
      typeof Chart === "undefined" ||
      !$("#traffic-trends-chart").length ||
      !window.nexifymySecurity
    ) {
      return;
    }

    var trafficChart = null;

    function updateTrafficChart(chartData) {
      var ctx = document.getElementById("traffic-trends-chart");
      if (!ctx || !chartData) {
        return;
      }

      if (trafficChart) {
        trafficChart.destroy();
      }

      trafficChart = new Chart(ctx.getContext("2d"), {
        type: "line",
        data: {
          labels: chartData.labels || [],
          datasets: [
            {
              label: "Page Views",
              data: chartData.page_views || [],
              borderColor: "#6366f1",
              backgroundColor: "rgba(99, 102, 241, 0.1)",
              borderWidth: 2,
              tension: 0.4,
              fill: true,
              pointBackgroundColor: "#ffffff",
              pointBorderColor: "#6366f1",
              pointRadius: 4,
            },
            {
              label: "Unique Visitors",
              data: chartData.unique_visitors || [],
              borderColor: "#10b981",
              backgroundColor: "rgba(16, 185, 129, 0.05)",
              borderWidth: 2,
              tension: 0.4,
              fill: false,
              borderDash: [5, 5],
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: true,
          plugins: {
            legend: { position: "top" },
            tooltip: {
              mode: "index",
              intersect: false,
            },
          },
          scales: {
            y: { beginAtZero: true },
          },
        },
      });
    }

    function updateTopPages(pages) {
      var html = '<ul class="nms-list-stats">';
      if (Array.isArray(pages) && pages.length > 0) {
        pages.forEach(function (page) {
          var url = page && page.url ? page.url : "";
          var shortUrl = url.substring(0, 50) + (url.length > 50 ? "..." : "");
          html += "<li>";
          html +=
            '<span class="nms-stat-label" title="' +
            escapeHtml(url) +
            '"><span class="dashicons dashicons-admin-page"></span> ' +
            escapeHtml(shortUrl) +
            "</span>";
          html +=
            '<span class="nms-badge info">' +
            Number(page.count || 0) +
            " views</span>";
          html += "</li>";
        });
      } else {
        html += '<li class="nms-list-empty">No data available</li>';
      }
      html += "</ul>";
      $("#top-pages-list").html(html);
    }

    function updateTopReferrers(referrers) {
      var html = '<ul class="nms-list-stats">';
      if (Array.isArray(referrers) && referrers.length > 0) {
        referrers.forEach(function (ref) {
          var source = ref && ref.referrer ? ref.referrer : "Direct";
          var shortSource =
            source.substring(0, 40) + (source.length > 40 ? "..." : "");

          html += "<li>";
          html +=
            '<span class="nms-stat-label" title="' +
            escapeHtml(source) +
            '"><span class="dashicons dashicons-admin-links"></span> ' +
            escapeHtml(shortSource) +
            "</span>";
          html +=
            '<span class="nms-badge success">' +
            Number(ref.count || 0) +
            "</span>";
          html += "</li>";
        });
      } else {
        html += '<li class="nms-list-empty">No data available</li>';
      }
      html += "</ul>";
      $("#top-referrers-list").html(html);
    }

    function updateGeoDistribution(geo) {
      var html = '<ul class="nms-list-stats">';
      if (Array.isArray(geo) && geo.length > 0) {
        geo.forEach(function (country) {
          var label =
            (country && (country.country_name || country.country_code)) ||
            "Unknown";
          html += "<li>";
          html +=
            '<span class="nms-stat-label"><span class="dashicons dashicons-location"></span> ' +
            escapeHtml(label) +
            "</span>";
          html +=
            '<span class="nms-badge warning">' +
            Number(country.count || 0) +
            " visits</span>";
          html += "</li>";
        });
      } else {
        html += '<li class="nms-list-empty">No geographic data available</li>';
      }
      html += "</ul>";
      $("#geo-distribution").html(html);
    }

    function loadTrafficAnalytics(days) {
      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        dataType: "json",
        data: {
          action: "nexifymy_get_traffic_analytics",
          nonce: nexifymySecurity.nonce,
          days: days || 30,
        },
        success: function (response) {
          if (response && response.success && response.data) {
            updateTrafficChart(response.data.chart_data);
            updateTopPages(response.data.top_pages);
            updateTopReferrers(response.data.top_referrers);
            updateGeoDistribution(response.data.geo_distribution);
          }
        },
      });
    }

    $("#traffic-chart-period")
      .off("change.nmsTraffic")
      .on("change.nmsTraffic", function () {
        loadTrafficAnalytics($(this).val());
      });

    loadTrafficAnalytics(30);
  }

  function initCaptchaProviderToggle() {
    var $provider = $("#captcha-provider");
    if (!$provider.length) {
      return;
    }

    function updateProviderRows() {
      var provider = $provider.val();
      if (provider === "nexifymy") {
        $(".nexifymy-captcha-row").show();
        $(".external-captcha-row").hide();
      } else {
        $(".nexifymy-captcha-row").hide();
        $(".external-captcha-row").show();
      }
    }

    $provider
      .off("change.nmsCaptchaProvider")
      .on("change.nmsCaptchaProvider", updateProviderRows);
    updateProviderRows();
  }

  function initSupplyChainHandlers() {
    if (
      !$("#run-supply-chain-scan").length &&
      !$("#save-supply-chain-settings").length
    ) {
      return;
    }

    $("#run-supply-chain-scan")
      .off("click.nmsSupplyChain")
      .on("click.nmsSupplyChain", function () {
        var $btn = $(this);
        $btn
          .prop("disabled", true)
          .html('<span class="dashicons dashicons-update spin"></span> Scanning...');

        $.post(
          nexifymySecurity.ajaxUrl,
          {
            action: "nexifymy_supply_chain_scan",
            nonce: nexifymySecurity.nonce,
          },
          function (response) {
            if (response && response.success) {
              window.location.reload();
              return;
            }

            alert(
              "Scan failed: " +
                ((response && response.data) || "Unknown error"),
            );
            $btn
              .prop("disabled", false)
              .html(
                '<span class="dashicons dashicons-update"></span> Run Scan',
              );
          },
          "json",
        );
      });

    function parsePatchPayload($button) {
      var raw = $button.attr("data-patch");
      if (!raw) {
        return null;
      }

      try {
        return JSON.parse(raw);
      } catch (_error) {
        return null;
      }
    }

    function formatPreviewSummary(data) {
      if (!data || !data.compatibility_report) {
        return "Preview completed.";
      }

      var report = data.compatibility_report;
      var safe = report.safe_to_apply ? "Yes" : "No";
      var total = report.total_patches || 0;
      var highRisk = report.high_risk_count || 0;
      var summary = report.summary || "";

      return (
        "Preview Result\n" +
        "Safe to Apply: " +
        safe +
        "\n" +
        "Patches Reviewed: " +
        total +
        "\n" +
        "High-Risk Items: " +
        highRisk +
        "\n\n" +
        summary
      );
    }

    $(document)
      .off("click.nmsSupplyChain", ".verify-cdn-script")
      .on("click.nmsSupplyChain", ".verify-cdn-script", function () {
        var $btn = $(this);
        var url = $btn.data("url");
        $btn.prop("disabled", true).text("Generating...");

        $.post(
          nexifymySecurity.ajaxUrl,
          {
            action: "nexifymy_verify_cdn_script",
            nonce: nexifymySecurity.nonce,
            url: url,
          },
          function (response) {
            if (response && response.success && response.data.integrity) {
              window.prompt("Copy this SRI hash:", response.data.integrity);
            } else {
              alert("Failed to generate SRI hash");
            }
            $btn.prop("disabled", false).text("Generate SRI");
          },
          "json",
        );
      });

    $(document)
      .off("click.nmsSupplyChain", ".preview-supply-chain-patch")
      .on("click.nmsSupplyChain", ".preview-supply-chain-patch", function () {
        var $btn = $(this);
        var patch = parsePatchPayload($btn);

        if (!patch) {
          alert("Invalid patch payload.");
          return;
        }

        $btn.prop("disabled", true).text("Previewing...");

        $.post(
          nexifymySecurity.ajaxUrl,
          {
            action: "nexifymy_preview_supply_chain_patch",
            nonce: nexifymySecurity.nonce,
            patch: JSON.stringify(patch),
          },
          function (response) {
            if (response && response.success) {
              alert(formatPreviewSummary(response.data));
            } else {
              alert(
                "Preview failed: " +
                  ((response && response.data) || "Unknown error"),
              );
            }
            $btn.prop("disabled", false).text("Preview Patch");
          },
          "json",
        );
      });

    $(document)
      .off("click.nmsSupplyChain", ".apply-supply-chain-patch")
      .on("click.nmsSupplyChain", ".apply-supply-chain-patch", function () {
        var $btn = $(this);
        var patch = parsePatchPayload($btn);

        if (!patch) {
          alert("Invalid patch payload.");
          return;
        }

        var confirmationMessage =
          "Apply patch now?\n\n" +
          "Package: " +
          (patch.package_name || "unknown") +
          "\nCommand: " +
          (patch.command || "n/a");

        if (!window.confirm(confirmationMessage)) {
          return;
        }

        $btn.prop("disabled", true).text("Applying...");

        $.post(
          nexifymySecurity.ajaxUrl,
          {
            action: "nexifymy_apply_supply_chain_patch",
            nonce: nexifymySecurity.nonce,
            confirm: "yes",
            patch: JSON.stringify(patch),
          },
          function (response) {
            if (response && response.success) {
              alert("Patch applied successfully.");
              window.location.reload();
              return;
            }

            alert(
              "Patch failed: " +
                ((response && response.data) || "Unknown error"),
            );
            $btn.prop("disabled", false).text("Apply Patch");
          },
          "json",
        );
      });

    $("#save-supply-chain-settings")
      .off("click.nmsSupplyChain")
      .on("click.nmsSupplyChain", function () {
        var settings = {
          enabled: true,
          scan_plugins: $("#supply-chain-scan-plugins").is(":checked"),
          scan_themes: $("#supply-chain-scan-themes").is(":checked"),
          scan_composer: $("#supply-chain-scan-composer").is(":checked"),
          scan_npm: $("#supply-chain-scan-npm").is(":checked"),
          monitor_external_scripts: $("#supply-chain-monitor-scripts").is(
            ":checked",
          ),
          verify_cdn_integrity: true,
          auto_scan_schedule: $("#supply-chain-auto-scan").val(),
          notify_on_issues: $("#supply-chain-notify").is(":checked"),
        };

        $.post(
          nexifymySecurity.ajaxUrl,
          {
            action: "nexifymy_save_module_settings",
            nonce: nexifymySecurity.nonce,
            module: "supply_chain",
            settings: settings,
          },
          function (response) {
            if (response && response.success) {
              alert("Settings saved successfully");
            }
          },
          "json",
        );
      });
  }

  function initComplianceHandlers() {
    if (
      !$("#generate-compliance-report").length &&
      !$("#generate-first-report").length &&
      !$("#run-compliance-check").length &&
      !$("#run-data-map-scan").length &&
      !$("#submit-rtbf-request").length
    ) {
      return;
    }

    function displayComplianceResults(results) {
      var html = '<div class="nms-compliance-grid">';

      $.each(results, function (_category, data) {
        var passed = 0;
        var failed = 0;
        var checks = data.checks || {};

        $.each(checks, function (_key, check) {
          if (check.passed) {
            passed++;
          } else {
            failed++;
          }
        });

        var total = passed + failed;
        var percentage = total > 0 ? Math.round((passed / total) * 100) : 0;
        var level =
          percentage >= 80
            ? "good"
            : percentage >= 60
              ? "warning"
              : "critical";

        html += '<div class="nms-compliance-card">';
        html += '<div class="nms-compliance-card-header">';
        html += '<h4 class="nms-compliance-title">' + escapeHtml(data.name) + "</h4>";
        html +=
          '<span class="nms-compliance-score nms-compliance-score-' +
          level +
          '">' +
          percentage +
          "%</span>";
        html += "</div>";

        html += '<div class="nms-compliance-checks">';
        $.each(checks, function (_key, check) {
          html +=
            '<div class="nms-compliance-check ' +
            (check.passed ? "pass" : "fail") +
            '">';
          html +=
            '<span class="nms-compliance-check-icon">' +
            (check.passed ? "OK" : "X") +
            "</span>";
          html +=
            '<span class="nms-compliance-check-label">' +
            escapeHtml(check.name) +
            "</span>";
          html += "</div>";
        });
        html += "</div></div>";
      });

      html += "</div>";

      $("#compliance-check-grid").html(html);
      $("#quick-compliance-results").slideDown();
    }

    function renderDataMapRows(records) {
      var html = "";
      if (Array.isArray(records) && records.length > 0) {
        html += '<table class="widefat striped">';
        html +=
          "<thead><tr><th>Data Element</th><th>Location</th><th>Purpose</th><th>Retention</th><th>Third-Party Sharing</th><th>Legal Basis</th></tr></thead><tbody>";
        records.forEach(function (record) {
          html += "<tr>";
          html += "<td>" + escapeHtml(record.data_element || "") + "</td>";
          html += "<td>" + escapeHtml(record.location || "") + "</td>";
          html += "<td>" + escapeHtml(record.purpose || "") + "</td>";
          html += "<td>" + escapeHtml(record.retention || "") + "</td>";
          html +=
            "<td>" + escapeHtml(record.third_party_sharing || "") + "</td>";
          html += "<td>" + escapeHtml(record.legal_basis || "") + "</td>";
          html += "</tr>";
        });
        html += "</tbody></table>";
      } else {
        html =
          "<p id='data-map-table-body'>No PII records detected yet. Run a data map scan to build the report.</p>";
      }

      $("#data-map-results").html(html);
    }

    $("#generate-compliance-report, #generate-first-report")
      .off("click.nmsCompliance")
      .on("click.nmsCompliance", function () {
        var $btn = $(this);
        $btn
          .prop("disabled", true)
          .html(
            '<span class="dashicons dashicons-update spin"></span> Generating...',
          );

        $.post(
          nexifymySecurity.ajaxUrl,
          {
            action: "nexifymy_generate_report",
            nonce: nexifymySecurity.nonce,
          },
          function (response) {
            if (response && response.success) {
              window.location.reload();
              return;
            }

            alert(
              "Report generation failed: " +
                ((response && response.data) || "Unknown error"),
            );
            $btn
              .prop("disabled", false)
              .html(
                '<span class="dashicons dashicons-media-document"></span> Generate Report',
              );
          },
          "json",
        );
      });

    $("#run-compliance-check")
      .off("click.nmsCompliance")
      .on("click.nmsCompliance", function () {
        var $btn = $(this);
        $btn
          .prop("disabled", true)
          .html('<span class="dashicons dashicons-update spin"></span> Checking...');

        $.post(
          nexifymySecurity.ajaxUrl,
          {
            action: "nexifymy_run_compliance_check",
            nonce: nexifymySecurity.nonce,
          },
          function (response) {
            if (response && response.success) {
              displayComplianceResults(response.data);
            } else {
              alert(
                "Check failed: " + ((response && response.data) || "Unknown error"),
              );
            }

            $btn
              .prop("disabled", false)
              .html(
                '<span class="dashicons dashicons-yes-alt"></span> Run Quick Check',
              );
          },
          "json",
        );
      });

    $(document)
      .off("click.nmsCompliance", ".download-report")
      .on("click.nmsCompliance", ".download-report", function () {
        var reportId = $(this).data("report-id");

        $.post(
          nexifymySecurity.ajaxUrl,
          {
            action: "nexifymy_download_report",
            nonce: nexifymySecurity.nonce,
            report_id: reportId,
          },
          function (response) {
            if (response && response.success && response.data.url) {
              window.open(response.data.url, "_blank");
              return;
            }

            alert("Failed to download report");
          },
          "json",
        );
      });

    $("#run-data-map-scan")
      .off("click.nmsCompliance")
      .on("click.nmsCompliance", function () {
        var $btn = $(this);
        $btn
          .prop("disabled", true)
          .html('<span class="dashicons dashicons-update spin"></span> Scanning...');

        $.post(
          nexifymySecurity.ajaxUrl,
          {
            action: "nexifymy_get_data_map",
            nonce: nexifymySecurity.nonce,
          },
          function (response) {
            if (response && response.success && response.data) {
              renderDataMapRows(response.data.records || []);
            } else {
              alert(
                "Data map scan failed: " +
                  ((response && response.data) || "Unknown error"),
              );
            }

            $btn
              .prop("disabled", false)
              .html('<span class="dashicons dashicons-update"></span> Refresh Map');
          },
          "json",
        );
      });

    $("#export-data-map-pdf")
      .off("click.nmsCompliance")
      .on("click.nmsCompliance", function () {
        var $btn = $(this);
        $btn
          .prop("disabled", true)
          .html(
            '<span class="dashicons dashicons-update spin"></span> Exporting...',
          );

        $.post(
          nexifymySecurity.ajaxUrl,
          {
            action: "nexifymy_export_data_map",
            nonce: nexifymySecurity.nonce,
            format: "pdf",
          },
          function (response) {
            if (response && response.success && response.data && response.data.url) {
              window.open(response.data.url, "_blank");
              if (response.data.fallback) {
                alert(
                  "PDF generator not available. Opened HTML report instead; use browser Print to save as PDF.",
                );
              }
            } else {
              alert(
                "Data map export failed: " +
                  ((response && response.data) || "Unknown error"),
              );
            }

            $btn
              .prop("disabled", false)
              .html(
                '<span class="dashicons dashicons-download"></span> Export Data Map (PDF)',
              );
          },
          "json",
        );
      });

    function runRtbfAction(actionName) {
      var userId = parseInt($("#rtbf-user-id").val(), 10);
      if (!userId || userId < 1) {
        alert("Please enter a valid user ID.");
        return;
      }

      var payload = {
        action: actionName,
        nonce: nexifymySecurity.nonce,
        user_id: userId,
      };

      if (actionName === "nexifymy_erase_user_data") {
        payload.include_comments = $("#rtbf-include-comments").is(":checked")
          ? 1
          : 0;
      }

      $("#rtbf-status").html(
        '<p><span class="dashicons dashicons-update spin"></span> Processing request...</p>',
      );

      $.post(
        nexifymySecurity.ajaxUrl,
        payload,
        function (response) {
          if (response && response.success) {
            if (actionName === "nexifymy_erase_user_data") {
              $("#rtbf-status").html(
                '<div class="notice notice-success inline"><p>Erasure completed. Verification status: ' +
                  escapeHtml(
                    response.data.verification &&
                      response.data.verification.is_clean
                      ? "Clean"
                      : "Review needed",
                  ) +
                  "</p></div>",
              );
            } else {
              $("#rtbf-status").html(
                '<div class="notice notice-info inline"><p>Verification result: ' +
                  escapeHtml(response.data.is_clean ? "Clean" : "Review needed") +
                  "</p></div>",
              );
            }
          } else {
            $("#rtbf-status").html(
              '<div class="notice notice-error inline"><p>' +
                escapeHtml((response && response.data) || "Request failed.") +
                "</p></div>",
            );
          }
        },
        "json",
      );
    }

    $("#submit-rtbf-request")
      .off("click.nmsCompliance")
      .on("click.nmsCompliance", function () {
        runRtbfAction("nexifymy_erase_user_data");
      });

    $("#verify-rtbf-request")
      .off("click.nmsCompliance")
      .on("click.nmsCompliance", function () {
        runRtbfAction("nexifymy_verify_erasure");
      });

    $("#save-compliance-settings")
      .off("click.nmsCompliance")
      .on("click.nmsCompliance", function () {
        var settings = {
          enabled: true,
          auto_generate: $("#compliance-auto-generate").is(":checked"),
          schedule: $("#compliance-schedule").val(),
          email_reports: $("#compliance-email-reports").is(":checked"),
          include_gdpr: $("#compliance-include-gdpr").is(":checked"),
          include_security: $("#compliance-include-security").is(":checked"),
          include_performance: $("#compliance-include-performance").is(":checked"),
          include_threats: $("#compliance-include-threats").is(":checked"),
          retention_days: parseInt($("#compliance-retention-days").val(), 10),
        };

        $.post(
          nexifymySecurity.ajaxUrl,
          {
            action: "nexifymy_save_module_settings",
            nonce: nexifymySecurity.nonce,
            module: "compliance",
            settings: settings,
          },
          function (response) {
            if (response && response.success) {
              alert("Settings saved successfully");
            }
          },
          "json",
        );
      });
  }

  function initAiThreatHandlers() {
    if (!$("#ai-threats-list").length) {
      return;
    }

    function displayThreats(threats) {
      var html = "";

      if (Array.isArray(threats) && threats.length > 0) {
        html = '<table class="widefat striped">';
        html += "<thead><tr>";
        html += "<th>IP Address</th>";
        html += "<th>Threat Score</th>";
        html += "<th>Anomalies</th>";
        html += "<th>Status</th>";
        html += "<th>Time</th>";
        html += "</tr></thead><tbody>";

        threats
          .slice()
          .reverse()
          .slice(0, 20)
          .forEach(function (threat) {
            var statusClass = threat.status === "blocked" ? "danger" : "warning";
            var scoreClass =
              threat.score >= 90 ? "danger" : threat.score >= 75 ? "warning" : "info";

            html += "<tr>";
            html += "<td><code>" + escapeHtml(threat.ip) + "</code></td>";
            html +=
              '<td><span class="nms-badge ' +
              scoreClass +
              '">' +
              Number(threat.score || 0) +
              "/100</span></td>";
            html +=
              "<td>" +
              escapeHtml(
                Array.isArray(threat.anomalies)
                  ? threat.anomalies.join(", ")
                  : threat.anomalies,
              ) +
              "</td>";
            html +=
              '<td><span class="nms-badge ' +
              statusClass +
              '">' +
              escapeHtml(threat.status) +
              "</span></td>";
            html +=
              "<td>" +
              escapeHtml(threat.blocked_at || threat.flagged_at || "") +
              "</td>";
            html += "</tr>";
          });

        html += "</tbody></table>";
      } else {
        html = '<p class="nms-empty-state">No threats detected yet.</p>';
      }

      $("#ai-threats-list").html(html);
    }

    function loadAiThreats() {
      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        dataType: "json",
        data: {
          action: "nexifymy_get_ai_threats",
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          if (response && response.success && response.data) {
            displayThreats(response.data);
          }
        },
      });
    }

    $("#refresh-ai-status")
      .off("click.nmsAi")
      .on("click.nmsAi", function () {
        var $btn = $(this);
        $btn.prop("disabled", true);

        $.ajax({
          url: nexifymySecurity.ajaxUrl,
          type: "POST",
          dataType: "json",
          data: {
            action: "nexifymy_get_ai_status",
            nonce: nexifymySecurity.nonce,
          },
          success: function (response) {
            if (response && response.success && response.data) {
              var status = response.data;
              $("#ai-total-records").text((status.total_records || 0).toLocaleString());
              $("#ai-threats-today").text((status.threats_today || 0).toLocaleString());
              $("#ai-countries").text((status.known_countries || 0).toLocaleString());
              $("#ai-last-learned").text(status.last_learned || "Never");

              var hoursHtml = "";
              if (Array.isArray(status.peak_hours) && status.peak_hours.length > 0) {
                status.peak_hours.forEach(function (hour) {
                  hoursHtml +=
                    '<span class="nms-badge info nms-ai-hour-badge">' +
                    String(hour).padStart(2, "0") +
                    ":00</span> ";
                });
              } else {
                hoursHtml = "Learning...";
              }
              $("#ai-peak-hours").html(hoursHtml);
            }
            $btn.prop("disabled", false);
          },
          error: function () {
            $btn.prop("disabled", false);
          },
        });
      });

    $("#reset-ai-learning")
      .off("click.nmsAi")
      .on("click.nmsAi", function () {
        if (
          !window.confirm(
            "This will reset all AI learning data and behavior patterns. Continue?",
          )
        ) {
          return;
        }

        var $btn = $(this);
        $btn.prop("disabled", true).text("Resetting...");

        $.ajax({
          url: nexifymySecurity.ajaxUrl,
          type: "POST",
          dataType: "json",
          data: {
            action: "nexifymy_reset_ai_learning",
            nonce: nexifymySecurity.nonce,
          },
          success: function (response) {
            if (response && response.success) {
              alert("AI learning data reset successfully.");
              window.location.reload();
              return;
            }

            $btn
              .prop("disabled", false)
              .html('<span class="dashicons dashicons-trash"></span> Reset Learning');
          },
          error: function () {
            $btn
              .prop("disabled", false)
              .html('<span class="dashicons dashicons-trash"></span> Reset Learning');
          },
        });
      });

    $("#save-ai-settings")
      .off("click.nmsAi")
      .on("click.nmsAi", function () {
        var $btn = $(this);
        var $status = $("#ai-settings-status");

        var settings = {
          enabled: $("#ai-enabled").is(":checked"),
          insider_threat_enabled: $("#ai-insider-enabled").is(":checked"),
          insider_threat_threshold: clampInt(
            $("#ai-insider-threshold").val(),
            60,
            1,
            100,
          ),
          data_exfiltration_enabled: $("#ai-exfiltration-enabled").is(":checked"),
          exfiltration_threshold: clampInt(
            $("#ai-exfiltration-threshold").val(),
            60,
            1,
            100,
          ),
          exfiltration_baseline_days: clampInt(
            $("#ai-exfiltration-baseline-days").val(),
            30,
            1,
            365,
          ),
          session_risk_threshold: clampInt(
            $("#ai-session-risk-threshold").val(),
            60,
            1,
            100,
          ),
          zero_trust_reauth_interval: clampInt(
            $("#ai-reauth-interval").val(),
            900,
            60,
            86400,
          ),
          zero_trust_risk_spike_threshold: clampInt(
            $("#ai-risk-spike-threshold").val(),
            20,
            1,
            100,
          ),
        };

        $("#ai-insider-threshold").val(settings.insider_threat_threshold);
        $("#ai-exfiltration-threshold").val(settings.exfiltration_threshold);
        $("#ai-exfiltration-baseline-days").val(settings.exfiltration_baseline_days);
        $("#ai-session-risk-threshold").val(settings.session_risk_threshold);
        $("#ai-reauth-interval").val(settings.zero_trust_reauth_interval);
        $("#ai-risk-spike-threshold").val(settings.zero_trust_risk_spike_threshold);

        $btn.prop("disabled", true);
        $status
          .removeClass("nms-temp-feedback--ok nms-temp-feedback--error")
          .text("Saving...");

        $.ajax({
          url: nexifymySecurity.ajaxUrl,
          type: "POST",
          dataType: "json",
          data: {
            action: "nexifymy_save_module_settings",
            nonce: nexifymySecurity.nonce,
            module: "ai_detection",
            settings: settings,
          },
          success: function (response) {
            if (response && response.success) {
              $status
                .addClass("nms-temp-feedback--ok")
                .text("AI settings saved.");
              $("#refresh-ai-status").trigger("click");
              return;
            }

            $status
              .addClass("nms-temp-feedback--error")
              .text(
                "Save failed: " + ((response && response.data) || "Unknown error"),
              );
          },
          error: function () {
            $status
              .addClass("nms-temp-feedback--error")
              .text("Network error while saving AI settings.");
          },
          complete: function () {
            $btn.prop("disabled", false);
          },
        });
      });

    loadAiThreats();
  }

  function initTempAccessHandlers() {
    if (!$("#btn-request-temp-access").length && !$("#temp-permissions-table").length) {
      return;
    }

    var isAdmin =
      String($(".nms-temp-access-page").data("temp-access-admin") || "0") === "1";

    function setFeedback($el, message, isSuccess) {
      if (!$el.length) {
        return;
      }
      $el
        .removeClass("nms-temp-feedback--ok nms-temp-feedback--error")
        .addClass(isSuccess ? "nms-temp-feedback--ok" : "nms-temp-feedback--error")
        .text(message || "");
    }

    function statusBadge(status) {
      var safeStatus = String(status || "unknown").toLowerCase();
      var map = {
        pending: "nms-temp-status nms-temp-status--pending",
        active: "nms-temp-status nms-temp-status--active",
        expired: "nms-temp-status nms-temp-status--expired",
        revoked: "nms-temp-status nms-temp-status--revoked",
      };
      var cssClass = map[safeStatus] || "nms-temp-status";
      return '<span class="' + cssClass + '">' + escapeHtml(safeStatus) + "</span>";
    }

    function roleDisplay(role) {
      if (!role) {
        return "";
      }
      return role.charAt(0).toUpperCase() + role.slice(1);
    }

    function sortGrants(grants) {
      var order = {
        pending: 1,
        active: 2,
        expired: 3,
        revoked: 4,
      };
      return grants.slice().sort(function (a, b) {
        var aRank = order[a.status] || 99;
        var bRank = order[b.status] || 99;
        if (aRank !== bRank) {
          return aRank - bRank;
        }
        return String(b.granted_at || "").localeCompare(String(a.granted_at || ""));
      });
    }

    function renderGrants(grants) {
      var $body = $("#temp-permissions-body");
      if (!$body.length) {
        return;
      }

      if (!Array.isArray(grants) || grants.length === 0) {
        $body.html(
          '<tr><td colspan="9" class="nms-empty-state">No temporary access requests found.</td></tr>',
        );
        return;
      }

      var html = "";
      sortGrants(grants).forEach(function (grant) {
        var actions = "";

        if (isAdmin && grant.can_approve) {
          actions +=
            '<button type="button" class="button button-small nms-temp-approve" data-id="' +
            Number(grant.id || 0) +
            '" data-role="' +
            escapeHtml(grant.elevated_role || "administrator") +
            '">' +
            "Approve" +
            "</button> ";
        }

        if (isAdmin && grant.can_revoke) {
          actions +=
            '<button type="button" class="button button-small nms-temp-revoke" data-id="' +
            Number(grant.id || 0) +
            '">' +
            "Revoke" +
            "</button>";
        }

        if (!actions) {
          actions = '<span class="description">No actions</span>';
        }

        html += "<tr>";
        html +=
          "<td><strong>" +
          escapeHtml(grant.user_login || "Unknown") +
          "</strong><br><span class=\"description\">" +
          escapeHtml(grant.user_email || "") +
          "</span></td>";
        html += "<td>" + escapeHtml(roleDisplay(grant.original_role)) + "</td>";
        html += "<td>" + escapeHtml(roleDisplay(grant.elevated_role)) + "</td>";
        html += "<td>" + escapeHtml(grant.granted_at || "") + "</td>";
        html += "<td>" + escapeHtml(grant.expires_at || "") + "</td>";
        html += "<td>" + escapeHtml(grant.granted_by || "Pending") + "</td>";
        html += "<td>" + escapeHtml(grant.reason || "") + "</td>";
        html += "<td>" + statusBadge(grant.status) + "</td>";
        html += '<td class="nms-temp-actions">' + actions + "</td>";
        html += "</tr>";
      });

      $body.html(html);
    }

    function loadTempPermissions() {
      if (!isAdmin || !$("#temp-permissions-table").length) {
        return;
      }

      var $status = $("#temp-access-table-status");
      setFeedback($status, "Refreshing...", true);

      $.ajax({
        url: nexifymySecurity.ajaxUrl,
        type: "POST",
        dataType: "json",
        data: {
          action: "nexifymy_get_temp_permissions",
          nonce: nexifymySecurity.nonce,
        },
        success: function (response) {
          if (response && response.success && response.data) {
            renderGrants(response.data.grants || []);
            setFeedback($status, "Queue refreshed.", true);
            return;
          }
          setFeedback(
            $status,
            "Unable to load temporary permissions.",
            false,
          );
        },
        error: function () {
          setFeedback(
            $status,
            "Network error while loading temporary permissions.",
            false,
          );
        },
      });
    }

    $("#btn-request-temp-access")
      .off("click.nmsTempAccess")
      .on("click.nmsTempAccess", function () {
        var $btn = $(this);
        var $msg = $("#temp-access-request-msg");
        var reason = $.trim($("#temp-access-reason").val());
        var requestedRole = $("#temp-access-requested-role").val();
        var duration = clampInt($("#temp-access-duration").val(), 60, 5, 1440);

        if (!reason) {
          setFeedback($msg, "Reason is required.", false);
          return;
        }

        $btn.prop("disabled", true);
        setFeedback($msg, "Submitting request...", true);

        $.ajax({
          url: nexifymySecurity.ajaxUrl,
          type: "POST",
          dataType: "json",
          data: {
            action: "nexifymy_request_temp_access",
            nonce: nexifymySecurity.nonce,
            reason: reason,
            duration: duration,
            requested_role: requestedRole,
          },
          success: function (response) {
            if (response && response.success) {
              setFeedback(
                $msg,
                (response.data && response.data.message) || "Request submitted.",
                true,
              );
              $("#temp-access-reason").val("");
              if (isAdmin) {
                loadTempPermissions();
              }
              return;
            }

            setFeedback(
              $msg,
              "Request failed: " + ((response && response.data) || "Unknown error"),
              false,
            );
          },
          error: function () {
            setFeedback($msg, "Network error while submitting request.", false);
          },
          complete: function () {
            $btn.prop("disabled", false);
          },
        });
      });

    $("#btn-refresh-temp-perms")
      .off("click.nmsTempAccess")
      .on("click.nmsTempAccess", function () {
        loadTempPermissions();
      });

    $(document)
      .off("click.nmsTempAccess", ".nms-temp-approve")
      .on("click.nmsTempAccess", ".nms-temp-approve", function () {
        var $btn = $(this);
        var requestId = Number($btn.data("id") || 0);
        var requestedRole = String($btn.data("role") || "administrator").toLowerCase();
        var approvedInput = window.prompt(
          "Approve role (administrator/editor):",
          requestedRole,
        );
        if (approvedInput === null) {
          return;
        }

        var approvedRole = String(approvedInput).toLowerCase().trim();
        if (approvedRole !== "administrator" && approvedRole !== "editor") {
          approvedRole = requestedRole === "editor" ? "editor" : "administrator";
        }

        var durationInput = window.prompt(
          "Approval duration in minutes (optional override):",
          "60",
        );
        var duration = clampInt(durationInput, 60, 5, 1440);

        if (requestId <= 0) {
          return;
        }

        $btn.prop("disabled", true);
        setFeedback($("#temp-access-table-status"), "Approving request...", true);

        $.ajax({
          url: nexifymySecurity.ajaxUrl,
          type: "POST",
          dataType: "json",
          data: {
            action: "nexifymy_approve_temp_access",
            nonce: nexifymySecurity.nonce,
            request_id: requestId,
            approved_role: approvedRole,
            duration: duration,
          },
          success: function (response) {
            if (response && response.success) {
              setFeedback(
                $("#temp-access-table-status"),
                (response.data && response.data.message) || "Request approved.",
                true,
              );
              loadTempPermissions();
              return;
            }

            setFeedback(
              $("#temp-access-table-status"),
              "Approval failed: " + ((response && response.data) || "Unknown error"),
              false,
            );
          },
          error: function () {
            setFeedback(
              $("#temp-access-table-status"),
              "Network error while approving request.",
              false,
            );
          },
          complete: function () {
            $btn.prop("disabled", false);
          },
        });
      });

    $(document)
      .off("click.nmsTempAccess", ".nms-temp-revoke")
      .on("click.nmsTempAccess", ".nms-temp-revoke", function () {
        var $btn = $(this);
        var grantId = Number($btn.data("id") || 0);
        if (grantId <= 0) {
          return;
        }
        if (!window.confirm("Revoke this temporary permission?")) {
          return;
        }

        $btn.prop("disabled", true);
        setFeedback($("#temp-access-table-status"), "Revoking permission...", true);

        $.ajax({
          url: nexifymySecurity.ajaxUrl,
          type: "POST",
          dataType: "json",
          data: {
            action: "nexifymy_revoke_temp_access",
            nonce: nexifymySecurity.nonce,
            grant_id: grantId,
          },
          success: function (response) {
            if (response && response.success) {
              setFeedback(
                $("#temp-access-table-status"),
                (response.data && response.data.message) ||
                  "Permission revoked successfully.",
                true,
              );
              loadTempPermissions();
              return;
            }

            setFeedback(
              $("#temp-access-table-status"),
              "Revoke failed: " + ((response && response.data) || "Unknown error"),
              false,
            );
          },
          error: function () {
            setFeedback(
              $("#temp-access-table-status"),
              "Network error while revoking permission.",
              false,
            );
          },
          complete: function () {
            $btn.prop("disabled", false);
          },
        });
      });

    loadTempPermissions();
  }

  function initAnalyticsTabCharts() {
    if (typeof Chart === "undefined") {
      return;
    }

    var $data = $("#nms-analytics-chart-data");
    if (!$data.length) {
      return;
    }

    var labels = parseJsonAttr($data, "data-labels", []);
    var blocked = parseJsonAttr($data, "data-blocked", []);
    var threats = parseJsonAttr($data, "data-threats", []);
    var logins = parseJsonAttr($data, "data-logins", []);

    var threatsCanvas = document.getElementById("nms-threats-chart");
    if (threatsCanvas) {
      new Chart(threatsCanvas.getContext("2d"), {
        type: "line",
        data: {
          labels: labels,
          datasets: [
            {
              label: "Threats Blocked",
              data: blocked,
              borderColor: "#4f46e5",
              backgroundColor: "rgba(79, 70, 229, 0.1)",
              borderWidth: 2,
              tension: 0.4,
              fill: true,
              pointBackgroundColor: "#ffffff",
              pointBorderColor: "#4f46e5",
              pointRadius: 4,
            },
            {
              label: "Malware Detected",
              data: threats,
              borderColor: "#dc2626",
              backgroundColor: "rgba(220, 38, 38, 0.05)",
              borderWidth: 2,
              tension: 0.4,
              fill: false,
              borderDash: [5, 5],
            },
          ],
        },
        options: {
          responsive: true,
          plugins: {
            legend: { position: "top" },
            tooltip: {
              mode: "index",
              intersect: false,
              backgroundColor: "rgba(255, 255, 255, 0.9)",
              titleColor: "#1e293b",
              bodyColor: "#64748b",
              borderColor: "#e2e8f0",
              borderWidth: 1,
            },
          },
          scales: {
            y: { beginAtZero: true, grid: { borderDash: [2, 2] } },
            x: { grid: { display: false } },
          },
        },
      });
    }

    var loginCanvas = document.getElementById("nms-logins-chart");
    if (loginCanvas) {
      new Chart(loginCanvas.getContext("2d"), {
        type: "bar",
        data: {
          labels: labels,
          datasets: [
            {
              label: "Failed Logins",
              data: logins,
              backgroundColor: "#f59e0b",
              borderRadius: 4,
            },
          ],
        },
        options: {
          responsive: true,
          plugins: { legend: { display: false } },
          scales: {
            y: { beginAtZero: true },
          },
        },
      });
    }
  }

  function initP2pHandlers() {
    if (!$("#p2p-settings-form").length) {
      return;
    }

    function setPeerStatus(type, message) {
      var className = "info";
      if (type === "success" || type === "danger" || type === "warning") {
        className = type;
      }
      $("#p2p-peer-status").html(
        '<span class="nms-inline-status nms-inline-status-' +
          className +
          '">' +
          escapeHtml(message) +
          "</span>",
      );
    }

    function fallbackCopy(text) {
      var $temp = $("<textarea>");
      $("body").append($temp);
      $temp.val(text).trigger("select");
      document.execCommand("copy");
      $temp.remove();
    }

    $("#p2p-threshold-slider")
      .off("input.nmsP2P")
      .on("input.nmsP2P", function () {
        $("#threshold-value").text($(this).val());
      });

    $(".nms-copy-node-key")
      .off("click.nmsP2P")
      .on("click.nmsP2P", function () {
        var key = $(this).data("key");
        if (!key) {
          return;
        }

        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard
            .writeText(key)
            .then(function () {
              setPeerStatus("success", "Node key copied to clipboard.");
            })
            .catch(function () {
              fallbackCopy(key);
              setPeerStatus("success", "Node key copied to clipboard.");
            });
        } else {
          fallbackCopy(key);
          setPeerStatus("success", "Node key copied to clipboard.");
        }
      });

    var $modal = $("#add-peer-modal");
    $("#add-peer-btn")
      .off("click")
      .on("click.nmsP2P", function () {
        if ($modal.length) {
          $modal.fadeIn(150);
        }
      });

    $(".nms-modal-close, .cancel-peer-btn")
      .off("click")
      .on("click.nmsP2P", function () {
        if ($modal.length) {
          $modal.fadeOut(150);
        }
      });

    $modal.off("click.nmsP2P").on("click.nmsP2P", function (event) {
      if (event.target === this) {
        $modal.fadeOut(150);
      }
    });

    $("#add-peer-form")
      .off("submit.nmsP2P")
      .on("submit.nmsP2P", function (event) {
        event.preventDefault();

        var $form = $(this);
        var $btn = $form.find('button[type="submit"]');
        var originalText = $btn.text();
        var addPeerNonce =
          $form.find('input[name="nexifymy_add_peer_nonce"]').val() ||
          nexifymySecurity.nonce;

        $btn.prop("disabled", true).text("Adding...");

        $.ajax({
          url: nexifymySecurity.ajaxUrl,
          method: "POST",
          dataType: "json",
          data: {
            action: "nexifymy_add_peer",
            nonce: addPeerNonce,
            peer_url: $("#peer_url").val(),
            peer_api_key: $("#peer_api_key").val(),
            peer_label: $("#peer_label").val(),
          },
          success: function (response) {
            if (response && response.success) {
              alert("Peer added successfully.");
              window.location.reload();
              return;
            }

            alert(
              "Error: " + ((response && response.data) || "Unknown error"),
            );
            $btn.prop("disabled", false).text(originalText);
          },
          error: function () {
            alert("Network error.");
            $btn.prop("disabled", false).text(originalText);
          },
        });
      });

    $(document)
      .off("click", ".delete-peer-btn")
      .on("click.nmsP2P", ".delete-peer-btn", function () {
        if (!window.confirm("Are you sure you want to remove this peer?")) {
          return;
        }

        var peerId = $(this).data("peer-id");

        $.ajax({
          url: nexifymySecurity.ajaxUrl,
          method: "POST",
          dataType: "json",
          data: {
            action: "nexifymy_remove_peer",
            nonce: nexifymySecurity.nonce,
            peer_id: peerId,
          },
          success: function (response) {
            if (response && response.success) {
              window.location.reload();
              return;
            }

            alert("Error: " + ((response && response.data) || "Unknown error"));
          },
          error: function () {
            alert("Network error.");
          },
        });
      });

    $("#p2p-settings-form")
      .off("submit.nmsP2P")
      .on("submit.nmsP2P", function (event) {
        event.preventDefault();

        var $form = $(this);
        var $btn = $form.find('button[type="submit"]');
        var originalText = $btn.text();
        var nonce =
          $form.find('input[name="nexifymy_p2p_nonce"]').val() ||
          nexifymySecurity.nonce;

        $btn.prop("disabled", true).text("Saving...");

        $.ajax({
          url: nexifymySecurity.ajaxUrl,
          method: "POST",
          dataType: "json",
          data: {
            action: "nexifymy_save_p2p_settings",
            nonce: nonce,
            p2p_enabled: $("#p2p_enabled").is(":checked") ? 1 : 0,
            p2p_broadcast_enabled: $("input[name='p2p_broadcast_enabled']").is(
              ":checked",
            )
              ? 1
              : 0,
            p2p_trust_threshold: $("input[name='p2p_trust_threshold']").val(),
          },
          success: function (response) {
            if (response && response.success) {
              alert("Settings saved successfully.");
            } else {
              alert(
                "Error: " + ((response && response.data) || "Unknown error"),
              );
            }
            $btn.prop("disabled", false).text(originalText);
          },
          error: function () {
            alert("Network error.");
            $btn.prop("disabled", false).text(originalText);
          },
        });
      });
  }

  function initGenericTemplateHandlers() {
    $(document)
      .off("click.nmsTemplate", ".nms-stop-propagation")
      .on("click.nmsTemplate", ".nms-stop-propagation", function (event) {
        event.stopPropagation();
      });

    $(document)
      .off("click.nmsTemplate", ".nms-open-page-tab")
      .on("click.nmsTemplate", ".nms-open-page-tab", function () {
        var tab = $(this).data("page-tab");
        if (!tab) {
          return;
        }
        $('.nms-page-tab[data-tab="' + tab + '"]').trigger("click");
      });
  }

  $(function () {
    if (!window.nexifymySecurity) {
      return;
    }

    initTrafficAnalyticsWidget();
    initCaptchaProviderToggle();
    initSupplyChainHandlers();
    initComplianceHandlers();
    initAiThreatHandlers();
    initTempAccessHandlers();
    initAnalyticsTabCharts();
    initP2pHandlers();
    initGenericTemplateHandlers();
  });
})(jQuery);
