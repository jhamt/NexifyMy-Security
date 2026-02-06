<?php
/**
 * Site Health Calculator Module.
 * Calculates overall site security health score and generates recommendations.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_Site_Health_Calculator {

	/**
	 * Health status thresholds.
	 */
	const HEALTH_EXCELLENT = 90;
	const HEALTH_GOOD = 70;
	const HEALTH_AT_RISK = 50;
	const HEALTH_CRITICAL = 0;

	/**
	 * Impact weights for each classification tier.
	 */
	const IMPACT_CONFIRMED_MALWARE = 30;
	const IMPACT_SUSPICIOUS_CODE = 10;
	const IMPACT_SECURITY_VULNERABILITY = 15;
	const IMPACT_CODE_SMELL = 2;

	/**
	 * Calculate site health metrics from scan results.
	 *
	 * @param array $scan_results Scan results array.
	 * @return array Health metrics and summary.
	 */
	public function calculate_health_metrics( $scan_results ) {
		$files_scanned = isset( $scan_results['files_scanned'] ) ? (int) $scan_results['files_scanned'] : 0;
		$threats = isset( $scan_results['threats'] ) ? $scan_results['threats'] : array();

		// Count threats by classification
		$threat_counts = $this->count_threats_by_classification( $threats );

		// Calculate total affected files
		$files_with_threats = count( $threats );
		$clean_files = max( 0, $files_scanned - $files_with_threats );

		// Calculate percentages
		$clean_percentage = $files_scanned > 0 ? ( $clean_files / $files_scanned ) * 100 : 100;
		$affected_percentage = $files_scanned > 0 ? ( $files_with_threats / $files_scanned ) * 100 : 0;

		// Calculate health score
		$health_score = intval( $clean_percentage );

		// Determine health status
		$health_status = $this->determine_health_status( $health_score );

		// Calculate threat breakdown percentages
		$threat_percentages = $this->calculate_threat_percentages( $threat_counts, $files_scanned );

		// Generate recommendation
		$recommendation = $this->generate_recommendation( $health_score, $threat_counts );

		return array(
			'health_score'         => $health_score,
			'health_status'        => $health_status,
			'files_scanned'        => $files_scanned,
			'clean_files'          => $clean_files,
			'clean_percentage'     => round( $clean_percentage, 2 ),
			'affected_files'       => $files_with_threats,
			'affected_percentage'  => round( $affected_percentage, 2 ),
			'threat_counts'        => $threat_counts,
			'threat_percentages'   => $threat_percentages,
			'recommendation'       => $recommendation,
			'calculated_at'        => current_time( 'mysql' ),
		);
	}

	/**
	 * Count threats by classification.
	 *
	 * @param array $threats Array of threat files.
	 * @return array Counts by classification.
	 */
	private function count_threats_by_classification( $threats ) {
		$counts = array(
			'CONFIRMED_MALWARE'        => 0,
			'SUSPICIOUS_CODE'          => 0,
			'SECURITY_VULNERABILITY'   => 0,
			'CODE_SMELL'               => 0,
			'UNCLASSIFIED'             => 0,
		);

		foreach ( $threats as $threat_file ) {
			// Each file may have multiple threats, use highest classification
			$file_classification = 'UNCLASSIFIED';
			$classification_priority = array(
				'CONFIRMED_MALWARE'      => 4,
				'SUSPICIOUS_CODE'        => 3,
				'SECURITY_VULNERABILITY' => 2,
				'CODE_SMELL'             => 1,
			);

			$highest_priority = 0;

			if ( isset( $threat_file['threats'] ) && is_array( $threat_file['threats'] ) ) {
				foreach ( $threat_file['threats'] as $threat ) {
					$classification = isset( $threat['classification'] ) ? $threat['classification'] : 'UNCLASSIFIED';
					$priority = isset( $classification_priority[ $classification ] ) ? $classification_priority[ $classification ] : 0;

					if ( $priority > $highest_priority ) {
						$highest_priority = $priority;
						$file_classification = $classification;
					}
				}
			}

			// Increment count for this file's highest classification
			if ( isset( $counts[ $file_classification ] ) ) {
				$counts[ $file_classification ]++;
			}
		}

		return $counts;
	}

	/**
	 * Calculate health score (0-100).
	 *
	 * Algorithm:
	 * Start with 100, subtract impact for each threat type.
	 * Floor at 0 (cannot go negative).
	 *
	 * @param array $threat_counts Threat counts by classification.
	 * @return int Health score (0-100).
	 */
	private function calculate_health_score( $threat_counts ) {
		$score = 100;

		// Subtract impact for each threat type
		$score -= $threat_counts['CONFIRMED_MALWARE'] * self::IMPACT_CONFIRMED_MALWARE;
		$score -= $threat_counts['SUSPICIOUS_CODE'] * self::IMPACT_SUSPICIOUS_CODE;
		$score -= $threat_counts['SECURITY_VULNERABILITY'] * self::IMPACT_SECURITY_VULNERABILITY;
		$score -= $threat_counts['CODE_SMELL'] * self::IMPACT_CODE_SMELL;

		// Floor at 0
		$score = max( 0, $score );

		return (int) $score;
	}

	/**
	 * Determine health status based on score.
	 *
	 * @param int $health_score Health score (0-100).
	 * @return string Health status.
	 */
	private function determine_health_status( $health_score ) {
		if ( $health_score >= self::HEALTH_EXCELLENT ) {
			return 'excellent';
		} elseif ( $health_score >= self::HEALTH_GOOD ) {
			return 'good';
		} elseif ( $health_score >= self::HEALTH_AT_RISK ) {
			return 'at_risk';
		}

		return 'critical';
	}

	/**
	 * Calculate threat breakdown percentages.
	 *
	 * @param array $threat_counts  Threat counts.
	 * @param int   $files_scanned Total files scanned.
	 * @return array Percentages by classification.
	 */
	private function calculate_threat_percentages( $threat_counts, $files_scanned ) {
		$percentages = array();

		if ( $files_scanned === 0 ) {
			return $percentages;
		}

		foreach ( $threat_counts as $classification => $count ) {
			$percentages[ $classification ] = round( ( $count / $files_scanned ) * 100, 2 );
		}

		return $percentages;
	}

	/**
	 * Generate actionable recommendation based on health metrics.
	 *
	 * @param int   $health_score  Health score.
	 * @param array $threat_counts Threat counts.
	 * @return string Recommendation text.
	 */
	private function generate_recommendation( $health_score, $threat_counts ) {
		$recommendations = array();

		// Critical threats
		if ( $threat_counts['CONFIRMED_MALWARE'] > 0 ) {
			$recommendations[] = sprintf(
				'<i class="fas fa-exclamation-circle" style="color: #dc3545;"></i> <strong>URGENT:</strong> %d confirmed malware file%s detected. Review and quarantine immediately.',
				$threat_counts['CONFIRMED_MALWARE'],
				$threat_counts['CONFIRMED_MALWARE'] > 1 ? 's' : ''
			);
		}

		// Suspicious code
		if ( $threat_counts['SUSPICIOUS_CODE'] > 0 ) {
			$recommendations[] = sprintf(
				'<i class="fas fa-exclamation-triangle" style="color: #ff9800;"></i> %d suspicious code pattern%s found. Manual review recommended.',
				$threat_counts['SUSPICIOUS_CODE'],
				$threat_counts['SUSPICIOUS_CODE'] > 1 ? 's' : ''
			);
		}

		// Security vulnerabilities
		if ( $threat_counts['SECURITY_VULNERABILITY'] > 0 ) {
			$recommendations[] = sprintf(
				'<i class="fas fa-tools" style="color: #ffc107;"></i> %d security vulnerabilit%s detected. Update plugins/themes to patched versions.',
				$threat_counts['SECURITY_VULNERABILITY'],
				$threat_counts['SECURITY_VULNERABILITY'] > 1 ? 'ies' : 'y'
			);
		}

		// Code smells (informational)
		if ( $threat_counts['CODE_SMELL'] > 0 && $health_score >= self::HEALTH_GOOD ) {
			$recommendations[] = sprintf(
				'<i class="fas fa-info-circle" style="color: #007bff;"></i> %d code quality issue%s found. Review if unexpected.',
				$threat_counts['CODE_SMELL'],
				$threat_counts['CODE_SMELL'] > 1 ? 's' : ''
			);
		}

		// Health status recommendations
		if ( $health_score >= self::HEALTH_EXCELLENT && empty($threat_counts['CONFIRMED_MALWARE']) ) {
			$recommendations[] = '<i class="fas fa-check-circle" style="color: #28a745;"></i> <strong>Excellent security health!</strong> Your site is clean and secure.';
		} elseif ( $health_score >= self::HEALTH_GOOD && empty($threat_counts['CONFIRMED_MALWARE']) ) {
			$recommendations[] = '<i class="fas fa-thumbs-up" style="color: #ffc107;"></i> <strong>Good security health.</strong> Address findings to maintain security.';
		} elseif ( $health_score >= self::HEALTH_AT_RISK && empty($threat_counts['CONFIRMED_MALWARE']) ) {
			$recommendations[] = '<i class="fas fa-exclamation-triangle" style="color: #ff9800;"></i> <strong>Site security at risk.</strong> Address threats as soon as possible.';
		} else {
			$recommendations[] = '<i class="fas fa-radiation" style="color: #dc3545;"></i> <strong>CRITICAL SECURITY RISK!</strong> Immediate action required.';
		}

		return implode( '<br>', $recommendations );
	}

	/**
	 * Get health status display data (icon, color, label).
	 *
	 * @param string $health_status Health status.
	 * @return array Display data.
	 */
	public function get_health_status_display( $health_status ) {
		$display_map = array(
			'excellent' => array(
				'icon'  => 'fas fa-check',
				'color' => '#28a745', // Green
				'label' => 'Excellent',
				'class' => 'status-excellent',
			),
			'good' => array(
				'icon'  => 'fas fa-check',
				'color' => '#ffc107', // Yellow
				'label' => 'Good',
				'class' => 'status-good',
			),
			'at_risk' => array(
				'icon'  => 'fas fa-exclamation-triangle',
				'color' => '#ff9800', // Orange
				'label' => 'At Risk',
				'class' => 'status-at-risk',
			),
			'critical' => array(
				'icon'  => 'fas fa-times',
				'color' => '#dc3545', // Red
				'label' => 'Critical',
				'class' => 'status-critical',
			),
		);

		return isset( $display_map[ $health_status ] ) ? $display_map[ $health_status ] : $display_map['at_risk'];
	}

	/**
	 * Get classification display data (badge color, icon, label).
	 *
	 * @param string $classification Classification tier.
	 * @return array Display data.
	 */
	public function get_classification_display( $classification ) {
		$display_map = array(
			'CONFIRMED_MALWARE' => array(
				'icon'  => 'fas fa-circle',
				'color' => '#dc3545', // Red
				'label' => 'Confirmed Malware',
				'class' => 'badge-danger',
			),
			'SUSPICIOUS_CODE' => array(
				'icon'  => 'fas fa-circle',
				'color' => '#ff9800', // Orange
				'label' => 'Suspicious Code',
				'class' => 'badge-warning',
			),
			'SECURITY_VULNERABILITY' => array(
				'icon'  => 'fas fa-circle',
				'color' => '#ffc107', // Yellow
				'label' => 'Security Vulnerability',
				'class' => 'badge-warning',
			),
			'CODE_SMELL' => array(
				'icon'  => 'fas fa-circle',
				'color' => '#007bff', // Blue
				'label' => 'Code Quality Issue',
				'class' => 'badge-info',
			),
			'CLEAN' => array(
				'icon'  => 'fas fa-check',
				'color' => '#28a745', // Green
				'label' => 'Clean',
				'class' => 'badge-success',
			),
		);

		return isset( $display_map[ $classification ] ) ? $display_map[ $classification ] : array(
			'icon'  => 'fas fa-question',
			'color' => '#6c757d',
			'label' => 'Unknown',
			'class' => 'badge-secondary',
		);
	}

	/**
	 * Format health summary for display (HTML).
	 *
	 * @param array $health_metrics Health metrics array.
	 * @return string HTML summary card.
	 */
	public function format_health_summary_html( $health_metrics ) {
		$health_score = $health_metrics['health_score'];
		$health_status = $health_metrics['health_status'];
		$display = $this->get_health_status_display( $health_status );

		$progress_width = $health_score;
		$progress_color = $display['color'];

		$html = sprintf(
			'<div class="health-summary-card" style="border-left: 4px solid %s; padding: 20px; background: #f9f9f9; margin-bottom: 20px;">',
			$progress_color
		);

		// Header
		$html .= sprintf(
			'<h3><i class="fas fa-heartbeat" style="color: %s;"></i> Site Security Health: %d/100 <span style="color: %s;">(%s)</span></h3>',
			$progress_color,
			$health_score,
			$progress_color,
			$display['label']
		);

		// Progress bar
		$html .= sprintf(
			'<div class="health-progress" style="background: #e0e0e0; height: 20px; border-radius: 10px; margin-bottom: 15px;">' .
			'<div style="width: %d%%; height: 100%%; background: %s; border-radius: 10px; transition: width 0.3s;"></div></div>',
			$progress_width,
			$progress_color
		);

		// Stats
		$html .= sprintf(
			'<p><strong>Files Scanned:</strong> %s<br>' .
			'<strong>Clean Files:</strong> %s (%s%%)<br>' .
			'<strong>Affected Files:</strong> %s (%s%%)</p>',
			number_format( $health_metrics['files_scanned'] ),
			number_format( $health_metrics['clean_files'] ),
			$health_metrics['clean_percentage'],
			number_format( $health_metrics['affected_files'] ),
			$health_metrics['affected_percentage']
		);

		// Threat breakdown
		if ( $health_metrics['affected_files'] > 0 ) {
			$html .= '<h4>Threat Breakdown:</h4><ul>';

			$counts = $health_metrics['threat_counts'];
			$percentages = $health_metrics['threat_percentages'];

			if ( $counts['CONFIRMED_MALWARE'] > 0 ) {
				$html .= sprintf(
					'<li style="color: #dc3545;"><i class="fas fa-times-circle"></i> <strong>Confirmed Malware:</strong> %d file%s (%s%%)</li>',
					$counts['CONFIRMED_MALWARE'],
					$counts['CONFIRMED_MALWARE'] > 1 ? 's' : '',
					$percentages['CONFIRMED_MALWARE']
				);
			}

			if ( $counts['SUSPICIOUS_CODE'] > 0 ) {
				$html .= sprintf(
					'<li style="color: #ff9800;"><i class="fas fa-exclamation-circle"></i> <strong>Suspicious Code:</strong> %d file%s (%s%%)</li>',
					$counts['SUSPICIOUS_CODE'],
					$counts['SUSPICIOUS_CODE'] > 1 ? 's' : '',
					$percentages['SUSPICIOUS_CODE']
				);
			}

			if ( $counts['SECURITY_VULNERABILITY'] > 0 ) {
				$html .= sprintf(
					'<li style="color: #ffc107;"><i class="fas fa-bug"></i> <strong>Security Vulnerabilities:</strong> %d file%s (%s%%)</li>',
					$counts['SECURITY_VULNERABILITY'],
					$counts['SECURITY_VULNERABILITY'] > 1 ? 's' : '',
					$percentages['SECURITY_VULNERABILITY']
				);
			}

			if ( $counts['CODE_SMELL'] > 0 ) {
				$html .= sprintf(
					'<li style="color: #007bff;"><i class="fas fa-code"></i> <strong>Code Quality Issues:</strong> %d file%s (%s%%)</li>',
					$counts['CODE_SMELL'],
					$counts['CODE_SMELL'] > 1 ? 's' : '',
					$percentages['CODE_SMELL']
				);
			}

			$html .= '</ul>';
		}

		// Recommendation
		$html .= sprintf(
			'<div class="health-recommendation" style="margin-top: 15px; padding: 10px; background: #fff; border-radius: 5px;">%s</div>',
			$health_metrics['recommendation']
		);

		$html .= '</div>';

		return $html;
	}
}
