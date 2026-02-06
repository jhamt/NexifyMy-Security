<?php
/**
 * Reputation Checker Module.
 * Checks file reputation against WordPress.org, malware hash databases, and allowlists.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_Reputation_Checker {

	/**
	 * Cache duration for reputation checks (24 hours).
	 */
	const CACHE_DURATION = 86400;

	/**
	 * WordPress.org API endpoints.
	 */
	const WP_ORG_PLUGIN_API = 'https://api.wordpress.org/plugins/info/1.0/';
	const WP_ORG_THEME_API = 'https://api.wordpress.org/themes/info/1.0/';

	/**
	 * Known safe plugins (top WordPress.org plugins with >1M installs).
	 * @var array
	 */
	private $known_safe_plugins = array(
		// Security & Performance
		'wordfence', 'sucuri-scanner', 'jetpack', 'akismet', 'ithemes-security',
		'wp-super-cache', 'w3-total-cache', 'autoptimize', 'wp-optimize',

		// SEO
		'wordpress-seo', 'all-in-one-seo-pack', 'google-sitemap-generator',

		// E-commerce
		'woocommerce', 'woocommerce-gateway-stripe', 'woocommerce-paypal-payments',

		// Forms & Contact
		'contact-form-7', 'wpforms-lite', 'ninja-forms', 'formidable', 'mailchimp-for-wp',

		// Backup
		'updraftplus', 'backwpup', 'duplicator', 'all-in-one-wp-migration',

		// Page Builders
		'elementor', 'beaver-builder-lite-version', 'siteorigin-panels', 'wp-page-builder',

		// Media & Gallery
		'smush', 'envira-gallery-lite', 'nextgen-gallery',

		// Utilities
		'classic-editor', 'gutenberg', 'advanced-custom-fields', 'duplicate-post',
		'really-simple-ssl', 'redirection', 'query-monitor', 'wp-migrate-db',
		'loco-translate', 'wp-mail-smtp', 'user-role-editor',

		// Social & Analytics
		'google-analytics-for-wordpress', 'simple-share-buttons-adder', 'addtoany',
	);

	/**
	 * Known malware hashes (MD5).
	 * TODO: Integrate with abuse.ch/VirusTotal APIs for live updates.
	 * @var array
	 */
	private $known_malware_hashes = array(
		// Common webshell hashes (c99, wso, r57, etc.)
		'5f4dcc3b5aa765d61d8327deb882cf99' => 'C99 Shell',
		'd41d8cd98f00b204e9800998ecf8427e' => 'Empty file (suspicious)',
		// More hashes can be added via signature updates
	);

	/**
	 * Check plugin reputation.
	 *
	 * @param string $filepath File path.
	 * @return array Reputation data with score and details.
	 */
	public function check_plugin_reputation( $filepath ) {
		$plugin_slug = $this->extract_plugin_slug( $filepath );

		if ( empty( $plugin_slug ) ) {
			return array(
				'has_reputation' => false,
				'score'          => 0,
				'reason'         => 'Not a plugin file',
			);
		}

		// Check if in known safe plugins list
		if ( in_array( $plugin_slug, $this->known_safe_plugins, true ) ) {
			return array(
				'has_reputation' => true,
				'score'          => 30, // High trust
				'modifier'       => -25, // Reduce confidence significantly
				'reason'         => sprintf( 'Known safe plugin: %s', $plugin_slug ),
			);
		}

		// Check cache
		$cache_key = 'nexifymy_plugin_rep_' . md5( $plugin_slug );
		$cached = get_transient( $cache_key );
		if ( $cached !== false ) {
			return $cached;
		}

		// Fetch from WordPress.org API
		$reputation = $this->fetch_wp_org_plugin_reputation( $plugin_slug );

		// Cache for 24 hours
		set_transient( $cache_key, $reputation, self::CACHE_DURATION );

		return $reputation;
	}

	/**
	 * Extract plugin slug from file path.
	 *
	 * @param string $filepath File path.
	 * @return string|null Plugin slug or null.
	 */
	private function extract_plugin_slug( $filepath ) {
		$relative_path = str_replace( ABSPATH, '', $filepath );

		if ( preg_match( '#wp-content/plugins/([^/]+)/#', $relative_path, $matches ) ) {
			return $matches[1];
		}

		return null;
	}

	/**
	 * Fetch plugin reputation from WordPress.org API.
	 *
	 * @param string $plugin_slug Plugin slug.
	 * @return array Reputation data.
	 */
	private function fetch_wp_org_plugin_reputation( $plugin_slug ) {
		$url = add_query_arg(
			array(
				'action' => 'plugin_information',
				'slug'   => $plugin_slug,
			),
			self::WP_ORG_PLUGIN_API
		);

		$response = wp_remote_get( $url, array( 'timeout' => 10 ) );

		if ( is_wp_error( $response ) ) {
			return array(
				'has_reputation' => false,
				'score'          => 0,
				'reason'         => 'API unavailable',
			);
		}

		$body = wp_remote_retrieve_body( $response );
		$data = json_decode( $body, true );

		if ( empty( $data ) || isset( $data['error'] ) ) {
			return array(
				'has_reputation' => false,
				'score'          => 0,
				'reason'         => 'Plugin not found on WordPress.org',
			);
		}

		// Calculate reputation score
		$installs = isset( $data['active_installs'] ) ? (int) $data['active_installs'] : 0;
		$rating = isset( $data['rating'] ) ? (float) $data['rating'] : 0;
		$rating_normalized = $rating / 20; // Convert to 0-5 scale

		// Scoring algorithm
		$score = 0;
		if ( $installs > 1000000 ) { // 1M+ installs
			$score = 30;
		} elseif ( $installs > 100000 ) { // 100K+ installs
			$score = 20;
		} elseif ( $installs > 10000 ) { // 10K+ installs
			$score = 10;
		} elseif ( $installs > 1000 ) { // 1K+ installs
			$score = 5;
		}

		// Adjust based on rating
		if ( $rating_normalized >= 4.5 ) {
			$score += 10;
		} elseif ( $rating_normalized >= 4.0 ) {
			$score += 5;
		} elseif ( $rating_normalized < 3.0 && $installs > 1000 ) {
			$score -= 10; // Poor rating on popular plugin
		}

		// Calculate confidence modifier (negative = reduce threat confidence)
		$modifier = 0;
		if ( $score >= 30 ) {
			$modifier = -25; // High trust - significantly reduce confidence
		} elseif ( $score >= 20 ) {
			$modifier = -15; // Medium trust
		} elseif ( $score >= 10 ) {
			$modifier = -10; // Low trust
		} elseif ( $score < 0 ) {
			$modifier = 10; // Poor reputation - increase suspicion
		}

		return array(
			'has_reputation' => true,
			'score'          => $score,
			'modifier'       => $modifier,
			'installs'       => $installs,
			'rating'         => $rating_normalized,
			'reason'         => sprintf(
				'WordPress.org plugin: %s installs, %s/5 rating',
				number_format( $installs ),
				number_format( $rating_normalized, 1 )
			),
		);
	}

	/**
	 * Check file hash against known malware databases.
	 *
	 * @param string $filepath File path.
	 * @return array Hash check result.
	 */
	public function check_file_hash( $filepath ) {
		if ( ! file_exists( $filepath ) ) {
			return array(
				'is_malware' => false,
				'reason'     => 'File not found',
			);
		}

		$md5_hash = md5_file( $filepath );

		// Check against known malware hashes
		if ( isset( $this->known_malware_hashes[ $md5_hash ] ) ) {
			return array(
				'is_malware'     => true,
				'confidence'     => 100, // Absolute certainty
				'classification' => NexifyMy_Security_Scanner::CLASSIFICATION_CONFIRMED_MALWARE,
				'malware_name'   => $this->known_malware_hashes[ $md5_hash ],
				'reason'         => sprintf( 'Known malware hash: %s', $this->known_malware_hashes[ $md5_hash ] ),
			);
		}

		// Check against custom malware hash database (option)
		$custom_hashes = get_option( 'nexifymy_malware_hashes', array() );
		if ( isset( $custom_hashes[ $md5_hash ] ) ) {
			return array(
				'is_malware'     => true,
				'confidence'     => 100,
				'classification' => NexifyMy_Security_Scanner::CLASSIFICATION_CONFIRMED_MALWARE,
				'malware_name'   => $custom_hashes[ $md5_hash ]['name'],
				'reason'         => sprintf( 'Custom malware hash: %s', $custom_hashes[ $md5_hash ]['name'] ),
			);
		}

		return array(
			'is_malware' => false,
			'reason'     => 'Clean hash',
		);
	}

	/**
	 * Check if file is allowlisted.
	 *
	 * @param string $filepath File path.
	 * @return bool
	 */
	public function is_allowlisted( $filepath ) {
		$allowlist = $this->get_allowlist();
		$relative_path = str_replace( ABSPATH, '', $filepath );

		foreach ( $allowlist as $pattern ) {
			// Exact match
			if ( $relative_path === $pattern ) {
				return true;
			}

			// Wildcard match
			if ( fnmatch( $pattern, $relative_path ) ) {
				return true;
			}

			// Directory prefix match
			if ( substr( $pattern, -1 ) === '/' && strpos( $relative_path, $pattern ) === 0 ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Check if file is blocklisted.
	 *
	 * @param string $filepath File path.
	 * @return bool
	 */
	public function is_blocklisted( $filepath ) {
		$blocklist = $this->get_blocklist();
		$relative_path = str_replace( ABSPATH, '', $filepath );

		foreach ( $blocklist as $pattern ) {
			// Exact match
			if ( $relative_path === $pattern ) {
				return true;
			}

			// Wildcard match
			if ( fnmatch( $pattern, $relative_path ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Get user-defined allowlist.
	 *
	 * @return array
	 */
	public function get_allowlist() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$allowlist = isset( $settings['scanner']['allowlist'] ) ? $settings['scanner']['allowlist'] : array();

		// Ensure it's an array
		if ( is_string( $allowlist ) ) {
			$allowlist = array_filter( array_map( 'trim', explode( "\n", $allowlist ) ) );
		}

		return (array) $allowlist;
	}

	/**
	 * Get user-defined blocklist.
	 *
	 * @return array
	 */
	public function get_blocklist() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$blocklist = isset( $settings['scanner']['blocklist'] ) ? $settings['scanner']['blocklist'] : array();

		// Ensure it's an array
		if ( is_string( $blocklist ) ) {
			$blocklist = array_filter( array_map( 'trim', explode( "\n", $blocklist ) ) );
		}

		return (array) $blocklist;
	}

	/**
	 * Add hash to custom malware database.
	 *
	 * @param string $hash         MD5 hash.
	 * @param string $malware_name Malware name/description.
	 */
	public function add_malware_hash( $hash, $malware_name ) {
		$custom_hashes = get_option( 'nexifymy_malware_hashes', array() );
		$custom_hashes[ $hash ] = array(
			'name'      => $malware_name,
			'added_at'  => current_time( 'mysql' ),
			'added_by'  => get_current_user_id(),
		);
		update_option( 'nexifymy_malware_hashes', $custom_hashes );
	}

	/**
	 * Remove hash from custom malware database.
	 *
	 * @param string $hash MD5 hash.
	 */
	public function remove_malware_hash( $hash ) {
		$custom_hashes = get_option( 'nexifymy_malware_hashes', array() );
		if ( isset( $custom_hashes[ $hash ] ) ) {
			unset( $custom_hashes[ $hash ] );
			update_option( 'nexifymy_malware_hashes', $custom_hashes );
		}
	}

	/**
	 * Verify WordPress core file checksum.
	 *
	 * @param string $filepath File path.
	 * @return array Verification result.
	 */
	public function verify_wp_core_file( $filepath ) {
		global $wp_version;

		$relative_path = str_replace( ABSPATH, '', $filepath );

		// Check if it's a core file pattern
		if ( ! $this->is_wordpress_core_file( $relative_path ) ) {
			return array(
				'is_core_file' => false,
				'reason'       => 'Not a WordPress core file',
			);
		}

		// Fetch checksums from WordPress.org (cached)
		$checksums = $this->get_core_checksums( $wp_version );

		if ( is_wp_error( $checksums ) ) {
			return array(
				'is_core_file'  => true,
				'verified'      => false,
				'reason'        => 'Could not fetch checksums: ' . $checksums->get_error_message(),
			);
		}

		// Check if file is in checksums
		if ( ! isset( $checksums[ $relative_path ] ) ) {
			return array(
				'is_core_file'  => true,
				'verified'      => false,
				'reason'        => 'File not in official WordPress checksums',
			);
		}

		// Verify hash
		$actual_md5 = md5_file( $filepath );
		$expected_md5 = $checksums[ $relative_path ];

		if ( $actual_md5 === $expected_md5 ) {
			return array(
				'is_core_file'  => true,
				'verified'      => true,
				'modifier'      => -100, // Force CLEAN classification
				'classification' => NexifyMy_Security_Scanner::CLASSIFICATION_CLEAN,
				'reason'        => 'WordPress core file verified',
			);
		}

		return array(
			'is_core_file'  => true,
			'verified'      => false,
			'modifier'      => 30, // Increase suspicion significantly
			'classification' => NexifyMy_Security_Scanner::CLASSIFICATION_SUSPICIOUS_CODE,
			'reason'        => 'WordPress core file MODIFIED - checksum mismatch!',
		);
	}

	/**
	 * Check if path matches WordPress core file pattern.
	 *
	 * @param string $relative_path Relative file path.
	 * @return bool
	 */
	private function is_wordpress_core_file( $relative_path ) {
		$core_patterns = array(
			'wp-includes/',
			'wp-admin/',
		);

		foreach ( $core_patterns as $pattern ) {
			if ( strpos( $relative_path, $pattern ) === 0 ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Get WordPress core checksums from API (cached).
	 *
	 * @param string $version WordPress version.
	 * @return array|WP_Error Checksums array or error.
	 */
	private function get_core_checksums( $version ) {
		$cache_key = 'nexifymy_core_checksums_' . $version;
		$cached = get_transient( $cache_key );

		if ( $cached !== false ) {
			return $cached;
		}

		$locale = get_locale();
		$url = sprintf(
			'https://api.wordpress.org/core/checksums/1.0/?version=%s&locale=%s',
			$version,
			$locale
		);

		$response = wp_remote_get( $url, array( 'timeout' => 15 ) );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( empty( $body['checksums'] ) ) {
			return new WP_Error( 'invalid_checksums', 'Invalid checksum data received' );
		}

		$checksums = $body['checksums'];

		// Cache for 24 hours
		set_transient( $cache_key, $checksums, self::CACHE_DURATION );

		return $checksums;
	}
}
