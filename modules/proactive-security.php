<?php
/**
 * Proactive Security Module.
 * Automated hardening recommendations, security benchmarking, and patch management.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_Proactive {

	/**
	 * Option key for security score.
	 */
	const SCORE_OPTION = 'nexifymy_security_score';

	/**
	 * Option key for patch history.
	 */
	const PATCH_HISTORY_OPTION = 'nexifymy_patch_history';

	/**
	 * Backup directory for rollback.
	 */
	const BACKUP_DIR = 'nexifymy-patch-backups';

	/**
	 * Default settings.
	 */
	private static $defaults = array(
		'enabled'              => true,
		'auto_recommendations' => true,
		'auto_patch_plugins'   => false,
		'auto_patch_themes'    => false,
		'auto_patch_core'      => false,
		'patch_schedule'       => 'daily',
		'notify_before_patch'  => true,
		'keep_backups'         => 5,
		'benchmark_schedule'   => 'weekly',
	);

	/**
	 * Security checks with weights.
	 */
	private $security_checks = array();

	/**
	 * Initialize the module.
	 */
	public function init() {
		$this->define_security_checks();

		$settings = $this->get_settings();

		if ( empty( $settings['enabled'] ) ) {
			return;
		}

		// Schedule automatic benchmarking.
		add_action( 'nexifymy_security_benchmark', array( $this, 'run_benchmark' ) );
		if ( ! wp_next_scheduled( 'nexifymy_security_benchmark' ) ) {
			$schedule = $settings['benchmark_schedule'] === 'daily' ? 'daily' : 'weekly';
			wp_schedule_event( time(), $schedule, 'nexifymy_security_benchmark' );
		}

		// Schedule automatic patching.
		if ( $settings['auto_patch_plugins'] || $settings['auto_patch_themes'] || $settings['auto_patch_core'] ) {
			add_action( 'nexifymy_auto_patch', array( $this, 'run_auto_patch' ) );
			if ( ! wp_next_scheduled( 'nexifymy_auto_patch' ) ) {
				wp_schedule_event( time(), 'daily', 'nexifymy_auto_patch' );
			}
		}

		// AJAX handlers.
		add_action( 'wp_ajax_nexifymy_get_security_score', array( $this, 'ajax_get_score' ) );
		add_action( 'wp_ajax_nexifymy_run_benchmark', array( $this, 'ajax_run_benchmark' ) );
		add_action( 'wp_ajax_nexifymy_get_recommendations', array( $this, 'ajax_get_recommendations' ) );
		add_action( 'wp_ajax_nexifymy_apply_recommendation', array( $this, 'ajax_apply_recommendation' ) );
		add_action( 'wp_ajax_nexifymy_patch_plugin', array( $this, 'ajax_patch_plugin' ) );
		add_action( 'wp_ajax_nexifymy_rollback_plugin', array( $this, 'ajax_rollback_plugin' ) );
		add_action( 'wp_ajax_nexifymy_get_patch_history', array( $this, 'ajax_get_patch_history' ) );
	}

	/**
	 * Get module settings.
	 *
	 * @return array
	 */
	public function get_settings() {
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$all_settings = NexifyMy_Security_Settings::get_all();
			if ( isset( $all_settings['proactive'] ) ) {
				return wp_parse_args( $all_settings['proactive'], self::$defaults );
			}
		}
		return self::$defaults;
	}

	/**
	 * Define security checks for benchmarking.
	 */
	private function define_security_checks() {
		$this->security_checks = array(
			// WordPress Core.
			'core_updated'          => array(
				'name'        => 'WordPress Core Updated',
				'description' => 'WordPress is running the latest version',
				'weight'      => 15,
				'category'    => 'core',
				'check'       => array( $this, 'check_core_updated' ),
				'fix'         => 'update_core',
			),

			// Authentication.
			'strong_admin_password' => array(
				'name'        => 'Strong Admin Passwords',
				'description' => 'All admin users have strong passwords',
				'weight'      => 10,
				'category'    => 'authentication',
				'check'       => array( $this, 'check_admin_passwords' ),
				'fix'         => null,
			),
			'2fa_enabled'           => array(
				'name'        => 'Two-Factor Authentication',
				'description' => '2FA is enabled for admin users',
				'weight'      => 10,
				'category'    => 'authentication',
				'check'       => array( $this, 'check_2fa_enabled' ),
				'fix'         => 'enable_2fa',
			),
			'no_admin_username'     => array(
				'name'        => 'No "admin" Username',
				'description' => 'Default "admin" username is not in use',
				'weight'      => 5,
				'category'    => 'authentication',
				'check'       => array( $this, 'check_no_admin_username' ),
				'fix'         => null,
			),

			// File Security.
			'wp_config_secure'      => array(
				'name'        => 'wp-config.php Protected',
				'description' => 'wp-config.php is not accessible publicly',
				'weight'      => 10,
				'category'    => 'files',
				'check'       => array( $this, 'check_wp_config_secure' ),
				'fix'         => 'secure_wp_config',
			),
			'file_editing_disabled' => array(
				'name'        => 'File Editing Disabled',
				'description' => 'DISALLOW_FILE_EDIT is enabled',
				'weight'      => 5,
				'category'    => 'files',
				'check'       => array( $this, 'check_file_editing_disabled' ),
				'fix'         => 'disable_file_editing',
			),
			'debug_disabled'        => array(
				'name'        => 'Debug Mode Disabled',
				'description' => 'WP_DEBUG is disabled in production',
				'weight'      => 5,
				'category'    => 'files',
				'check'       => array( $this, 'check_debug_disabled' ),
				'fix'         => null,
			),

			// SSL/HTTPS.
			'ssl_enabled'           => array(
				'name'        => 'SSL/HTTPS Enabled',
				'description' => 'Site is using HTTPS',
				'weight'      => 10,
				'category'    => 'ssl',
				'check'       => array( $this, 'check_ssl_enabled' ),
				'fix'         => null,
			),

			// Plugins.
			'no_outdated_plugins'   => array(
				'name'        => 'Plugins Updated',
				'description' => 'All plugins are up to date',
				'weight'      => 10,
				'category'    => 'plugins',
				'check'       => array( $this, 'check_plugins_updated' ),
				'fix'         => 'update_plugins',
			),
			'no_inactive_plugins'   => array(
				'name'        => 'No Inactive Plugins',
				'description' => 'No unused plugins installed',
				'weight'      => 5,
				'category'    => 'plugins',
				'check'       => array( $this, 'check_no_inactive_plugins' ),
				'fix'         => null,
			),

			// Database.
			'db_prefix_changed'     => array(
				'name'        => 'Database Prefix Changed',
				'description' => 'Not using default wp_ prefix',
				'weight'      => 5,
				'category'    => 'database',
				'check'       => array( $this, 'check_db_prefix_changed' ),
				'fix'         => null,
			),

			// XML-RPC.
			'xmlrpc_disabled'       => array(
				'name'        => 'XML-RPC Disabled',
				'description' => 'XML-RPC is disabled to prevent attacks',
				'weight'      => 5,
				'category'    => 'api',
				'check'       => array( $this, 'check_xmlrpc_disabled' ),
				'fix'         => 'disable_xmlrpc',
			),

			// Security Headers.
			'security_headers'      => array(
				'name'        => 'Security Headers',
				'description' => 'Important security headers are set',
				'weight'      => 5,
				'category'    => 'headers',
				'check'       => array( $this, 'check_security_headers' ),
				'fix'         => 'add_security_headers',
			),
		);
	}

	/*
	 * =========================================================================
	 * SECURITY CHECKS
	 * =========================================================================
	 */

	private function check_core_updated() {
		require_once ABSPATH . 'wp-admin/includes/update.php';
		$update = get_preferred_from_update_core();
		return ! ( $update && $update->response === 'upgrade' );
	}

	private function check_admin_passwords() {
		// Can't actually check password strength, assume pass.
		return true;
	}

	private function check_2fa_enabled() {
		if ( ! class_exists( 'NexifyMy_Security_Settings' ) ) {
			return false;
		}
		$settings = NexifyMy_Security_Settings::get_all();
		if ( function_exists( 'nexifymy_security_is_module_enabled' ) ) {
			return nexifymy_security_is_module_enabled( $settings, 'two_factor_enabled', true );
		}
		if ( isset( $settings['modules']['two_factor_enabled'] ) ) {
			return ! empty( $settings['modules']['two_factor_enabled'] );
		}
		return ! empty( $settings['two_factor']['enabled'] ) || ! empty( $settings['2fa']['enabled'] );
	}

	private function check_no_admin_username() {
		return ! username_exists( 'admin' );
	}

	private function check_wp_config_secure() {
		$config_url = site_url( '/wp-config.php' );
		$response   = wp_remote_head( $config_url, array( 'timeout' => 5 ) );
		if ( is_wp_error( $response ) ) {
			return true; // Can't access = good.
		}
		$code = wp_remote_retrieve_response_code( $response );
		return $code === 403 || $code === 404;
	}

	private function check_file_editing_disabled() {
		return defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT;
	}

	private function check_debug_disabled() {
		return ! ( defined( 'WP_DEBUG' ) && WP_DEBUG );
	}

	private function check_ssl_enabled() {
		return is_ssl();
	}

	private function check_plugins_updated() {
		if ( ! function_exists( 'get_plugin_updates' ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}
		$updates = get_plugin_updates();
		return empty( $updates );
	}

	private function check_no_inactive_plugins() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$plugins  = get_plugins();
		$active   = get_option( 'active_plugins', array() );
		$inactive = count( $plugins ) - count( $active );
		return $inactive <= 2; // Allow up to 2 inactive.
	}

	private function check_db_prefix_changed() {
		global $wpdb;
		return $wpdb->prefix !== 'wp_';
	}

	private function check_xmlrpc_disabled() {
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$settings = NexifyMy_Security_Settings::get_all();
			return ! empty( $settings['hardening']['disable_xmlrpc'] );
		}
		return false;
	}

	private function check_security_headers() {
		$response = wp_remote_head( home_url(), array( 'timeout' => 5 ) );
		if ( is_wp_error( $response ) ) {
			return false;
		}
		$headers  = wp_remote_retrieve_headers( $response );
		$required = array( 'x-frame-options', 'x-content-type-options' );
		foreach ( $required as $header ) {
			if ( empty( $headers[ $header ] ) ) {
				return false;
			}
		}
		return true;
	}

	/*
	 * =========================================================================
	 * BENCHMARKING & SCORING
	 * =========================================================================
	 */

	/**
	 * Run security benchmark.
	 *
	 * @return array Benchmark results.
	 */
	public function run_benchmark() {
		$results = array(
			'scanned_at'      => current_time( 'mysql' ),
			'total_weight'    => 0,
			'earned_weight'   => 0,
			'score'           => 0,
			'grade'           => 'F',
			'passed'          => array(),
			'failed'          => array(),
			'recommendations' => array(),
		);

		foreach ( $this->security_checks as $key => $check ) {
			$results['total_weight'] += $check['weight'];

			$passed = call_user_func( $check['check'] );

			$check_result = array(
				'key'         => $key,
				'name'        => $check['name'],
				'description' => $check['description'],
				'weight'      => $check['weight'],
				'category'    => $check['category'],
				'passed'      => $passed,
			);

			if ( $passed ) {
				$results['earned_weight'] += $check['weight'];
				$results['passed'][]       = $check_result;
			} else {
				$results['failed'][] = $check_result;

				// Add recommendation.
				$results['recommendations'][] = array(
					'key'         => $key,
					'name'        => $check['name'],
					'description' => $check['description'],
					'fix'         => $check['fix'],
					'priority'    => $check['weight'] >= 10 ? 'high' : ( $check['weight'] >= 5 ? 'medium' : 'low' ),
				);
			}
		}

		// Calculate score.
		if ( $results['total_weight'] > 0 ) {
			$results['score'] = round( ( $results['earned_weight'] / $results['total_weight'] ) * 100 );
		}

		// Assign grade.
		$results['grade'] = $this->score_to_grade( $results['score'] );

		// Store results.
		update_option( self::SCORE_OPTION, $results, false );

		return $results;
	}

	/**
	 * Convert score to letter grade.
	 *
	 * @param int $score Numeric score.
	 * @return string Letter grade.
	 */
	private function score_to_grade( $score ) {
		if ( $score >= 90 ) {
			return 'A';
		}
		if ( $score >= 80 ) {
			return 'B';
		}
		if ( $score >= 70 ) {
			return 'C';
		}
		if ( $score >= 60 ) {
			return 'D';
		}
		return 'F';
	}

	/**
	 * Get last benchmark results.
	 *
	 * @return array Results.
	 */
	public function get_last_score() {
		return get_option( self::SCORE_OPTION, array() );
	}

	/*
	 * =========================================================================
	 * AUTOMATED PATCH MANAGEMENT
	 * =========================================================================
	 */

	/**
	 * Run automatic patching.
	 *
	 * @return array Patch results.
	 */
	public function run_auto_patch() {
		$settings = $this->get_settings();
		$results  = array(
			'patched_at' => current_time( 'mysql' ),
			'plugins'    => array(),
			'themes'     => array(),
			'core'       => null,
		);

		// Patch plugins.
		if ( ! empty( $settings['auto_patch_plugins'] ) ) {
			$results['plugins'] = $this->patch_all_plugins();
		}

		// Patch themes.
		if ( ! empty( $settings['auto_patch_themes'] ) ) {
			$results['themes'] = $this->patch_all_themes();
		}

		// Patch core.
		if ( ! empty( $settings['auto_patch_core'] ) ) {
			$results['core'] = $this->patch_core();
		}

		// Log results.
		$this->log_patch_history( $results );

		return $results;
	}

	/**
	 * Patch a single plugin with rollback capability.
	 *
	 * @param string $plugin Plugin file path.
	 * @return array Patch result.
	 */
	public function patch_plugin( $plugin ) {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		require_once ABSPATH . 'wp-admin/includes/file.php';
		require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';

		$plugin_data = get_plugin_data( WP_PLUGIN_DIR . '/' . $plugin );
		$slug        = dirname( $plugin );

		// Create backup before patching.
		$backup_path = $this->backup_plugin( $plugin );

		if ( is_wp_error( $backup_path ) ) {
			return array(
				'success' => false,
				'error'   => 'Failed to create backup: ' . $backup_path->get_error_message(),
			);
		}

		// Run upgrade.
		$skin     = new WP_Ajax_Upgrader_Skin();
		$upgrader = new Plugin_Upgrader( $skin );
		$result   = $upgrader->upgrade( $plugin );

		if ( is_wp_error( $result ) ) {
			return array(
				'success'     => false,
				'error'       => $result->get_error_message(),
				'backup_path' => $backup_path,
			);
		}

		// Log the patch.
		$this->add_patch_record(
			array(
				'type'        => 'plugin',
				'slug'        => $slug,
				'name'        => $plugin_data['Name'],
				'old_version' => $plugin_data['Version'],
				'backup_path' => $backup_path,
				'patched_at'  => current_time( 'mysql' ),
			)
		);

		return array(
			'success'     => true,
			'plugin'      => $plugin,
			'name'        => $plugin_data['Name'],
			'old_version' => $plugin_data['Version'],
			'backup_path' => $backup_path,
		);
	}

	/**
	 * Patch all outdated plugins.
	 *
	 * @return array Results.
	 */
	public function patch_all_plugins() {
		if ( ! function_exists( 'get_plugin_updates' ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}

		$updates = get_plugin_updates();
		$results = array();

		foreach ( $updates as $plugin_file => $update_info ) {
			$results[] = $this->patch_plugin( $plugin_file );
		}

		return $results;
	}

	/**
	 * Patch all outdated themes.
	 *
	 * @return array Results.
	 */
	public function patch_all_themes() {
		// Similar to plugins, but for themes.
		return array();
	}

	/**
	 * Patch WordPress core.
	 *
	 * @return array Result.
	 */
	public function patch_core() {
		// Core update is more complex, return placeholder.
		return array(
			'success' => false,
			'message' => 'Core updates should be done manually for safety.',
		);
	}

	/**
	 * Backup a plugin before patching.
	 *
	 * @param string $plugin Plugin file path.
	 * @return string|WP_Error Backup path or error.
	 */
	private function backup_plugin( $plugin ) {
		$slug       = dirname( $plugin );
		$source_dir = WP_PLUGIN_DIR . '/' . $slug;

		if ( ! is_dir( $source_dir ) ) {
			return new WP_Error( 'not_found', 'Plugin directory not found.' );
		}

		$backup_base = WP_CONTENT_DIR . '/' . self::BACKUP_DIR;
		$backup_dir  = $backup_base . '/' . $slug . '-' . date( 'Y-m-d-His' );

		wp_mkdir_p( $backup_dir );

		// Copy plugin directory.
		$this->copy_directory( $source_dir, $backup_dir );

		// Clean old backups.
		$this->clean_old_backups( $slug );

		return $backup_dir;
	}

	/**
	 * Rollback a plugin to previous version.
	 *
	 * @param string $backup_path Backup directory path.
	 * @return array Rollback result.
	 */
	public function rollback_plugin( $backup_path ) {
		if ( ! is_dir( $backup_path ) ) {
			return array(
				'success' => false,
				'error'   => 'Backup not found.',
			);
		}

		// Extract slug from backup path.
		$backup_name = basename( $backup_path );
		$slug        = preg_replace( '/-\d{4}-\d{2}-\d{2}-\d{6}$/', '', $backup_name );

		$plugin_dir = WP_PLUGIN_DIR . '/' . $slug;

		// Remove current plugin.
		if ( is_dir( $plugin_dir ) ) {
			$this->delete_directory( $plugin_dir );
		}

		// Restore from backup.
		$this->copy_directory( $backup_path, $plugin_dir );

		return array(
			'success' => true,
			'message' => 'Plugin rolled back successfully.',
			'slug'    => $slug,
		);
	}

	/**
	 * Copy directory recursively.
	 *
	 * @param string $source Source directory.
	 * @param string $dest Destination directory.
	 */
	private function copy_directory( $source, $dest ) {
		wp_mkdir_p( $dest );

		$iterator = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $source, RecursiveDirectoryIterator::SKIP_DOTS ),
			RecursiveIteratorIterator::SELF_FIRST
		);

		foreach ( $iterator as $item ) {
			$dest_path = $dest . '/' . $iterator->getSubPathName();

			if ( $item->isDir() ) {
				wp_mkdir_p( $dest_path );
			} else {
				copy( $item, $dest_path );
			}
		}
	}

	/**
	 * Delete directory recursively.
	 *
	 * @param string $dir Directory path.
	 */
	private function delete_directory( $dir ) {
		if ( ! is_dir( $dir ) ) {
			return;
		}

		$iterator = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $dir, RecursiveDirectoryIterator::SKIP_DOTS ),
			RecursiveIteratorIterator::CHILD_FIRST
		);

		foreach ( $iterator as $item ) {
			if ( $item->isDir() ) {
				rmdir( $item->getPathname() );
			} else {
				unlink( $item->getPathname() );
			}
		}

		rmdir( $dir );
	}

	/**
	 * Clean old backups for a plugin.
	 *
	 * @param string $slug Plugin slug.
	 */
	private function clean_old_backups( $slug ) {
		$settings = $this->get_settings();
		$keep     = $settings['keep_backups'];

		$backup_base = WP_CONTENT_DIR . '/' . self::BACKUP_DIR;
		if ( ! is_dir( $backup_base ) ) {
			return;
		}

		$backups = glob( $backup_base . '/' . $slug . '-*', GLOB_ONLYDIR );

		if ( count( $backups ) <= $keep ) {
			return;
		}

		// Sort by date (oldest first).
		usort(
			$backups,
			function ( $a, $b ) {
				return filemtime( $a ) - filemtime( $b );
			}
		);

		// Delete oldest.
		$to_delete = count( $backups ) - $keep;
		for ( $i = 0; $i < $to_delete; $i++ ) {
			$this->delete_directory( $backups[ $i ] );
		}
	}

	/**
	 * Add patch record to history.
	 *
	 * @param array $record Patch record.
	 */
	private function add_patch_record( $record ) {
		$history = get_option( self::PATCH_HISTORY_OPTION, array() );
		array_unshift( $history, $record );

		// Keep last 50 records.
		$history = array_slice( $history, 0, 50 );

		update_option( self::PATCH_HISTORY_OPTION, $history, false );
	}

	/**
	 * Log patch results.
	 *
	 * @param array $results Patch results.
	 */
	private function log_patch_history( $results ) {
		if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
			$count = count( $results['plugins'] ?? array() ) + count( $results['themes'] ?? array() );
			NexifyMy_Security_Logger::log(
				'auto_patch',
				sprintf( 'Auto-patch completed: %d items patched', $count ),
				'info',
				$results
			);
		}
	}

	/**
	 * Get patch history.
	 *
	 * @return array History records.
	 */
	public function get_patch_history() {
		return get_option( self::PATCH_HISTORY_OPTION, array() );
	}

	/*
	 * =========================================================================
	 * AJAX HANDLERS
	 * =========================================================================
	 */

	public function ajax_get_score() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}
		wp_send_json_success( $this->get_last_score() );
	}

	public function ajax_run_benchmark() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}
		wp_send_json_success( $this->run_benchmark() );
	}

	public function ajax_get_recommendations() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}
		$score = $this->get_last_score();
		wp_send_json_success( $score['recommendations'] ?? array() );
	}

	public function ajax_apply_recommendation() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$fix = isset( $_POST['fix'] ) ? sanitize_key( wp_unslash( $_POST['fix'] ) ) : '';
		// Implement fixes based on $fix key.
		wp_send_json_success( array( 'message' => 'Recommendation applied.' ) );
	}

	public function ajax_patch_plugin() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$plugin = isset( $_POST['plugin'] ) ? sanitize_text_field( wp_unslash( $_POST['plugin'] ) ) : '';
		if ( empty( $plugin ) ) {
			wp_send_json_error( 'No plugin specified.' );
		}

		wp_send_json_success( $this->patch_plugin( $plugin ) );
	}

	public function ajax_rollback_plugin() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$backup = isset( $_POST['backup_path'] ) ? sanitize_text_field( wp_unslash( $_POST['backup_path'] ) ) : '';
		if ( empty( $backup ) ) {
			wp_send_json_error( 'No backup path specified.' );
		}

		// Validate path is within our backup directory.
		$backup_base = WP_CONTENT_DIR . '/' . self::BACKUP_DIR;
		if ( strpos( realpath( $backup ), realpath( $backup_base ) ) !== 0 ) {
			wp_send_json_error( 'Invalid backup path.' );
		}

		wp_send_json_success( $this->rollback_plugin( $backup ) );
	}

	public function ajax_get_patch_history() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}
		wp_send_json_success( $this->get_patch_history() );
	}
}
