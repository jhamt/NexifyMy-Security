<?php
/**
 * Core File Repair Module.
 * Repairs corrupted WordPress core files using official WordPress.org sources.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_Core_Repair {

	/**
	 * WordPress.org checksums API.
	 */
	const CHECKSUMS_API = 'https://api.wordpress.org/core/checksums/1.0/';

	/**
	 * WordPress.org downloads.
	 */
	const DOWNLOAD_BASE = 'https://downloads.wordpress.org/release/';

	/**
	 * Default settings.
	 */
	private static $defaults = array(
		'enabled'       => true,
		'backup_before' => true,
		'notify_admin'  => true,
	);

	/**
	 * Initialize the module.
	 */
	public function init() {
		// AJAX handlers.
		add_action( 'wp_ajax_nexifymy_check_core_integrity', array( $this, 'ajax_check_integrity' ) );
		add_action( 'wp_ajax_nexifymy_repair_core_file', array( $this, 'ajax_repair_file' ) );
		add_action( 'wp_ajax_nexifymy_repair_all_core', array( $this, 'ajax_repair_all' ) );
		add_action( 'wp_ajax_nexifymy_download_fresh_core', array( $this, 'ajax_download_core' ) );
	}

	/**
	 * Get module settings.
	 *
	 * @return array
	 */
	public function get_settings() {
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$all_settings = NexifyMy_Security_Settings::get_all();
			if ( isset( $all_settings['core_repair'] ) ) {
				return wp_parse_args( $all_settings['core_repair'], self::$defaults );
			}
		}
		return self::$defaults;
	}

	/**
	 * Get WordPress core checksums from official API.
	 *
	 * @return array|WP_Error Checksums or error.
	 */
	public function get_official_checksums() {
		global $wp_version;

		$locale = get_locale();
		$url    = add_query_arg(
			array(
				'version' => $wp_version,
				'locale'  => $locale,
			),
			self::CHECKSUMS_API
		);

		$response = wp_remote_get( $url, array( 'timeout' => 30 ) );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( empty( $body['checksums'] ) ) {
			return new WP_Error( 'no_checksums', 'Could not retrieve checksums from WordPress.org' );
		}

		return $body['checksums'];
	}

	/**
	 * Check integrity of all core files.
	 *
	 * @return array Integrity report.
	 */
	public function check_integrity() {
		global $wp_version;

		$checksums = $this->get_official_checksums();

		if ( is_wp_error( $checksums ) ) {
			return array(
				'success' => false,
				'error'   => $checksums->get_error_message(),
			);
		}

		$modified = array();
		$missing  = array();
		$verified = 0;

		foreach ( $checksums as $file => $expected_hash ) {
			$file_path = ABSPATH . $file;

			if ( ! file_exists( $file_path ) ) {
				$missing[] = array(
					'file'     => $file,
					'expected' => $expected_hash,
					'status'   => 'missing',
				);
				continue;
			}

			$actual_hash = md5_file( $file_path );

			if ( $actual_hash !== $expected_hash ) {
				$modified[] = array(
					'file'     => $file,
					'expected' => $expected_hash,
					'actual'   => $actual_hash,
					'size'     => size_format( filesize( $file_path ) ),
					'modified' => date( 'Y-m-d H:i:s', filemtime( $file_path ) ),
					'status'   => 'modified',
				);
			} else {
				++$verified;
			}
		}

		return array(
			'success'        => true,
			'wp_version'     => $wp_version,
			'checked_at'     => current_time( 'mysql' ),
			'total_files'    => count( $checksums ),
			'verified'       => $verified,
			'modified_count' => count( $modified ),
			'missing_count'  => count( $missing ),
			'modified'       => $modified,
			'missing'        => $missing,
			'is_clean'       => empty( $modified ) && empty( $missing ),
		);
	}

	/**
	 * Download fresh WordPress core files.
	 *
	 * @return string|WP_Error Path to extracted files or error.
	 */
	public function download_fresh_core() {
		global $wp_version;

		// Include required files.
		require_once ABSPATH . 'wp-admin/includes/file.php';

		$download_url = self::DOWNLOAD_BASE . 'wordpress-' . $wp_version . '.zip';

		// Download the ZIP file.
		$tmp_file = download_url( $download_url, 120 );

		if ( is_wp_error( $tmp_file ) ) {
			return $tmp_file;
		}

		// Create extraction directory.
		$extract_dir = WP_CONTENT_DIR . '/nexifymy-temp/core-' . $wp_version . '-' . time();
		wp_mkdir_p( $extract_dir );

		// Extract ZIP.
		$result = unzip_file( $tmp_file, $extract_dir );

		// Delete temp ZIP.
		@unlink( $tmp_file );

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		return $extract_dir . '/wordpress';
	}

	/**
	 * Repair a single core file.
	 *
	 * @param string $file Relative file path.
	 * @param string $source_dir Optional source directory with fresh files.
	 * @return array Repair result.
	 */
	public function repair_file( $file, $source_dir = null ) {
		$settings    = $this->get_settings();
		$target_path = ABSPATH . $file;

		// Validate file is a core file.
		$checksums = $this->get_official_checksums();
		if ( is_wp_error( $checksums ) ) {
			return array(
				'success' => false,
				'error'   => $checksums->get_error_message(),
			);
		}

		if ( ! isset( $checksums[ $file ] ) ) {
			return array(
				'success' => false,
				'error'   => 'File is not a WordPress core file.',
			);
		}

		// Backup if enabled.
		if ( ! empty( $settings['backup_before'] ) && file_exists( $target_path ) ) {
			$this->backup_file( $target_path, $file );
		}

		// Get fresh file.
		if ( $source_dir && file_exists( $source_dir . '/' . $file ) ) {
			$source_path = $source_dir . '/' . $file;
		} else {
			// Download fresh core if no source provided.
			$fresh_dir = $this->download_fresh_core();
			if ( is_wp_error( $fresh_dir ) ) {
				return array(
					'success' => false,
					'error'   => $fresh_dir->get_error_message(),
				);
			}
			$source_path = $fresh_dir . '/' . $file;
		}

		if ( ! file_exists( $source_path ) ) {
			return array(
				'success' => false,
				'error'   => 'Fresh file not found in WordPress package.',
			);
		}

		// Create directory if needed.
		$dir = dirname( $target_path );
		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
		}

		// Copy fresh file.
		if ( ! copy( $source_path, $target_path ) ) {
			return array(
				'success' => false,
				'error'   => 'Failed to copy file. Check permissions.',
			);
		}

		// Verify repair.
		$new_hash      = md5_file( $target_path );
		$expected_hash = $checksums[ $file ];

		if ( $new_hash !== $expected_hash ) {
			return array(
				'success' => false,
				'error'   => 'File replaced but hash still does not match.',
			);
		}

		// Log the repair.
		if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
			NexifyMy_Security_Logger::log(
				'core_file_repaired',
				sprintf( 'Core file repaired: %s', $file ),
				'info',
				array( 'file' => $file )
			);
		}

		return array(
			'success' => true,
			'file'    => $file,
			'message' => 'File successfully repaired.',
		);
	}

	/**
	 * Repair all modified/missing core files.
	 *
	 * @return array Repair results.
	 */
	public function repair_all() {
		$integrity = $this->check_integrity();

		if ( ! $integrity['success'] ) {
			return $integrity;
		}

		if ( $integrity['is_clean'] ) {
			return array(
				'success'  => true,
				'message'  => 'All core files are already intact.',
				'repaired' => 0,
			);
		}

		// Download fresh core once.
		$fresh_dir = $this->download_fresh_core();
		if ( is_wp_error( $fresh_dir ) ) {
			return array(
				'success' => false,
				'error'   => $fresh_dir->get_error_message(),
			);
		}

		$repaired = array();
		$failed   = array();

		// Repair modified files.
		foreach ( $integrity['modified'] as $item ) {
			$result = $this->repair_file( $item['file'], $fresh_dir );
			if ( $result['success'] ) {
				$repaired[] = $item['file'];
			} else {
				$failed[] = array(
					'file'  => $item['file'],
					'error' => $result['error'],
				);
			}
		}

		// Restore missing files.
		foreach ( $integrity['missing'] as $item ) {
			$result = $this->repair_file( $item['file'], $fresh_dir );
			if ( $result['success'] ) {
				$repaired[] = $item['file'];
			} else {
				$failed[] = array(
					'file'  => $item['file'],
					'error' => $result['error'],
				);
			}
		}

		// Cleanup temp directory.
		$this->cleanup_temp_dir( dirname( $fresh_dir ) );

		// Notify admin if enabled.
		$settings = $this->get_settings();
		if ( ! empty( $settings['notify_admin'] ) && ! empty( $repaired ) ) {
			$this->send_repair_notification( $repaired, $failed );
		}

		return array(
			'success'        => true,
			'repaired_count' => count( $repaired ),
			'failed_count'   => count( $failed ),
			'repaired'       => $repaired,
			'failed'         => $failed,
		);
	}

	/**
	 * Backup a file before repair.
	 *
	 * @param string $file_path Absolute file path.
	 * @param string $relative Relative file path.
	 */
	private function backup_file( $file_path, $relative ) {
		$backup_dir  = WP_CONTENT_DIR . '/nexifymy-backups/core/' . date( 'Y-m-d_H-i-s' );
		$backup_path = $backup_dir . '/' . $relative;

		wp_mkdir_p( dirname( $backup_path ) );
		copy( $file_path, $backup_path );
	}

	/**
	 * Cleanup temporary directory.
	 *
	 * @param string $dir Directory path.
	 */
	private function cleanup_temp_dir( $dir ) {
		if ( ! is_dir( $dir ) ) {
			return;
		}

		$iterator = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $dir, RecursiveDirectoryIterator::SKIP_DOTS ),
			RecursiveIteratorIterator::CHILD_FIRST
		);

		foreach ( $iterator as $file ) {
			if ( $file->isDir() ) {
				@rmdir( $file->getPathname() );
			} else {
				@unlink( $file->getPathname() );
			}
		}

		@rmdir( $dir );
	}

	/**
	 * Send repair notification email.
	 *
	 * @param array $repaired Repaired files.
	 * @param array $failed Failed files.
	 */
	private function send_repair_notification( $repaired, $failed ) {
		$to      = get_option( 'admin_email' );
		$subject = sprintf( '[%s] WordPress Core Files Repaired', get_bloginfo( 'name' ) );

		$message  = "WordPress Core File Repair Report\n\n";
		$message .= sprintf( "Site: %s\n", home_url() );
		$message .= sprintf( "Time: %s\n\n", current_time( 'mysql' ) );

		$message .= sprintf( "Successfully Repaired: %d files\n", count( $repaired ) );
		foreach ( $repaired as $file ) {
			$message .= "  ✓ {$file}\n";
		}

		if ( ! empty( $failed ) ) {
			$message .= sprintf( "\nFailed to Repair: %d files\n", count( $failed ) );
			foreach ( $failed as $item ) {
				$message .= "  ✗ {$item['file']} - {$item['error']}\n";
			}
		}

		wp_mail( $to, $subject, $message );
	}

	/*
	 * =========================================================================
	 * AJAX HANDLERS
	 * =========================================================================
	 */

	/**
	 * Check core integrity via AJAX.
	 */
	public function ajax_check_integrity() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$result = $this->check_integrity();
		wp_send_json_success( $result );
	}

	/**
	 * Repair single file via AJAX.
	 */
	public function ajax_repair_file() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$file = isset( $_POST['file'] ) ? sanitize_text_field( wp_unslash( $_POST['file'] ) ) : '';

		if ( empty( $file ) ) {
			wp_send_json_error( 'No file specified.' );
		}

		$result = $this->repair_file( $file );
		wp_send_json_success( $result );
	}

	/**
	 * Repair all modified/missing files via AJAX.
	 */
	public function ajax_repair_all() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$result = $this->repair_all();
		wp_send_json_success( $result );
	}

	/**
	 * Download fresh core via AJAX (for manual extraction).
	 */
	public function ajax_download_core() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$path = $this->download_fresh_core();

		if ( is_wp_error( $path ) ) {
			wp_send_json_error( $path->get_error_message() );
		}

		wp_send_json_success(
			array(
				'message' => 'Fresh WordPress core downloaded.',
				'path'    => $path,
			)
		);
	}
}
