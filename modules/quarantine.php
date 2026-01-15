<?php
/**
 * Quarantine Module.
 * Provides secure file quarantine instead of direct deletion.
 * Files are moved to a protected directory and can be restored or permanently deleted.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_Quarantine {

	/**
	 * Quarantine directory relative to wp-content.
	 */
	const QUARANTINE_DIR = 'nexifymy-quarantine';

	/**
	 * Option key for quarantine log.
	 */
	const QUARANTINE_LOG_OPTION = 'nexifymy_quarantine_log';

	/**
	 * Initialize the quarantine module.
	 */
	public function init() {
		// AJAX handlers.
		add_action( 'wp_ajax_nexifymy_quarantine_file', array( $this, 'ajax_quarantine_file' ) );
		add_action( 'wp_ajax_nexifymy_restore_file', array( $this, 'ajax_restore_file' ) );
		add_action( 'wp_ajax_nexifymy_delete_quarantined', array( $this, 'ajax_delete_quarantined' ) );
		add_action( 'wp_ajax_nexifymy_get_quarantined_files', array( $this, 'ajax_get_quarantined' ) );

		// Ensure quarantine directory exists.
		$this->ensure_quarantine_dir();
	}

	/**
	 * Get the full path to the quarantine directory.
	 *
	 * @return string
	 */
	public function get_quarantine_path() {
		return WP_CONTENT_DIR . '/' . self::QUARANTINE_DIR;
	}

	/**
	 * Ensure the quarantine directory exists and is protected.
	 */
	private function ensure_quarantine_dir() {
		$quarantine_path = $this->get_quarantine_path();

		if ( ! is_dir( $quarantine_path ) ) {
			wp_mkdir_p( $quarantine_path );
		}

		// Protect directory with .htaccess and index.php.
		$htaccess_path = $quarantine_path . '/.htaccess';
		if ( ! file_exists( $htaccess_path ) ) {
			file_put_contents( $htaccess_path, "Order Deny,Allow\nDeny from all\n" );
		}

		$index_path = $quarantine_path . '/index.php';
		if ( ! file_exists( $index_path ) ) {
			file_put_contents( $index_path, "<?php\n// Silence is golden.\n" );
		}
	}

	/**
	 * Check if a file path is safe to operate on.
	 *
	 * @param string $file_path File path.
	 * @return bool|WP_Error True if safe, WP_Error if not.
	 */
	private function validate_file_path( $file_path ) {
		// Must be within WordPress directory.
		$real_path = realpath( $file_path );
		$abspath = realpath( ABSPATH );

		if ( ! $real_path ) {
			return new WP_Error( 'invalid_path', 'File path is invalid.' );
		}

		if ( strpos( $real_path, $abspath ) !== 0 ) {
			return new WP_Error( 'outside_wp', 'Cannot operate on files outside WordPress directory.' );
		}

		// Protect critical files.
		$protected_files = array(
			'wp-config.php',
			'.htaccess',
			'index.php', // Only at root.
		);

		$basename = basename( $real_path );
		if ( $basename === 'wp-config.php' ) {
			return new WP_Error( 'protected_file', 'This file is protected and cannot be modified.' );
		}

		// Don't allow if file is within the quarantine directory itself.
		$quarantine_path = realpath( $this->get_quarantine_path() );
		if ( $quarantine_path && strpos( $real_path, $quarantine_path ) === 0 ) {
			return new WP_Error( 'already_quarantined', 'File is already in quarantine.' );
		}

		return true;
	}

	/**
	 * Generate a unique quarantine filename.
	 *
	 * @param string $original_path Original file path.
	 * @return string Quarantine filename.
	 */
	private function generate_quarantine_filename( $original_path ) {
		$hash = md5( $original_path . time() );
		$ext = pathinfo( $original_path, PATHINFO_EXTENSION );
		return $hash . '_' . time() . '.' . $ext . '.quarantine';
	}

	/**
	 * Move a file to quarantine.
	 *
	 * @param string $file_path Full path to the file.
	 * @param string $reason Reason for quarantine.
	 * @return array|WP_Error Quarantine info or error.
	 */
	public function quarantine_file( $file_path, $reason = '' ) {
		// Validate.
		$valid = $this->validate_file_path( $file_path );
		if ( is_wp_error( $valid ) ) {
			return $valid;
		}

		$real_path = realpath( $file_path );
		if ( ! file_exists( $real_path ) ) {
			return new WP_Error( 'not_found', 'File does not exist.' );
		}

		// Generate quarantine filename.
		$quarantine_filename = $this->generate_quarantine_filename( $real_path );
		$quarantine_full_path = $this->get_quarantine_path() . '/' . $quarantine_filename;

		// Store file metadata before moving.
		$file_info = array(
			'original_path'     => str_replace( ABSPATH, '', $real_path ),
			'original_full'     => $real_path,
			'quarantine_name'   => $quarantine_filename,
			'quarantine_path'   => $quarantine_full_path,
			'size'              => filesize( $real_path ),
			'md5'               => md5_file( $real_path ),
			'quarantined_at'    => current_time( 'mysql' ),
			'quarantined_by'    => get_current_user_id(),
			'reason'            => sanitize_text_field( $reason ),
		);

		// Move the file.
		if ( ! rename( $real_path, $quarantine_full_path ) ) {
			return new WP_Error( 'move_failed', 'Failed to move file to quarantine. Check permissions.' );
		}

		// Log the quarantine action.
		$this->add_to_quarantine_log( $file_info );

		// Log to security logger.
		if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
			NexifyMy_Security_Logger::log(
				'file_quarantined',
				sprintf( 'File quarantined: %s', $file_info['original_path'] ),
				'warning',
				$file_info
			);
		}

		return $file_info;
	}

	/**
	 * Restore a file from quarantine.
	 *
	 * @param string $quarantine_filename The quarantine filename.
	 * @return bool|WP_Error True on success, WP_Error on failure.
	 */
	public function restore_file( $quarantine_filename ) {
		$log = $this->get_quarantine_log();
		$file_info = null;

		// Find the file in log.
		foreach ( $log as $index => $entry ) {
			if ( $entry['quarantine_name'] === $quarantine_filename ) {
				$file_info = $entry;
				break;
			}
		}

		if ( ! $file_info ) {
			return new WP_Error( 'not_found', 'Quarantine entry not found.' );
		}

		$quarantine_full_path = $this->get_quarantine_path() . '/' . $quarantine_filename;
		$original_path = ABSPATH . $file_info['original_path'];

		if ( ! file_exists( $quarantine_full_path ) ) {
			return new WP_Error( 'file_missing', 'Quarantined file no longer exists.' );
		}

		// Check if original location still exists (directory).
		$original_dir = dirname( $original_path );
		if ( ! is_dir( $original_dir ) ) {
			return new WP_Error( 'dir_missing', 'Original directory no longer exists.' );
		}

		// Move back.
		if ( ! rename( $quarantine_full_path, $original_path ) ) {
			return new WP_Error( 'restore_failed', 'Failed to restore file. Check permissions.' );
		}

		// Remove from log.
		$this->remove_from_quarantine_log( $quarantine_filename );

		// Log the restore.
		if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
			NexifyMy_Security_Logger::log(
				'file_restored',
				sprintf( 'File restored from quarantine: %s', $file_info['original_path'] ),
				'info',
				$file_info
			);
		}

		return true;
	}

	/**
	 * Permanently delete a quarantined file.
	 *
	 * @param string $quarantine_filename The quarantine filename.
	 * @return bool|WP_Error True on success, WP_Error on failure.
	 */
	public function delete_quarantined( $quarantine_filename ) {
		$quarantine_full_path = $this->get_quarantine_path() . '/' . $quarantine_filename;

		// Validate the filename format.
		if ( ! preg_match( '/^[a-f0-9]{32}_\d+\.\w+\.quarantine$/', $quarantine_filename ) ) {
			return new WP_Error( 'invalid_filename', 'Invalid quarantine filename.' );
		}

		if ( ! file_exists( $quarantine_full_path ) ) {
			// Still remove from log.
			$this->remove_from_quarantine_log( $quarantine_filename );
			return new WP_Error( 'file_missing', 'File already deleted.' );
		}

		// Get log entry for logging.
		$log = $this->get_quarantine_log();
		$file_info = null;
		foreach ( $log as $entry ) {
			if ( $entry['quarantine_name'] === $quarantine_filename ) {
				$file_info = $entry;
				break;
			}
		}

		// Delete the file.
		if ( ! unlink( $quarantine_full_path ) ) {
			return new WP_Error( 'delete_failed', 'Failed to delete file. Check permissions.' );
		}

		// Remove from log.
		$this->remove_from_quarantine_log( $quarantine_filename );

		// Log the deletion.
		if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
			NexifyMy_Security_Logger::log(
				'file_deleted',
				sprintf( 'Quarantined file permanently deleted: %s', $file_info ? $file_info['original_path'] : $quarantine_filename ),
				'info',
				$file_info ?: array( 'quarantine_name' => $quarantine_filename )
			);
		}

		return true;
	}

	/**
	 * Get the quarantine log.
	 *
	 * @return array
	 */
	public function get_quarantine_log() {
		return get_option( self::QUARANTINE_LOG_OPTION, array() );
	}

	/**
	 * Add entry to quarantine log.
	 *
	 * @param array $file_info File info.
	 */
	private function add_to_quarantine_log( $file_info ) {
		$log = $this->get_quarantine_log();
		$log[] = $file_info;
		update_option( self::QUARANTINE_LOG_OPTION, $log );
	}

	/**
	 * Remove entry from quarantine log.
	 *
	 * @param string $quarantine_filename The quarantine filename.
	 */
	private function remove_from_quarantine_log( $quarantine_filename ) {
		$log = $this->get_quarantine_log();
		$new_log = array();

		foreach ( $log as $entry ) {
			if ( $entry['quarantine_name'] !== $quarantine_filename ) {
				$new_log[] = $entry;
			}
		}

		update_option( self::QUARANTINE_LOG_OPTION, $new_log );
	}

	/*
	 * =========================================================================
	 * AJAX HANDLERS
	 * =========================================================================
	 */

	/**
	 * Quarantine a file via AJAX.
	 */
	public function ajax_quarantine_file() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$file_path = isset( $_POST['file_path'] ) ? sanitize_text_field( $_POST['file_path'] ) : '';
		$reason = isset( $_POST['reason'] ) ? sanitize_text_field( $_POST['reason'] ) : 'Threat detected';

		if ( empty( $file_path ) ) {
			wp_send_json_error( 'No file path provided.' );
		}

		// Convert relative path to absolute.
		if ( strpos( $file_path, ABSPATH ) !== 0 ) {
			$file_path = ABSPATH . ltrim( $file_path, '/' );
		}

		$result = $this->quarantine_file( $file_path, $reason );

		if ( is_wp_error( $result ) ) {
			wp_send_json_error( $result->get_error_message() );
		}

		wp_send_json_success( array(
			'message' => 'File quarantined successfully.',
			'info'    => $result,
		) );
	}

	/**
	 * Restore a file via AJAX.
	 */
	public function ajax_restore_file() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$filename = isset( $_POST['filename'] ) ? sanitize_file_name( $_POST['filename'] ) : '';

		if ( empty( $filename ) ) {
			wp_send_json_error( 'No filename provided.' );
		}

		$result = $this->restore_file( $filename );

		if ( is_wp_error( $result ) ) {
			wp_send_json_error( $result->get_error_message() );
		}

		wp_send_json_success( 'File restored successfully.' );
	}

	/**
	 * Permanently delete a quarantined file via AJAX.
	 */
	public function ajax_delete_quarantined() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$filename = isset( $_POST['filename'] ) ? sanitize_file_name( $_POST['filename'] ) : '';

		if ( empty( $filename ) ) {
			wp_send_json_error( 'No filename provided.' );
		}

		$result = $this->delete_quarantined( $filename );

		if ( is_wp_error( $result ) ) {
			wp_send_json_error( $result->get_error_message() );
		}

		wp_send_json_success( 'File permanently deleted.' );
	}

	/**
	 * Get list of quarantined files via AJAX.
	 */
	public function ajax_get_quarantined() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$log = $this->get_quarantine_log();

		// Enrich with current status.
		$files = array();
		foreach ( $log as $entry ) {
			$quarantine_path = $this->get_quarantine_path() . '/' . $entry['quarantine_name'];
			$entry['exists'] = file_exists( $quarantine_path );
			$entry['size_formatted'] = size_format( $entry['size'] );
			$files[] = $entry;
		}

		wp_send_json_success( array(
			'count' => count( $files ),
			'files' => $files,
		) );
	}
}
