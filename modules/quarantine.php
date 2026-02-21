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
		* Recoverable deleted-files directory relative to wp-content.
	 */
	const DELETED_DIR = 'nexifymy-quarantine-deleted';
	/**
	 * Option key for quarantine log.
	*/
	const QUARANTINE_LOG_OPTION = 'nexifymy_quarantine_log';

	/**
		* Option key for recoverable deleted-files log.
	 */
	const DELETED_LOG_OPTION = 'nexifymy_quarantine_deleted_log';
	/**
	 * Initialize the quarantine module.
	 */
	public function init() {

		// AJAX handlers.
		add_action( 'wp_ajax_nexifymy_quarantine_file', array( $this, 'ajax_quarantine_file' ) );
		add_action( 'wp_ajax_nexifymy_delete_file', array( $this, 'ajax_delete_file' ) );
		add_action( 'wp_ajax_nexifymy_restore_file', array( $this, 'ajax_restore_file' ) );
		add_action( 'wp_ajax_nexifymy_delete_quarantined', array( $this, 'ajax_delete_quarantined' ) );
		add_action( 'wp_ajax_nexifymy_get_quarantined_files', array( $this, 'ajax_get_quarantined' ) );
		add_action( 'wp_ajax_nexifymy_get_deleted_quarantined_files', array( $this, 'ajax_get_deleted_quarantined' ) );
		add_action( 'wp_ajax_nexifymy_restore_deleted_quarantined', array( $this, 'ajax_restore_deleted_quarantined' ) );
		add_action( 'wp_ajax_nexifymy_delete_quarantined_permanently', array( $this, 'ajax_delete_quarantined_permanently' ) );

		// Ensure quarantine directory exists.
		$this->ensure_quarantine_dir();
		$this->ensure_deleted_dir();
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
	 * Get the full path to the recoverable deleted-files directory.
	 *
	 * @return string
	 */
	public function get_deleted_path() {

		return WP_CONTENT_DIR . '/' . self::DELETED_DIR;
	}

	/**
	 * Whether quarantine module is enabled.
	 *
	 * @return bool
	 */
	private function is_enabled() {

		$settings = get_option( 'nexifymy_security_settings', array() );
		if ( ! isset( $settings['modules'] ) || ! is_array( $settings['modules'] ) ) {
			return true;
		}

		if ( ! array_key_exists( 'quarantine_enabled', $settings['modules'] ) ) {
			return true;
		}

		return (bool) $settings['modules']['quarantine_enabled'];
	}

	/**
	 * Ensure a storage directory exists and is protected.
	 *
	 * @param string $storage_path Absolute path.
	 */
	private function ensure_storage_dir( $storage_path ) {

		if ( ! is_dir( $storage_path ) ) {
			wp_mkdir_p( $storage_path );
		}

		$htaccess_path = $storage_path . '/.htaccess';
		if ( ! file_exists( $htaccess_path ) ) {
				file_put_contents( $htaccess_path, "Order Deny,Allow\nDeny from all\n" );
		}

		$index_path = $storage_path . '/index.php';
		if ( ! file_exists( $index_path ) ) {
			file_put_contents( $index_path, "<?php\n// Silence is golden.\n" );
		}
	}
	/**
	 * Ensure the quarantine directory exists and is protected.
	 */
	private function ensure_quarantine_dir() {

		$this->ensure_storage_dir( $this->get_quarantine_path() );
	}

	/**
	 * Ensure deleted-files directory exists and is protected.
	 */
	private function ensure_deleted_dir() {

		$this->ensure_storage_dir( $this->get_deleted_path() );
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
		$abspath   = realpath( ABSPATH );

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
		$ext  = pathinfo( $original_path, PATHINFO_EXTENSION );
		return $hash . '_' . time() . '.' . $ext . '.quarantine';
	}

	/**
	 * Check if auto-quarantine is enabled.
	 *
	 * @return bool
	 */
	public function is_auto_quarantine_enabled() {

		$settings         = get_option( 'nexifymy_security_settings', array() );
		$scanner_settings = isset( $settings['scanner'] ) && is_array( $settings['scanner'] ) ? $settings['scanner'] : array();
		$mode             = sanitize_key( $scanner_settings['quarantine_mode'] ?? '' );
		if ( $mode === 'auto' ) {
			return true;
		}

		// Backward compatibility.
		return ! empty( $scanner_settings['auto_quarantine_enabled'] );
	}
	/**
	 * Move a file to quarantine.
	 *
	 * @param string $file_path Full path to the file.
	 * @param string $reason Reason for quarantine.
	 * @param bool   $manual    Whether this is a manual quarantine (bypasses auto-quarantine check).
	 * @return array|WP_Error Quarantine info or error.
	 */
	public function quarantine_file( $file_path, $reason = '', $manual = false ) {

		if ( ! $this->is_enabled() ) {
			return new WP_Error( 'module_disabled', 'Quarantine module is disabled in settings.' );
		}

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
		$quarantine_filename  = $this->generate_quarantine_filename( $real_path );
		$quarantine_full_path = $this->get_quarantine_path() . '/' . $quarantine_filename;

		// Store file metadata before moving.
		$file_info = array(
			'original_path'   => str_replace( ABSPATH, '', $real_path ),
			'original_full'   => $real_path,
			'quarantine_name' => $quarantine_filename,
			'quarantine_path' => $quarantine_full_path,
			'size'            => filesize( $real_path ),
			'md5'             => md5_file( $real_path ),
			'quarantined_at'  => current_time( 'mysql' ),
			'quarantined_by'  => get_current_user_id(),
			'reason'          => sanitize_text_field( $reason ),
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
		$log       = $this->get_quarantine_log();
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
		$original_path        = ABSPATH . $file_info['original_path'];

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
	 * Move a quarantined file to recoverable deleted storage.
	 *
	 * @param string $quarantine_filename The quarantine filename.
	 * @return array|WP_Error Deleted file info or error.
	 */
	public function delete_quarantined( $quarantine_filename ) {

		$quarantine_full_path = $this->get_quarantine_path() . '/' . $quarantine_filename;

		if ( ! preg_match( '/^[a-f0-9]{32}_\d+\.\w+\.quarantine$/', $quarantine_filename ) ) {
			return new WP_Error( 'invalid_filename', 'Invalid quarantine filename.' );
		}

		if ( ! file_exists( $quarantine_full_path ) ) {
			$this->remove_from_quarantine_log( $quarantine_filename );
			return new WP_Error( 'file_missing', 'File already deleted.' );
		}

		$log       = $this->get_quarantine_log();
		$file_info = null;
		foreach ( $log as $entry ) {
			if ( $entry['quarantine_name'] === $quarantine_filename ) {
				$file_info = $entry;
				break;
			}
		}

		$deleted_name      = $quarantine_filename . '.deleted';
		$deleted_full_path = $this->get_deleted_path() . '/' . $deleted_name;
		if ( ! rename( $quarantine_full_path, $deleted_full_path ) ) {
			return new WP_Error( 'delete_failed', 'Failed to move file to recoverable deleted storage. Check permissions.' );
		}

		$this->remove_from_quarantine_log( $quarantine_filename );

		$deleted_entry                 = $file_info ?: array(
			'quarantine_name' => $quarantine_filename,
			'original_path'   => $quarantine_filename,
			'size'            => 0,
		);
		$deleted_entry['deleted_name'] = $deleted_name;
		$deleted_entry['deleted_path'] = $deleted_full_path;
		$deleted_entry['deleted_at']   = current_time( 'mysql' );
		$deleted_entry['deleted_by']   = get_current_user_id();
		$this->add_to_deleted_log( $deleted_entry );

		if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
			NexifyMy_Security_Logger::log(
				'file_deleted',
				sprintf( 'Quarantined file moved to recoverable deleted storage: %s', $deleted_entry['original_path'] ),
				'warning',
				$deleted_entry
			);
		}

		return $deleted_entry;
	}

	/**
	 * Restore a recoverable deleted file back to quarantine.
	 *
	 * @param string $deleted_name Deleted file name.
	 * @return bool|WP_Error
	 */
	public function restore_deleted_quarantined( $deleted_name ) {

		$deleted_log   = $this->get_deleted_log();
		$deleted_entry = null;
		foreach ( $deleted_log as $entry ) {
			if ( isset( $entry['deleted_name'] ) && $entry['deleted_name'] === $deleted_name ) {
				$deleted_entry = $entry;
				break;
			}
		}

		if ( ! $deleted_entry ) {
			return new WP_Error( 'not_found', 'Deleted-file entry not found.' );
		}

		$deleted_full_path = $this->get_deleted_path() . '/' . $deleted_name;
		if ( ! file_exists( $deleted_full_path ) ) {
			$this->remove_from_deleted_log( $deleted_name );
			return new WP_Error( 'file_missing', 'Deleted file no longer exists.' );
		}

		$quarantine_name = $deleted_entry['quarantine_name'] ?? preg_replace( '/\.deleted$/', '', $deleted_name );
		if ( ! preg_match( '/^[a-f0-9]{32}_\d+\.\w+\.quarantine$/', $quarantine_name ) ) {
			$quarantine_name = md5( $deleted_name . time() ) . '_' . time() . '.php.quarantine';
		}

		$restored_quarantine_path = $this->get_quarantine_path() . '/' . $quarantine_name;
		if ( ! rename( $deleted_full_path, $restored_quarantine_path ) ) {
			return new WP_Error( 'restore_failed', 'Failed to restore deleted file back to quarantine.' );
		}

		$deleted_entry['quarantine_name'] = $quarantine_name;
		$deleted_entry['quarantine_path'] = $restored_quarantine_path;
		unset( $deleted_entry['deleted_name'], $deleted_entry['deleted_path'], $deleted_entry['deleted_at'], $deleted_entry['deleted_by'] );

		$this->remove_from_deleted_log( $deleted_name );
		$this->add_to_quarantine_log( $deleted_entry );

		if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
			NexifyMy_Security_Logger::log(
				'file_restored',
				sprintf( 'Deleted file restored to quarantine: %s', $deleted_entry['original_path'] ?? $deleted_name ),
				'info',
				$deleted_entry
			);
		}

		return true;
	}

	/**
	 * Permanently delete a recoverable deleted file.
	 *
	 * @param string $deleted_name Deleted file name.
	 * @return bool|WP_Error
	 */
	public function permanently_delete_deleted_quarantined( $deleted_name ) {

		$deleted_full_path = $this->get_deleted_path() . '/' . $deleted_name;
		if ( ! file_exists( $deleted_full_path ) ) {
			$this->remove_from_deleted_log( $deleted_name );
			return new WP_Error( 'file_missing', 'File already permanently deleted.' );
		}

		if ( ! unlink( $deleted_full_path ) ) {
			return new WP_Error( 'delete_failed', 'Failed to permanently delete file. Check permissions.' );
		}

		$this->remove_from_deleted_log( $deleted_name );

		if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
			NexifyMy_Security_Logger::log(
				'file_deleted',
				sprintf( 'Deleted file permanently removed: %s', $deleted_name ),
				'info',
				array( 'deleted_name' => $deleted_name )
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
	 * Get recoverable deleted-files log.
	 *
	 * @return array
	 */
	public function get_deleted_log() {

		return get_option( self::DELETED_LOG_OPTION, array() );
	}
	/**
	 * Add entry to quarantine log.
	 *
	 * @param array $file_info File info.
	 */
	private function add_to_quarantine_log( $file_info ) {
		$log   = $this->get_quarantine_log();
		$log[] = $file_info;
		update_option( self::QUARANTINE_LOG_OPTION, $log );
	}

	/**
	 * Remove entry from quarantine log.
	 *
	 * @param string $quarantine_filename The quarantine filename.
	 */
	private function remove_from_quarantine_log( $quarantine_filename ) {

		$log     = $this->get_quarantine_log();
		$new_log = array();

		foreach ( $log as $entry ) {
			if ( $entry['quarantine_name'] !== $quarantine_filename ) {
				$new_log[] = $entry;
			}
		}

		update_option( self::QUARANTINE_LOG_OPTION, $new_log );
	}

	/**
	 * Add entry to deleted-files log.
	 *
	 * @param array $file_info File info.
	 */
	private function add_to_deleted_log( $file_info ) {

		$log   = $this->get_deleted_log();
		$log[] = $file_info;
		update_option( self::DELETED_LOG_OPTION, $log );
	}

	/**
	 * Remove entry from deleted-files log.
	 *
	 * @param string $deleted_name Deleted filename.
	 */
	private function remove_from_deleted_log( $deleted_name ) {

		$log     = $this->get_deleted_log();
		$new_log = array();

		foreach ( $log as $entry ) {
			if ( ( $entry['deleted_name'] ?? '' ) !== $deleted_name ) {
				$new_log[] = $entry;
			}
		}

		update_option( self::DELETED_LOG_OPTION, $new_log );
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

		$file_path = isset( $_POST['file_path'] ) ? sanitize_text_field( wp_unslash( $_POST['file_path'] ) ) : '';
		$reason    = isset( $_POST['reason'] ) ? sanitize_text_field( wp_unslash( $_POST['reason'] ) ) : 'Threat detected';
		$manual    = true;
		// Default to manual.
		if ( isset( $_POST['manual'] ) ) {
			$manual_flag = filter_var( (string) wp_unslash( $_POST['manual'] ), FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE );
			$manual      = null === $manual_flag ? true : $manual_flag;
		}
		if ( empty( $file_path ) ) {
			wp_send_json_error( 'No file path provided.' );
		}

		// Convert relative path to absolute.
		if ( strpos( $file_path, ABSPATH ) !== 0 ) {
			$file_path = ABSPATH . ltrim( $file_path, '/\\' );
		}
		$result = $this->quarantine_file( $file_path, $reason, $manual );

		if ( is_wp_error( $result ) ) {
			wp_send_json_error( $result->get_error_message() );
		}

		wp_send_json_success(
			array(
				'message' => 'File quarantined successfully.',
				'info'    => $result,
			)
		);
	}

	/**
	 * Backward-compatible alias used by scanner "Quarantine" action.
	 */
	public function ajax_delete_file() {

		$this->ajax_quarantine_file();
	}
	/**
	 * Restore a file via AJAX.
	 */
	public function ajax_restore_file() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$filename = isset( $_POST['filename'] ) ? sanitize_file_name( wp_unslash( $_POST['filename'] ) ) : '';
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
	 * Move a quarantined file to recoverable deleted storage via AJAX.
	 */
	public function ajax_delete_quarantined() {

		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$filename = isset( $_POST['filename'] ) ? sanitize_file_name( wp_unslash( $_POST['filename'] ) ) : '';
		if ( empty( $filename ) ) {
			wp_send_json_error( 'No filename provided.' );
		}

		$result = $this->delete_quarantined( $filename );

		if ( is_wp_error( $result ) ) {
			wp_send_json_error( $result->get_error_message() );
		}

		wp_send_json_success(
			array(
				'message' => 'File moved to recoverable deleted storage.',
				'info'    => $result,
			)
		);
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
			$quarantine_path         = $this->get_quarantine_path() . '/' . $entry['quarantine_name'];
			$entry['exists']         = file_exists( $quarantine_path );
			$entry['size_formatted'] = size_format( $entry['size'] );
			$files[]                 = $entry;
		}

		wp_send_json_success(
			array(
				'count' => count( $files ),
				'files' => $files,
			)
		);
	}

	/**
	 * Get list of recoverable deleted files via AJAX.
	 */
	public function ajax_get_deleted_quarantined() {

		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$log   = $this->get_deleted_log();
		$files = array();
		foreach ( $log as $entry ) {
			$deleted_path            = $this->get_deleted_path() . '/' . ( $entry['deleted_name'] ?? '' );
			$entry['exists']         = file_exists( $deleted_path );
			$entry['size_formatted'] = size_format( (int) ( $entry['size'] ?? 0 ) );
			$files[]                 = $entry;
		}

		wp_send_json_success(
			array(
				'count' => count( $files ),
				'files' => $files,
			)
		);
	}

	/**
	 * Restore a deleted file back to quarantine via AJAX.
	 */
	public function ajax_restore_deleted_quarantined() {

		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$deleted_name = isset( $_POST['deleted_name'] ) ? sanitize_file_name( wp_unslash( $_POST['deleted_name'] ) ) : '';
		if ( empty( $deleted_name ) ) {
			wp_send_json_error( 'No deleted filename provided.' );
		}

		$result = $this->restore_deleted_quarantined( $deleted_name );
		if ( is_wp_error( $result ) ) {
			wp_send_json_error( $result->get_error_message() );
		}

		wp_send_json_success( 'File restored to quarantine successfully.' );
	}

	/**
	 * Permanently delete a file from recoverable deleted storage via AJAX.
	 */
	public function ajax_delete_quarantined_permanently() {

		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$deleted_name = isset( $_POST['deleted_name'] ) ? sanitize_file_name( wp_unslash( $_POST['deleted_name'] ) ) : '';
		if ( empty( $deleted_name ) ) {
			wp_send_json_error( 'No deleted filename provided.' );
		}

		$result = $this->permanently_delete_deleted_quarantined( $deleted_name );
		if ( is_wp_error( $result ) ) {
			wp_send_json_error( $result->get_error_message() );
		}

		wp_send_json_success( 'File permanently deleted.' );
	}
}
