<?php
/**
 * Cleanup Module.
 * Now uses Quarantine as the default action instead of direct deletion.
 * Direct deletion is only available for quarantined files (after review).
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_Cleanup {

	/**
	 * Initialize the cleanup tool.
	 */
	public function init() {

		// Reuse the shared Quarantine instance instead of re-registering duplicate hooks.
		if ( ! isset( $GLOBALS['nexifymy_quarantine'] ) || ! ( $GLOBALS['nexifymy_quarantine'] instanceof NexifyMy_Security_Quarantine ) ) {
				require_once NEXIFYMY_SECURITY_PATH . 'modules/quarantine.php';
			$GLOBALS['nexifymy_quarantine'] = new NexifyMy_Security_Quarantine();
			$GLOBALS['nexifymy_quarantine']->init();
		}

		// Legacy fallback endpoint (only if nothing already handles it).
		if ( ! has_action( 'wp_ajax_nexifymy_delete_file' ) ) {
			add_action( 'wp_ajax_nexifymy_delete_file', array( $this, 'ajax_delete_file' ) );
		}
	}
	/**
	 * Handle file "deletion" via AJAX.
	 * This now quarantines the file instead of deleting it directly.
	 */
	public function ajax_delete_file() {
		// 1. Verify Nonce.
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		// 2. Check Permissions.
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		// 3. Get the file path.
		$file_path = isset( $_POST['file_path'] ) ? sanitize_text_field( $_POST['file_path'] ) : '';

		if ( empty( $file_path ) ) {
			wp_send_json_error( 'No file path provided.' );
		}

		// 4. Check for force_delete flag (only admins, opt-in).
		$force_delete = isset( $_POST['force_delete'] ) && $_POST['force_delete'] === 'true';

		// 5. Get quarantine module.
		if ( ! isset( $GLOBALS['nexifymy_quarantine'] ) ) {
			require_once NEXIFYMY_SECURITY_PATH . 'modules/quarantine.php';
			$GLOBALS['nexifymy_quarantine'] = new NexifyMy_Security_Quarantine();
		}

		$quarantine = $GLOBALS['nexifymy_quarantine'];

		// Convert relative path to absolute if needed.
		if ( strpos( $file_path, ABSPATH ) !== 0 ) {
			$file_path = ABSPATH . ltrim( $file_path, '/' );
		}

		// 6. If force_delete AND file is already quarantined, delete it.
		if ( $force_delete ) {
			// This should only work for files already in quarantine.
			$quarantine_path = $quarantine->get_quarantine_path();
			$real_path       = realpath( $file_path );

			if ( $real_path && strpos( $real_path, realpath( $quarantine_path ) ) === 0 ) {
				// It's in quarantine, we can delete.
				$filename = basename( $file_path );
				$result   = $quarantine->delete_quarantined( $filename );

				if ( is_wp_error( $result ) ) {
					wp_send_json_error( $result->get_error_message() );
				}

				wp_send_json_success( 'File permanently deleted from quarantine.' );
			} else {
				wp_send_json_error( 'Direct deletion is only allowed for quarantined files. Use quarantine first.' );
			}
		}

		// 7. Default action: Quarantine the file.
		$result = $quarantine->quarantine_file( $file_path, 'User requested cleanup' );

		if ( is_wp_error( $result ) ) {
			wp_send_json_error( $result->get_error_message() );
		}

		wp_send_json_success(
			array(
				'message'     => 'File has been quarantined (not deleted). You can restore or permanently delete it from the Quarantine section.',
				'quarantined' => true,
				'info'        => $result,
			)
		);
	}
}
