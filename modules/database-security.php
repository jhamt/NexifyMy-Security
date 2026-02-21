<?php
/**
 * Database Security & Backup Module.
 * Provides database backup, optimization, and security features.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_Database {

	/**
	 * Backup directory name.
	 */
	const BACKUP_DIR = 'nexifymy-backups';

	/**
	 * Option key for backup log.
	 */
	const BACKUP_LOG_KEY = 'nexifymy_database_backup_log';

	/**
	 * Default settings.
	 */
	private static $defaults = array(
		'backup_enabled'     => true,
		'backup_schedule'    => 'weekly',
		'max_backups'        => 5,
		'include_transients' => false,
		'auto_optimize'      => false,
	);

	/**
	 * Initialize the database security module.
	 */
	public function init() {
		// AJAX handlers.
		add_action( 'wp_ajax_nexifymy_create_backup', array( $this, 'ajax_create_backup' ) );
		add_action( 'wp_ajax_nexifymy_delete_backup', array( $this, 'ajax_delete_backup' ) );
		add_action( 'wp_ajax_nexifymy_download_backup', array( $this, 'ajax_download_backup' ) );
		add_action( 'wp_ajax_nexifymy_get_backups', array( $this, 'ajax_get_backups' ) );
		add_action( 'wp_ajax_nexifymy_optimize_database', array( $this, 'ajax_optimize_database' ) );
		add_action( 'wp_ajax_nexifymy_get_optimization_stats', array( $this, 'ajax_get_optimization_stats' ) );
		add_action( 'wp_ajax_nexifymy_get_database_info', array( $this, 'ajax_get_database_info' ) );

		// Scheduled backup hook.
		add_action( 'nexifymy_scheduled_backup', array( $this, 'run_scheduled_backup' ) );
	}

	/**
	 * Get the backup directory path.
	 *
	 * @return string
	 */
	public function get_backup_path() {
		$upload_dir = wp_upload_dir();
		return trailingslashit( $upload_dir['basedir'] ) . self::BACKUP_DIR;
	}

	/**
	 * Ensure backup directory exists and is protected.
	 *
	 * @return bool|WP_Error
	 */
	public function ensure_backup_dir() {
		$backup_path = $this->get_backup_path();

		if ( ! file_exists( $backup_path ) ) {
			if ( ! wp_mkdir_p( $backup_path ) ) {
				return new WP_Error( 'mkdir_failed', 'Could not create backup directory.' );
			}
		}

		// Create .htaccess to deny direct access.
		$htaccess_path = $backup_path . '/.htaccess';
		if ( ! file_exists( $htaccess_path ) ) {
			$htaccess_content = "Order deny,allow\nDeny from all";
			file_put_contents( $htaccess_path, $htaccess_content );
		}

		// Create index.php to prevent directory listing.
		$index_path = $backup_path . '/index.php';
		if ( ! file_exists( $index_path ) ) {
			file_put_contents( $index_path, '<?php // Silence is golden.' );
		}

		return true;
	}

	/**
	 * Generate backup filename.
	 *
	 * @return string
	 */
	private function generate_backup_filename() {
		global $wpdb;
		$date    = gmdate( 'Y-m-d_H-i-s' );
		$db_name = $wpdb->dbname;
		$random  = wp_generate_password( 8, false );
		return sanitize_file_name( "{$db_name}_{$date}_{$random}.sql" );
	}

	/**
	 * Create a database backup.
	 *
	 * @return array|WP_Error Backup info or error.
	 */
	public function create_backup() {
		global $wpdb;

		// Ensure backup directory exists.
		$result = $this->ensure_backup_dir();
		if ( is_wp_error( $result ) ) {
			return $result;
		}

		$backup_path = $this->get_backup_path();
		$filename    = $this->generate_backup_filename();
		$filepath    = $backup_path . '/' . $filename;

		// Get settings.
		$settings           = $this->get_settings();
		$include_transients = ! empty( $settings['include_transients'] );

		// Start output buffer.
		$sql  = '';
		$sql .= "-- NexifyMy Security Database Backup\n";
		$sql .= '-- Generated: ' . gmdate( 'Y-m-d H:i:s' ) . " UTC\n";
		$sql .= '-- WordPress Version: ' . get_bloginfo( 'version' ) . "\n";
		$sql .= '-- Site URL: ' . get_site_url() . "\n";
		$sql .= "-- ----------------------------------------\n\n";
		$sql .= "SET SQL_MODE = \"NO_AUTO_VALUE_ON_ZERO\";\n";
		$sql .= "SET time_zone = \"+00:00\";\n\n";

		// Get all tables with the WordPress prefix.
		$tables = $wpdb->get_results( 'SHOW TABLES', ARRAY_N );

		if ( empty( $tables ) ) {
			return new WP_Error( 'no_tables', 'No database tables found.' );
		}

		$tables_exported = 0;
		$rows_exported   = 0;

		foreach ( $tables as $table ) {
			$table_name = $table[0];

			// Only backup tables with WordPress prefix.
			if ( strpos( $table_name, $wpdb->prefix ) !== 0 ) {
				continue;
			}

			// Validate table name contains only allowed characters.
			if ( ! preg_match( '/^[a-zA-Z0-9_]+$/', $table_name ) ) {
				continue;
			}

			// Check if this is the options table (for transient filtering).
			$is_options_table = ( $table_name === $wpdb->prefix . 'options' );

			// Get table structure (table name validated above).
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$create_table = $wpdb->get_row( "SHOW CREATE TABLE `{$table_name}`", ARRAY_N );
			if ( $create_table ) {
				$sql .= "\n-- Table structure for `{$table_name}`\n";
				$sql .= "DROP TABLE IF EXISTS `{$table_name}`;\n";
				$sql .= $create_table[1] . ";\n\n";
			}

			// Get table data (table name validated above).
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$rows = $wpdb->get_results( "SELECT * FROM `{$table_name}`", ARRAY_A );

			if ( ! empty( $rows ) ) {
				$sql .= "-- Data for `{$table_name}`\n";

				foreach ( $rows as $row ) {
					// Skip transient rows in options table if disabled.
					if ( $is_options_table && ! $include_transients ) {
						$option_name = isset( $row['option_name'] ) ? $row['option_name'] : '';
						if ( strpos( $option_name, '_transient_' ) === 0 || strpos( $option_name, '_site_transient_' ) === 0 ) {
							continue;
						}
					}

					$values = array();
					foreach ( $row as $value ) {
						if ( is_null( $value ) ) {
							$values[] = 'NULL';
						} else {
							$values[] = "'" . $wpdb->_real_escape( $value ) . "'";
						}
					}
					$sql .= "INSERT INTO `{$table_name}` VALUES (" . implode( ', ', $values ) . ");\n";
					++$rows_exported;
				}
				$sql .= "\n";
			}

			++$tables_exported;
		}

		// Write to file.
		$bytes_written = file_put_contents( $filepath, $sql );

		if ( false === $bytes_written ) {
			return new WP_Error( 'write_failed', 'Could not write backup file.' );
		}

		// Log the backup.
		$backup_info = array(
			'filename'   => $filename,
			'filepath'   => $filepath,
			'size'       => $bytes_written,
			'tables'     => $tables_exported,
			'rows'       => $rows_exported,
			'created_at' => time(),
		);

		$this->add_to_backup_log( $backup_info );

		// Auto-delete old backups.
		$this->cleanup_old_backups();

		// Log the action.
		if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
			NexifyMy_Security_Logger::log(
				'database_backup',
				sprintf( 'Database backup created: %s (%s)', $filename, size_format( $bytes_written ) ),
				'info',
				array(
					'tables' => $tables_exported,
					'rows'   => $rows_exported,
				)
			);
		}

		return $backup_info;
	}

	/**
	 * Get list of existing backups.
	 *
	 * @return array
	 */
	public function get_backups() {
		$backup_log = get_option( self::BACKUP_LOG_KEY, array() );

		// Verify files still exist.
		$valid_backups = array();
		foreach ( $backup_log as $backup ) {
			if ( isset( $backup['filepath'] ) && file_exists( $backup['filepath'] ) ) {
				$backup['size']  = filesize( $backup['filepath'] );
				$valid_backups[] = $backup;
			}
		}

		// Sort by created_at descending.
		usort(
			$valid_backups,
			function ( $a, $b ) {
				return ( $b['created_at'] ?? 0 ) - ( $a['created_at'] ?? 0 );
			}
		);

		return $valid_backups;
	}

	/**
	 * Delete a backup file.
	 *
	 * @param string $filename Backup filename.
	 * @return bool|WP_Error
	 */
	public function delete_backup( $filename ) {
		$backup_path = $this->get_backup_path();
		$filepath    = $backup_path . '/' . sanitize_file_name( $filename );

		// Validate file is within backup directory.
		if ( strpos( realpath( $filepath ), realpath( $backup_path ) ) !== 0 ) {
			return new WP_Error( 'invalid_path', 'Invalid backup file path.' );
		}

		if ( ! file_exists( $filepath ) ) {
			return new WP_Error( 'not_found', 'Backup file not found.' );
		}

		if ( ! unlink( $filepath ) ) {
			return new WP_Error( 'delete_failed', 'Could not delete backup file.' );
		}

		// Remove from log.
		$this->remove_from_backup_log( $filename );

		// Log the action.
		if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
			NexifyMy_Security_Logger::log(
				'database_backup_deleted',
				sprintf( 'Database backup deleted: %s', $filename ),
				'info',
				array()
			);
		}

		return true;
	}

	/**
	 * Add entry to backup log.
	 *
	 * @param array $backup_info Backup info.
	 */
	private function add_to_backup_log( $backup_info ) {
		$log   = get_option( self::BACKUP_LOG_KEY, array() );
		$log[] = $backup_info;
		update_option( self::BACKUP_LOG_KEY, $log );
	}

	/**
	 * Remove entry from backup log.
	 *
	 * @param string $filename Filename to remove.
	 */
	private function remove_from_backup_log( $filename ) {
		$log = get_option( self::BACKUP_LOG_KEY, array() );
		$log = array_filter(
			$log,
			function ( $entry ) use ( $filename ) {
				return $entry['filename'] !== $filename;
			}
		);
		update_option( self::BACKUP_LOG_KEY, array_values( $log ) );
	}

	/**
	 * Cleanup old backups beyond max_backups limit.
	 */
	private function cleanup_old_backups() {
		$settings    = $this->get_settings();
		$max_backups = absint( $settings['max_backups'] ) ?: 5;

		$backups = $this->get_backups();

		if ( count( $backups ) > $max_backups ) {
			$to_delete = array_slice( $backups, $max_backups );
			foreach ( $to_delete as $backup ) {
				$this->delete_backup( $backup['filename'] );
			}
		}
	}

	/**
	 * Get optimization statistics.
	 *
	 * @return array
	 */
	public function get_optimization_stats() {
		global $wpdb;

		$stats = array(
			'transients'     => 0,
			'revisions'      => 0,
			'spam_comments'  => 0,
			'trash_comments' => 0,
			'trash_posts'    => 0,
			'orphan_meta'    => 0,
		);

		// Transients.
		$stats['transients'] = (int) $wpdb->get_var(
			"SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name LIKE '_transient_%' OR option_name LIKE '_site_transient_%'"
		);

		// Revisions.
		$stats['revisions'] = (int) $wpdb->get_var(
			"SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_type = 'revision'"
		);

		// Spam comments.
		$stats['spam_comments'] = (int) $wpdb->get_var(
			"SELECT COUNT(*) FROM {$wpdb->comments} WHERE comment_approved = 'spam'"
		);

		// Trash comments.
		$stats['trash_comments'] = (int) $wpdb->get_var(
			"SELECT COUNT(*) FROM {$wpdb->comments} WHERE comment_approved = 'trash'"
		);

		// Trash posts.
		$stats['trash_posts'] = (int) $wpdb->get_var(
			"SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_status = 'trash'"
		);

		// Orphaned post meta.
		$stats['orphan_meta'] = (int) $wpdb->get_var(
			"SELECT COUNT(*) FROM {$wpdb->postmeta} WHERE post_id NOT IN (SELECT ID FROM {$wpdb->posts})"
		);

		$stats['total'] = array_sum( $stats );

		return $stats;
	}

	/**
	 * Optimize the database by cleaning unnecessary data.
	 *
	 * @param array $options What to clean.
	 * @return array Cleaned counts.
	 */
	public function optimize_database( $options = array() ) {
		global $wpdb;

		$defaults = array(
			'transients'     => true,
			'revisions'      => true,
			'spam_comments'  => true,
			'trash_comments' => true,
			'trash_posts'    => true,
			'orphan_meta'    => true,
		);

		$options = wp_parse_args( $options, $defaults );
		$cleaned = array();

		// Clean transients.
		if ( ! empty( $options['transients'] ) ) {
			$cleaned['transients'] = $wpdb->query(
				"DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_%' OR option_name LIKE '_site_transient_%'"
			);
		}

		// Clean revisions.
		if ( ! empty( $options['revisions'] ) ) {
			$cleaned['revisions'] = $wpdb->query(
				"DELETE FROM {$wpdb->posts} WHERE post_type = 'revision'"
			);
		}

		// Clean spam comments.
		if ( ! empty( $options['spam_comments'] ) ) {
			$cleaned['spam_comments'] = $wpdb->query(
				"DELETE FROM {$wpdb->comments} WHERE comment_approved = 'spam'"
			);
		}

		// Clean trash comments.
		if ( ! empty( $options['trash_comments'] ) ) {
			$cleaned['trash_comments'] = $wpdb->query(
				"DELETE FROM {$wpdb->comments} WHERE comment_approved = 'trash'"
			);
		}

		// Clean trash posts.
		if ( ! empty( $options['trash_posts'] ) ) {
			$cleaned['trash_posts'] = $wpdb->query(
				"DELETE FROM {$wpdb->posts} WHERE post_status = 'trash'"
			);
		}

		// Clean orphaned meta.
		if ( ! empty( $options['orphan_meta'] ) ) {
			$cleaned['orphan_meta'] = $wpdb->query(
				"DELETE FROM {$wpdb->postmeta} WHERE post_id NOT IN (SELECT ID FROM {$wpdb->posts})"
			);
		}

		// Optimize tables.
		$tables = $wpdb->get_col( 'SHOW TABLES' );
		foreach ( $tables as $table ) {
			// Validate table name and check prefix.
			if ( strpos( $table, $wpdb->prefix ) === 0 && preg_match( '/^[a-zA-Z0-9_]+$/', $table ) ) {
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$wpdb->query( "OPTIMIZE TABLE `{$table}`" );
			}
		}

		$cleaned['total'] = array_sum( $cleaned );

		// Log the action.
		if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
			NexifyMy_Security_Logger::log(
				'database_optimized',
				sprintf( 'Database optimized: %d items cleaned', $cleaned['total'] ),
				'info',
				$cleaned
			);
		}

		return $cleaned;
	}

	/**
	 * Get database info and security status.
	 *
	 * @return array
	 */
	public function get_database_info() {
		global $wpdb;

		$info = array(
			'prefix'            => $wpdb->prefix,
			'is_default_prefix' => ( $wpdb->prefix === 'wp_' ),
			'database_name'     => $wpdb->dbname,
			'database_size'     => 0,
			'table_count'       => 0,
		);

		// Get database size.
		$size_query = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT SUM(data_length + index_length) as size FROM information_schema.TABLES WHERE table_schema = %s',
				$wpdb->dbname
			)
		);

		if ( $size_query ) {
			$info['database_size']           = (int) $size_query->size;
			$info['database_size_formatted'] = size_format( $info['database_size'] );
		}

		// Get table count.
		$tables              = $wpdb->get_var(
			$wpdb->prepare(
				'SELECT COUNT(*) FROM information_schema.TABLES WHERE table_schema = %s AND table_name LIKE %s',
				$wpdb->dbname,
				$wpdb->prefix . '%'
			)
		);
		$info['table_count'] = (int) $tables;

		return $info;
	}

	/**
	 * Get module settings.
	 *
	 * @return array
	 */
	public function get_settings() {
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$all_settings = NexifyMy_Security_Settings::get_all();
			if ( isset( $all_settings['database'] ) ) {
				return wp_parse_args( $all_settings['database'], self::$defaults );
			}
		}
		return self::$defaults;
	}

	/**
	 * Schedule database backup.
	 *
	 * @param string $frequency 'daily', 'weekly', or 'none'.
	 */
	public function schedule_backup( $frequency = 'weekly' ) {
		// Clear existing schedule.
		wp_clear_scheduled_hook( 'nexifymy_scheduled_backup' );

		if ( 'none' === $frequency ) {
			return;
		}

		$interval = 'daily' === $frequency ? 'daily' : 'weekly';
		wp_schedule_event( time() + HOUR_IN_SECONDS, $interval, 'nexifymy_scheduled_backup' );
	}

	/**
	 * Run scheduled backup.
	 */
	public function run_scheduled_backup() {
		$settings = $this->get_settings();

		if ( empty( $settings['backup_enabled'] ) ) {
			return;
		}

		$result = $this->create_backup();

		if ( is_wp_error( $result ) ) {
			if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
				NexifyMy_Security_Logger::log(
					'scheduled_backup_failed',
					'Scheduled database backup failed: ' . $result->get_error_message(),
					'error',
					array()
				);
			}
			return;
		}

		// Auto-optimize if enabled.
		if ( ! empty( $settings['auto_optimize'] ) ) {
			$this->optimize_database();
		}

		// Trigger alert.
		do_action( 'nexifymy_security_alert', 'backup_complete', 'Scheduled database backup completed successfully.', $result );
	}

	/*
	 * =========================================================================
	 * AJAX HANDLERS
	 * =========================================================================
	 */

	/**
	 * Create backup via AJAX.
	 */
	public function ajax_create_backup() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$result = $this->create_backup();

		if ( is_wp_error( $result ) ) {
			wp_send_json_error( $result->get_error_message() );
		}

		wp_send_json_success(
			array(
				'message' => 'Backup created successfully.',
				'backup'  => $result,
			)
		);
	}

	/**
	 * Delete backup via AJAX.
	 */
	public function ajax_delete_backup() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$filename = isset( $_POST['filename'] ) ? sanitize_file_name( wp_unslash( $_POST['filename'] ) ) : '';
		if ( empty( $filename ) ) {
			wp_send_json_error( 'Filename required.' );
		}

		$result = $this->delete_backup( $filename );

		if ( is_wp_error( $result ) ) {
			wp_send_json_error( $result->get_error_message() );
		}

		wp_send_json_success( array( 'message' => 'Backup deleted.' ) );
	}

	/**
	 * Download backup via AJAX.
	 */
	public function ajax_download_backup() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Unauthorized' );
		}

		$filename = isset( $_GET['filename'] ) ? sanitize_file_name( wp_unslash( $_GET['filename'] ) ) : '';
		if ( empty( $filename ) ) {
			wp_die( 'Filename required.' );
		}

		$backup_path = $this->get_backup_path();
		$filepath    = $backup_path . '/' . $filename;

		// Validate file is within backup directory.
		if ( ! file_exists( $filepath ) || strpos( realpath( $filepath ), realpath( $backup_path ) ) !== 0 ) {
			wp_die( 'Backup file not found.' );
		}

		// Serve file for download.
		header( 'Content-Type: application/sql' );
		header( 'Content-Disposition: attachment; filename="' . $filename . '"' );
		header( 'Content-Length: ' . filesize( $filepath ) );
		header( 'Cache-Control: no-cache, no-store, must-revalidate' );
		header( 'Pragma: no-cache' );
		header( 'Expires: 0' );

		readfile( $filepath );
		exit;
	}

	/**
	 * Get backups list via AJAX.
	 */
	public function ajax_get_backups() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$backups = $this->get_backups();

		// Format for display.
		foreach ( $backups as &$backup ) {
			$backup['size_formatted']       = size_format( $backup['size'] );
			$backup['created_at_formatted'] = date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $backup['created_at'] );
		}

		wp_send_json_success( array( 'backups' => $backups ) );
	}

	/**
	 * Optimize database via AJAX.
	 */
	public function ajax_optimize_database() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$options = isset( $_POST['options'] ) && is_array( $_POST['options'] )
		? array_map( 'sanitize_text_field', wp_unslash( $_POST['options'] ) )
			: array();
		$result  = $this->optimize_database( $options );
		wp_send_json_success(
			array(
				'message' => sprintf( 'Optimization complete. %d items cleaned.', $result['total'] ),
				'cleaned' => $result,
			)
		);
	}

	/**
	 * Get optimization stats via AJAX.
	 */
	public function ajax_get_optimization_stats() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$stats = $this->get_optimization_stats();
		wp_send_json_success( array( 'stats' => $stats ) );
	}

	/**
	 * Get database info via AJAX.
	 */
	public function ajax_get_database_info() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$info = $this->get_database_info();
		wp_send_json_success( array( 'info' => $info ) );
	}
}
