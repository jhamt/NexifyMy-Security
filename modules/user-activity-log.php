<?php
/**
 * User Activity Log Module.
 * Tracks user logins, logouts, failed attempts, profile changes,
 * content edits, plugin/theme changes, settings modifications, and more.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_Activity_Log {

	/**
	 * Database table name (without prefix).
	 */
	const TABLE_NAME = 'nexifymy_activity_log';

	/**
	 * Event groups.
	 */
	const GROUP_AUTH     = 'authentication';
	const GROUP_USER     = 'user';
	const GROUP_CONTENT  = 'content';
	const GROUP_SYSTEM   = 'system';
	const GROUP_SECURITY = 'security';

	/**
	 * Default settings.
	 */
	private static $defaults = array(
		'enabled'                => true,
		'log_logins'             => true,
		'log_failed_logins'      => true,
		'log_logouts'            => true,
		'log_profile_changes'    => true,
		'log_role_changes'       => true,
		'log_user_creation'      => true,
		'log_user_deletion'      => true,
		'log_password_changes'   => true,
		'log_post_changes'       => true,
		'log_page_changes'       => true,
		'log_media_uploads'      => true,
		'log_plugin_changes'     => true,
		'log_theme_changes'      => true,
		'log_option_changes'     => true,
		'log_widget_changes'     => true,
		'log_menu_changes'       => true,
		'log_export'             => true,
		'retention_days'         => 90,
		'excluded_users'         => array(),
		'excluded_post_types'    => array( 'revision', 'nav_menu_item' ),
		'excluded_options'       => array( '_transient_', '_site_transient_', 'cron', 'session_tokens' ),
	);

	/**
	 * Initialize the module.
	 */
	public function init() {
		$all_settings = get_option( 'nexifymy_security_settings', array() );
		if ( isset( $all_settings['modules']['activity_log_enabled'] ) && ! $all_settings['modules']['activity_log_enabled'] ) {
			return;
		}

		$settings = $this->get_settings();
		if ( empty( $settings['enabled'] ) ) {
			return;
		}

		// Create database table if needed.
		$this->maybe_create_table();

		// Authentication hooks.
		if ( ! empty( $settings['log_logins'] ) ) {
			add_action( 'wp_login', array( $this, 'on_login' ), 10, 2 );
		}
		if ( ! empty( $settings['log_failed_logins'] ) ) {
			add_action( 'wp_login_failed', array( $this, 'on_login_failed' ), 10, 2 );
		}
		if ( ! empty( $settings['log_logouts'] ) ) {
			add_action( 'wp_logout', array( $this, 'on_logout' ), 10, 1 );
		}

		// User hooks.
		if ( ! empty( $settings['log_profile_changes'] ) ) {
			add_action( 'profile_update', array( $this, 'on_profile_update' ), 10, 3 );
		}
		if ( ! empty( $settings['log_role_changes'] ) ) {
			add_action( 'set_user_role', array( $this, 'on_role_change' ), 10, 3 );
		}
		if ( ! empty( $settings['log_user_creation'] ) ) {
			add_action( 'user_register', array( $this, 'on_user_register' ), 10, 2 );
		}
		if ( ! empty( $settings['log_user_deletion'] ) ) {
			add_action( 'delete_user', array( $this, 'on_user_delete' ), 10, 3 );
		}
		if ( ! empty( $settings['log_password_changes'] ) ) {
			add_action( 'after_password_reset', array( $this, 'on_password_reset' ), 10, 2 );
		}

		// Content hooks.
		if ( ! empty( $settings['log_post_changes'] ) || ! empty( $settings['log_page_changes'] ) ) {
			add_action( 'transition_post_status', array( $this, 'on_post_status_change' ), 10, 3 );
			add_action( 'before_delete_post', array( $this, 'on_post_delete' ), 10, 2 );
		}
		if ( ! empty( $settings['log_media_uploads'] ) ) {
			add_action( 'add_attachment', array( $this, 'on_media_upload' ), 10, 1 );
			add_action( 'delete_attachment', array( $this, 'on_media_delete' ), 10, 1 );
		}

		// System hooks.
		if ( ! empty( $settings['log_plugin_changes'] ) ) {
			add_action( 'activated_plugin', array( $this, 'on_plugin_activate' ), 10, 2 );
			add_action( 'deactivated_plugin', array( $this, 'on_plugin_deactivate' ), 10, 2 );
			add_action( 'upgrader_process_complete', array( $this, 'on_plugin_update' ), 10, 2 );
			add_action( 'deleted_plugin', array( $this, 'on_plugin_delete' ), 10, 2 );
		}
		if ( ! empty( $settings['log_theme_changes'] ) ) {
			add_action( 'switch_theme', array( $this, 'on_theme_switch' ), 10, 3 );
		}
		if ( ! empty( $settings['log_option_changes'] ) ) {
			add_action( 'updated_option', array( $this, 'on_option_update' ), 10, 3 );
		}
		if ( ! empty( $settings['log_export'] ) ) {
			add_action( 'export_wp', array( $this, 'on_export' ), 10, 1 );
		}

		// Cleanup cron.
		if ( ! wp_next_scheduled( 'nexifymy_activity_log_cleanup' ) ) {
			wp_schedule_event( time(), 'daily', 'nexifymy_activity_log_cleanup' );
		}
		add_action( 'nexifymy_activity_log_cleanup', array( $this, 'purge_old_entries' ) );

		// AJAX handlers.
		add_action( 'wp_ajax_nexifymy_get_activity_log', array( $this, 'ajax_get_activity_log' ) );
		add_action( 'wp_ajax_nexifymy_export_activity_log', array( $this, 'ajax_export_activity_log' ) );
		add_action( 'wp_ajax_nexifymy_purge_activity_log', array( $this, 'ajax_purge_activity_log' ) );
		add_action( 'wp_ajax_nexifymy_get_activity_stats', array( $this, 'ajax_get_activity_stats' ) );
	}

	/**
	 * Get module settings.
	 */
	public function get_settings() {
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$all_settings = NexifyMy_Security_Settings::get_all();
			if ( isset( $all_settings['activity_log'] ) ) {
				return wp_parse_args( $all_settings['activity_log'], self::$defaults );
			}
		}
		return self::$defaults;
	}

	/**
	 * Create the database table if it doesn't exist.
	 * This method is public so it can be called from the activation hook.
	 */
	public function maybe_create_table() {
		global $wpdb;
		$table = $wpdb->prefix . self::TABLE_NAME;

		if ( get_option( 'nexifymy_activity_log_db_version' ) === '1.0' ) {
			return;
		}

		// Only run table creation in admin context to avoid loading wp-admin files on frontend
		if ( ! is_admin() && ! defined( 'WP_CLI' ) ) {
			return;
		}

		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE IF NOT EXISTS {$table} (
			id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			user_id BIGINT(20) UNSIGNED DEFAULT 0,
			username VARCHAR(60) DEFAULT '',
			user_role VARCHAR(60) DEFAULT '',
			event_type VARCHAR(60) NOT NULL,
			event_group VARCHAR(30) NOT NULL DEFAULT 'system',
			severity VARCHAR(20) NOT NULL DEFAULT 'info',
			object_type VARCHAR(60) DEFAULT '',
			object_id BIGINT(20) UNSIGNED DEFAULT 0,
			object_name VARCHAR(255) DEFAULT '',
			description TEXT NOT NULL,
			ip_address VARCHAR(45) DEFAULT '',
			user_agent VARCHAR(512) DEFAULT '',
			metadata LONGTEXT DEFAULT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY  (id),
			KEY idx_user_id (user_id),
			KEY idx_event_type (event_type),
			KEY idx_event_group (event_group),
			KEY idx_severity (severity),
			KEY idx_created_at (created_at),
			KEY idx_ip_address (ip_address)
		) {$charset_collate};";

		// Safely load upgrade functions only if available
		if ( ! function_exists( 'dbDelta' ) ) {
			require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		}
		dbDelta( $sql );

		update_option( 'nexifymy_activity_log_db_version', '1.0' );
	}

	// ─── Core Logging Method ─────────────────────────────────────────────

	/**
	 * Insert an activity log entry.
	 */
	public function log( $event_type, $event_group, $description, $args = array() ) {
		global $wpdb;

		$settings = $this->get_settings();
		$current_user = wp_get_current_user();

		// Check excluded users.
		if ( ! empty( $settings['excluded_users'] ) && $current_user->ID > 0 ) {
			if ( in_array( $current_user->user_login, $settings['excluded_users'], true ) ) {
				return false;
			}
		}

		$data = array(
			'user_id'     => isset( $args['user_id'] ) ? absint( $args['user_id'] ) : $current_user->ID,
			'username'    => isset( $args['username'] ) ? sanitize_user( $args['username'] ) : ( $current_user->ID > 0 ? $current_user->user_login : 'guest' ),
			'user_role'   => isset( $args['user_role'] ) ? sanitize_text_field( $args['user_role'] ) : ( ! empty( $current_user->roles ) ? implode( ', ', $current_user->roles ) : 'none' ),
			'event_type'  => sanitize_key( $event_type ),
			'event_group' => sanitize_key( $event_group ),
			'severity'    => isset( $args['severity'] ) ? sanitize_key( $args['severity'] ) : 'info',
			'object_type' => isset( $args['object_type'] ) ? sanitize_text_field( $args['object_type'] ) : '',
			'object_id'   => isset( $args['object_id'] ) ? absint( $args['object_id'] ) : 0,
			'object_name' => isset( $args['object_name'] ) ? sanitize_text_field( $args['object_name'] ) : '',
			'description' => sanitize_text_field( $description ),
			'ip_address'  => $this->get_client_ip(),
			'user_agent'  => isset( $_SERVER['HTTP_USER_AGENT'] ) ? substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ), 0, 512 ) : '',
			'metadata'    => isset( $args['metadata'] ) ? wp_json_encode( $args['metadata'] ) : null,
			'created_at'  => current_time( 'mysql' ),
		);

		$table = $wpdb->prefix . self::TABLE_NAME;
		return $wpdb->insert( $table, $data );
	}

	// ─── Authentication Events ───────────────────────────────────────────

	/**
	 * User logged in.
	 */
	public function on_login( $user_login, $user ) {
		$this->log( 'login_success', self::GROUP_AUTH,
			sprintf( 'User "%s" logged in successfully', $user_login ),
			array(
				'user_id'     => $user->ID,
				'username'    => $user_login,
				'user_role'   => implode( ', ', $user->roles ),
				'object_type' => 'user',
				'object_id'   => $user->ID,
				'object_name' => $user->display_name,
				'severity'    => 'info',
			)
		);
	}

	/**
	 * Failed login attempt.
	 */
	public function on_login_failed( $username, $error = null ) {
		$error_msg = '';
		if ( $error instanceof WP_Error ) {
			$codes = $error->get_error_codes();
			$error_msg = ! empty( $codes ) ? implode( ', ', $codes ) : '';
		}

		$this->log( 'login_failed', self::GROUP_AUTH,
			sprintf( 'Failed login attempt for username "%s"', $username ),
			array(
				'user_id'     => 0,
				'username'    => $username,
				'user_role'   => 'none',
				'object_type' => 'user',
				'object_name' => $username,
				'severity'    => 'warning',
				'metadata'    => array( 'error' => $error_msg ),
			)
		);
	}

	/**
	 * User logged out.
	 */
	public function on_logout( $user_id ) {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}

		$this->log( 'logout', self::GROUP_AUTH,
			sprintf( 'User "%s" logged out', $user->user_login ),
			array(
				'user_id'     => $user->ID,
				'username'    => $user->user_login,
				'user_role'   => implode( ', ', $user->roles ),
				'object_type' => 'user',
				'object_id'   => $user->ID,
				'object_name' => $user->display_name,
			)
		);
	}

	// ─── User Events ─────────────────────────────────────────────────────

	/**
	 * User profile updated.
	 */
	public function on_profile_update( $user_id, $old_user_data, $userdata = array() ) {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}

		$changes = array();
		if ( $old_user_data->user_email !== $user->user_email ) {
			$changes[] = sprintf( 'email changed from %s to %s', $old_user_data->user_email, $user->user_email );
		}
		if ( $old_user_data->display_name !== $user->display_name ) {
			$changes[] = sprintf( 'display name changed to %s', $user->display_name );
		}
		if ( $old_user_data->user_url !== $user->user_url ) {
			$changes[] = 'website URL changed';
		}

		$desc = ! empty( $changes )
			? sprintf( 'Profile updated for "%s": %s', $user->user_login, implode( '; ', $changes ) )
			: sprintf( 'Profile updated for "%s"', $user->user_login );

		$this->log( 'profile_update', self::GROUP_USER, $desc, array(
			'user_id'     => $user->ID,
			'username'    => $user->user_login,
			'user_role'   => implode( ', ', $user->roles ),
			'object_type' => 'user',
			'object_id'   => $user->ID,
			'object_name' => $user->display_name,
			'metadata'    => array( 'changes' => $changes ),
		) );
	}

	/**
	 * User role changed.
	 */
	public function on_role_change( $user_id, $role, $old_roles ) {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}

		$old = ! empty( $old_roles ) ? implode( ', ', $old_roles ) : 'none';

		$this->log( 'role_change', self::GROUP_USER,
			sprintf( 'Role changed for "%s": %s → %s', $user->user_login, $old, $role ),
			array(
				'user_id'     => $user->ID,
				'username'    => $user->user_login,
				'user_role'   => $role,
				'object_type' => 'user',
				'object_id'   => $user->ID,
				'object_name' => $user->display_name,
				'severity'    => 'warning',
				'metadata'    => array( 'old_roles' => $old_roles, 'new_role' => $role ),
			)
		);
	}

	/**
	 * New user registered.
	 */
	public function on_user_register( $user_id, $userdata = array() ) {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}

		$this->log( 'user_created', self::GROUP_USER,
			sprintf( 'New user registered: "%s" (%s)', $user->user_login, $user->user_email ),
			array(
				'object_type' => 'user',
				'object_id'   => $user->ID,
				'object_name' => $user->user_login,
				'severity'    => 'notice',
				'metadata'    => array( 'email' => $user->user_email, 'role' => implode( ', ', $user->roles ) ),
			)
		);
	}

	/**
	 * User deleted.
	 */
	public function on_user_delete( $user_id, $reassign = null, $user = null ) {
		if ( ! $user ) {
			$user = get_userdata( $user_id );
		}
		$name = $user ? $user->user_login : "ID:{$user_id}";

		$this->log( 'user_deleted', self::GROUP_USER,
			sprintf( 'User deleted: "%s"', $name ),
			array(
				'object_type' => 'user',
				'object_id'   => $user_id,
				'object_name' => $name,
				'severity'    => 'warning',
				'metadata'    => array( 'reassigned_to' => $reassign ),
			)
		);
	}

	/**
	 * Password reset.
	 */
	public function on_password_reset( $user, $new_pass ) {
		if ( ! $user ) {
			return;
		}

		$this->log( 'password_reset', self::GROUP_USER,
			sprintf( 'Password reset for "%s"', $user->user_login ),
			array(
				'user_id'     => $user->ID,
				'username'    => $user->user_login,
				'user_role'   => implode( ', ', $user->roles ),
				'object_type' => 'user',
				'object_id'   => $user->ID,
				'object_name' => $user->display_name,
				'severity'    => 'notice',
			)
		);
	}

	// ─── Content Events ──────────────────────────────────────────────────

	/**
	 * Post status changed (create, update, publish, trash).
	 */
	public function on_post_status_change( $new_status, $old_status, $post ) {
		if ( ! $post || wp_is_post_revision( $post->ID ) ) {
			return;
		}

		$settings = $this->get_settings();
		$excluded = ! empty( $settings['excluded_post_types'] ) ? $settings['excluded_post_types'] : array();
		if ( in_array( $post->post_type, $excluded, true ) ) {
			return;
		}

		// Skip if not tracking this post type.
		if ( $post->post_type === 'page' && empty( $settings['log_page_changes'] ) ) {
			return;
		}
		if ( $post->post_type === 'post' && empty( $settings['log_post_changes'] ) ) {
			return;
		}

		// Determine event type.
		if ( $old_status === 'new' || $old_status === 'auto-draft' ) {
			$event = 'content_created';
			$desc = sprintf( '%s created: "%s"', ucfirst( $post->post_type ), $post->post_title );
		} elseif ( $new_status === 'trash' ) {
			$event = 'content_trashed';
			$desc = sprintf( '%s trashed: "%s"', ucfirst( $post->post_type ), $post->post_title );
		} elseif ( $new_status === 'publish' && $old_status !== 'publish' ) {
			$event = 'content_published';
			$desc = sprintf( '%s published: "%s"', ucfirst( $post->post_type ), $post->post_title );
		} elseif ( $old_status === $new_status ) {
			$event = 'content_updated';
			$desc = sprintf( '%s updated: "%s"', ucfirst( $post->post_type ), $post->post_title );
		} else {
			$event = 'content_status_changed';
			$desc = sprintf( '%s "%s" status: %s → %s', ucfirst( $post->post_type ), $post->post_title, $old_status, $new_status );
		}

		$this->log( $event, self::GROUP_CONTENT, $desc, array(
			'object_type' => $post->post_type,
			'object_id'   => $post->ID,
			'object_name' => $post->post_title,
			'metadata'    => array( 'old_status' => $old_status, 'new_status' => $new_status ),
		) );
	}

	/**
	 * Post permanently deleted.
	 */
	public function on_post_delete( $post_id, $post ) {
		if ( ! $post || wp_is_post_revision( $post_id ) ) {
			return;
		}

		$settings = $this->get_settings();
		$excluded = ! empty( $settings['excluded_post_types'] ) ? $settings['excluded_post_types'] : array();
		if ( in_array( $post->post_type, $excluded, true ) ) {
			return;
		}

		$this->log( 'content_deleted', self::GROUP_CONTENT,
			sprintf( '%s permanently deleted: "%s"', ucfirst( $post->post_type ), $post->post_title ),
			array(
				'object_type' => $post->post_type,
				'object_id'   => $post_id,
				'object_name' => $post->post_title,
				'severity'    => 'warning',
			)
		);
	}

	/**
	 * Media uploaded.
	 */
	public function on_media_upload( $attachment_id ) {
		$attachment = get_post( $attachment_id );
		if ( ! $attachment ) {
			return;
		}

		$this->log( 'media_uploaded', self::GROUP_CONTENT,
			sprintf( 'Media uploaded: "%s"', $attachment->post_title ),
			array(
				'object_type' => 'attachment',
				'object_id'   => $attachment_id,
				'object_name' => $attachment->post_title,
				'metadata'    => array(
					'mime_type' => $attachment->post_mime_type,
					'file'      => get_attached_file( $attachment_id ),
				),
			)
		);
	}

	/**
	 * Media deleted.
	 */
	public function on_media_delete( $attachment_id ) {
		$attachment = get_post( $attachment_id );
		$name = $attachment ? $attachment->post_title : "ID:{$attachment_id}";

		$this->log( 'media_deleted', self::GROUP_CONTENT,
			sprintf( 'Media deleted: "%s"', $name ),
			array(
				'object_type' => 'attachment',
				'object_id'   => $attachment_id,
				'object_name' => $name,
				'severity'    => 'notice',
			)
		);
	}

	// ─── System Events ───────────────────────────────────────────────────

	/**
	 * Plugin activated.
	 */
	public function on_plugin_activate( $plugin, $network_wide ) {
		$plugin_data = get_plugin_data( WP_PLUGIN_DIR . '/' . $plugin, false, false );
		$name = ! empty( $plugin_data['Name'] ) ? $plugin_data['Name'] : $plugin;

		$this->log( 'plugin_activated', self::GROUP_SYSTEM,
			sprintf( 'Plugin activated: "%s"', $name ),
			array(
				'object_type' => 'plugin',
				'object_name' => $name,
				'severity'    => 'notice',
				'metadata'    => array( 'plugin_file' => $plugin, 'network_wide' => $network_wide ),
			)
		);
	}

	/**
	 * Plugin deactivated.
	 */
	public function on_plugin_deactivate( $plugin, $network_wide ) {
		$plugin_data = get_plugin_data( WP_PLUGIN_DIR . '/' . $plugin, false, false );
		$name = ! empty( $plugin_data['Name'] ) ? $plugin_data['Name'] : $plugin;

		$this->log( 'plugin_deactivated', self::GROUP_SYSTEM,
			sprintf( 'Plugin deactivated: "%s"', $name ),
			array(
				'object_type' => 'plugin',
				'object_name' => $name,
				'severity'    => 'notice',
				'metadata'    => array( 'plugin_file' => $plugin, 'network_wide' => $network_wide ),
			)
		);
	}

	/**
	 * Plugin updated.
	 */
	public function on_plugin_update( $upgrader, $options ) {
		if ( ! isset( $options['type'] ) || $options['type'] !== 'plugin' ) {
			return;
		}
		if ( ! isset( $options['action'] ) || $options['action'] !== 'update' ) {
			return;
		}

		$plugins = array();
		if ( isset( $options['plugins'] ) && is_array( $options['plugins'] ) ) {
			$plugins = $options['plugins'];
		} elseif ( isset( $options['plugin'] ) ) {
			$plugins = array( $options['plugin'] );
		}

		foreach ( $plugins as $plugin ) {
			$plugin_data = get_plugin_data( WP_PLUGIN_DIR . '/' . $plugin, false, false );
			$name = ! empty( $plugin_data['Name'] ) ? $plugin_data['Name'] : $plugin;

			$this->log( 'plugin_updated', self::GROUP_SYSTEM,
				sprintf( 'Plugin updated: "%s" to version %s', $name, ! empty( $plugin_data['Version'] ) ? $plugin_data['Version'] : 'unknown' ),
				array(
					'object_type' => 'plugin',
					'object_name' => $name,
					'severity'    => 'notice',
					'metadata'    => array( 'plugin_file' => $plugin, 'version' => $plugin_data['Version'] ?? '' ),
				)
			);
		}
	}

	/**
	 * Plugin deleted.
	 */
	public function on_plugin_delete( $plugin_file, $deleted ) {
		if ( ! $deleted ) {
			return;
		}

		$this->log( 'plugin_deleted', self::GROUP_SYSTEM,
			sprintf( 'Plugin deleted: "%s"', $plugin_file ),
			array(
				'object_type' => 'plugin',
				'object_name' => $plugin_file,
				'severity'    => 'warning',
			)
		);
	}

	/**
	 * Theme switched.
	 */
	public function on_theme_switch( $new_name, $new_theme, $old_theme ) {
		$old_name = is_object( $old_theme ) ? $old_theme->get( 'Name' ) : 'Unknown';

		$this->log( 'theme_switched', self::GROUP_SYSTEM,
			sprintf( 'Theme switched from "%s" to "%s"', $old_name, $new_name ),
			array(
				'object_type' => 'theme',
				'object_name' => $new_name,
				'severity'    => 'notice',
				'metadata'    => array( 'old_theme' => $old_name, 'new_theme' => $new_name ),
			)
		);
	}

	/**
	 * WordPress option updated (filtered to important ones).
	 */
	public function on_option_update( $option, $old_value, $value ) {
		$settings = $this->get_settings();
		$excluded = ! empty( $settings['excluded_options'] ) ? $settings['excluded_options'] : array();

		// Skip transients and excluded options.
		foreach ( $excluded as $pattern ) {
			if ( strpos( $option, $pattern ) === 0 ) {
				return;
			}
		}

		// Only track important options.
		$tracked_options = array(
			'blogname', 'blogdescription', 'siteurl', 'home', 'admin_email',
			'users_can_register', 'default_role', 'permalink_structure',
			'active_plugins', 'template', 'stylesheet',
			'nexifymy_security_settings',
		);

		$is_tracked = in_array( $option, $tracked_options, true );
		if ( ! $is_tracked ) {
			return;
		}

		$this->log( 'option_updated', self::GROUP_SYSTEM,
			sprintf( 'Option updated: "%s"', $option ),
			array(
				'object_type' => 'option',
				'object_name' => $option,
				'severity'    => ( $option === 'admin_email' || $option === 'siteurl' || $option === 'home' ) ? 'warning' : 'info',
			)
		);
	}

	/**
	 * WordPress export.
	 */
	public function on_export( $args ) {
		$this->log( 'data_exported', self::GROUP_SYSTEM,
			'WordPress data exported',
			array(
				'object_type' => 'export',
				'severity'    => 'notice',
				'metadata'    => $args,
			)
		);
	}

	// ─── Utility Methods ─────────────────────────────────────────────────

	/**
	 * Get client IP address.
	 */
	private function get_client_ip() {
		$remote_addr     = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		$trusted_proxies = get_option( 'nexifymy_security_trusted_proxies', array() );

		if ( $remote_addr && in_array( $remote_addr, (array) $trusted_proxies, true ) ) {
			$ip_keys = array( 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP' );
			foreach ( $ip_keys as $key ) {
				if ( empty( $_SERVER[ $key ] ) ) {
					continue;
				}

				$ip = sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) );
				// Handle comma-separated list.
				if ( strpos( $ip, ',' ) !== false ) {
					$ip = trim( explode( ',', $ip )[0] );
				}
				if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
					return $ip;
				}
			}
		}

		if ( $remote_addr && filter_var( $remote_addr, FILTER_VALIDATE_IP ) ) {
			return $remote_addr;
		}

		return '0.0.0.0';
	}

	/**
	 * Get entries from the activity log.
	 */
	public function get_entries( $args = array() ) {
		global $wpdb;
		$table = $wpdb->prefix . self::TABLE_NAME;

		$defaults = array(
			'event_group' => '',
			'event_type'  => '',
			'severity'    => '',
			'user_id'     => 0,
			'username'    => '',
			'ip_address'  => '',
			'search'      => '',
			'date_from'   => '',
			'date_to'     => '',
			'per_page'    => 25,
			'page'        => 1,
			'orderby'     => 'created_at',
			'order'       => 'DESC',
		);
		$args = wp_parse_args( $args, $defaults );

		$where = array( '1=1' );
		$values = array();

		if ( ! empty( $args['event_group'] ) ) {
			$where[] = 'event_group = %s';
			$values[] = $args['event_group'];
		}
		if ( ! empty( $args['event_type'] ) ) {
			$where[] = 'event_type = %s';
			$values[] = $args['event_type'];
		}
		if ( ! empty( $args['severity'] ) ) {
			$where[] = 'severity = %s';
			$values[] = $args['severity'];
		}
		if ( ! empty( $args['user_id'] ) ) {
			$where[] = 'user_id = %d';
			$values[] = absint( $args['user_id'] );
		}
		if ( ! empty( $args['username'] ) ) {
			$where[] = 'username LIKE %s';
			$values[] = '%' . $wpdb->esc_like( $args['username'] ) . '%';
		}
		if ( ! empty( $args['ip_address'] ) ) {
			$where[] = 'ip_address = %s';
			$values[] = $args['ip_address'];
		}
		if ( ! empty( $args['search'] ) ) {
			$where[] = '(description LIKE %s OR username LIKE %s OR object_name LIKE %s)';
			$like = '%' . $wpdb->esc_like( $args['search'] ) . '%';
			$values[] = $like;
			$values[] = $like;
			$values[] = $like;
		}
		if ( ! empty( $args['date_from'] ) ) {
			$where[] = 'created_at >= %s';
			$values[] = sanitize_text_field( $args['date_from'] ) . ' 00:00:00';
		}
		if ( ! empty( $args['date_to'] ) ) {
			$where[] = 'created_at <= %s';
			$values[] = sanitize_text_field( $args['date_to'] ) . ' 23:59:59';
		}

		$where_sql = implode( ' AND ', $where );

		// Sanitize order params.
		$allowed_orderby = array( 'id', 'created_at', 'event_type', 'severity', 'username' );
		$orderby = in_array( $args['orderby'], $allowed_orderby, true ) ? $args['orderby'] : 'created_at';
		$order = strtoupper( $args['order'] ) === 'ASC' ? 'ASC' : 'DESC';

		$per_page = absint( $args['per_page'] );
		$offset = ( absint( $args['page'] ) - 1 ) * $per_page;

		// Get total count.
		$count_sql = "SELECT COUNT(*) FROM {$table} WHERE {$where_sql}";
		if ( ! empty( $values ) ) {
			$count_sql = $wpdb->prepare( $count_sql, $values );
		}
		$total = (int) $wpdb->get_var( $count_sql );

		// Get entries.
		$sql = "SELECT * FROM {$table} WHERE {$where_sql} ORDER BY {$orderby} {$order} LIMIT %d OFFSET %d";
		$values[] = $per_page;
		$values[] = $offset;

		$entries = $wpdb->get_results( $wpdb->prepare( $sql, $values ) );

		return array(
			'entries'    => $entries ? $entries : array(),
			'total'      => $total,
			'pages'      => ceil( $total / $per_page ),
			'page'       => absint( $args['page'] ),
			'per_page'   => $per_page,
		);
	}

	/**
	 * Get activity statistics.
	 */
	public function get_stats( $days = 30 ) {
		global $wpdb;
		$table = $wpdb->prefix . self::TABLE_NAME;
		$since = gmdate( 'Y-m-d H:i:s', strtotime( "-{$days} days" ) );
		$yesterday = gmdate( 'Y-m-d H:i:s', strtotime( '-1 day' ) );
		$last_hour = gmdate( 'Y-m-d H:i:s', strtotime( '-1 hour' ) );

		$stats = array();

		// Total events.
		$stats['total'] = (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE created_at >= %s", $since )
		);

		// Events today.
		$today_start = gmdate( 'Y-m-d 00:00:00' );
		$stats['today'] = (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE created_at >= %s", $today_start )
		);

		// Events this hour.
		$stats['this_hour'] = (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE created_at >= %s", $last_hour )
		);

		// Unique users in period.
		$stats['unique_users'] = (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT COUNT(DISTINCT user_id) FROM {$table} WHERE created_at >= %s AND user_id > 0", $since )
		);

		// Unique IPs in period.
		$stats['unique_ips'] = (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT COUNT(DISTINCT ip_address) FROM {$table} WHERE created_at >= %s", $since )
		);

		// Events by group.
		$groups = $wpdb->get_results(
			$wpdb->prepare( "SELECT event_group, COUNT(*) as count FROM {$table} WHERE created_at >= %s GROUP BY event_group ORDER BY count DESC", $since )
		);
		$stats['by_group'] = array();
		foreach ( $groups as $row ) {
			$stats['by_group'][ $row->event_group ] = (int) $row->count;
		}

		// Events by severity.
		$severities = $wpdb->get_results(
			$wpdb->prepare( "SELECT severity, COUNT(*) as count FROM {$table} WHERE created_at >= %s GROUP BY severity ORDER BY count DESC", $since )
		);
		$stats['by_severity'] = array();
		foreach ( $severities as $row ) {
			$stats['by_severity'][ $row->severity ] = (int) $row->count;
		}

		// Login stats.
		$stats['logins'] = (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE event_type = 'login_success' AND created_at >= %s", $since )
		);
		$stats['failed_logins'] = (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE event_type = 'login_failed' AND created_at >= %s", $since )
		);
		$stats['logouts'] = (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE event_type = 'logout' AND created_at >= %s", $since )
		);

		// Login success rate.
		$total_login_attempts = $stats['logins'] + $stats['failed_logins'];
		$stats['login_success_rate'] = $total_login_attempts > 0 ? round( ( $stats['logins'] / $total_login_attempts ) * 100, 1 ) : 100;

		// Password resets.
		$stats['password_resets'] = (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE event_type = 'password_reset' AND created_at >= %s", $since )
		);

		// User management events.
		$stats['users_created'] = (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE event_type = 'user_created' AND created_at >= %s", $since )
		);
		$stats['users_deleted'] = (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE event_type = 'user_deleted' AND created_at >= %s", $since )
		);
		$stats['role_changes'] = (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE event_type = 'role_change' AND created_at >= %s", $since )
		);
		$stats['profile_updates'] = (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE event_type = 'profile_update' AND created_at >= %s", $since )
		);

		// Content stats.
		$stats['posts_created'] = (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE event_type = 'content_created' AND created_at >= %s", $since )
		);
		$stats['posts_updated'] = (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE event_type = 'content_updated' AND created_at >= %s", $since )
		);
		$stats['posts_published'] = (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE event_type = 'content_published' AND created_at >= %s", $since )
		);
		$stats['posts_deleted'] = (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE event_type IN ('content_deleted', 'content_trashed') AND created_at >= %s", $since )
		);
		$stats['media_uploads'] = (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE event_type = 'media_uploaded' AND created_at >= %s", $since )
		);

		// System stats.
		$stats['plugins_activated'] = (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE event_type = 'plugin_activated' AND created_at >= %s", $since )
		);
		$stats['plugins_deactivated'] = (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE event_type = 'plugin_deactivated' AND created_at >= %s", $since )
		);
		$stats['plugins_updated'] = (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE event_type = 'plugin_updated' AND created_at >= %s", $since )
		);
		$stats['theme_switches'] = (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE event_type = 'theme_switched' AND created_at >= %s", $since )
		);
		$stats['option_updates'] = (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE event_type = 'option_updated' AND created_at >= %s", $since )
		);

		// Most active users.
		$stats['active_users'] = $wpdb->get_results(
			$wpdb->prepare( "SELECT username, user_role, COUNT(*) as count FROM {$table} WHERE created_at >= %s AND user_id > 0 GROUP BY username, user_role ORDER BY count DESC LIMIT 10", $since )
		);

		// Recent suspicious IPs (multiple failed logins).
		$stats['suspicious_ips'] = $wpdb->get_results(
			$wpdb->prepare( "SELECT ip_address, COUNT(*) as count FROM {$table} WHERE event_type = 'login_failed' AND created_at >= %s GROUP BY ip_address HAVING count >= 3 ORDER BY count DESC LIMIT 10", $since )
		);

		// Daily event count (for chart).
		$stats['daily_counts'] = $wpdb->get_results(
			$wpdb->prepare( "SELECT DATE(created_at) as date, COUNT(*) as count FROM {$table} WHERE created_at >= %s GROUP BY DATE(created_at) ORDER BY date ASC", $since )
		);

		// Hourly distribution (for chart).
		$stats['hourly_distribution'] = $wpdb->get_results(
			$wpdb->prepare( "SELECT HOUR(created_at) as hour, COUNT(*) as count FROM {$table} WHERE created_at >= %s GROUP BY HOUR(created_at) ORDER BY hour ASC", $since )
		);

		// Peak hour.
		$peak_hour = $wpdb->get_row(
			$wpdb->prepare( "SELECT HOUR(created_at) as hour, COUNT(*) as count FROM {$table} WHERE created_at >= %s GROUP BY HOUR(created_at) ORDER BY count DESC LIMIT 1", $since )
		);
		$stats['peak_hour'] = $peak_hour ? (int) $peak_hour->hour : 0;
		$stats['peak_hour_count'] = $peak_hour ? (int) $peak_hour->count : 0;

		// Most active day.
		$peak_day = $wpdb->get_row(
			$wpdb->prepare( "SELECT DATE(created_at) as date, COUNT(*) as count FROM {$table} WHERE created_at >= %s GROUP BY DATE(created_at) ORDER BY count DESC LIMIT 1", $since )
		);
		$stats['peak_day'] = $peak_day ? $peak_day->date : '';
		$stats['peak_day_count'] = $peak_day ? (int) $peak_day->count : 0;

		// Average events per day.
		$stats['avg_events_per_day'] = $days > 0 ? round( $stats['total'] / $days, 1 ) : 0;

		// Events by event type (top 10).
		$stats['by_event_type'] = $wpdb->get_results(
			$wpdb->prepare( "SELECT event_type, COUNT(*) as count FROM {$table} WHERE created_at >= %s GROUP BY event_type ORDER BY count DESC LIMIT 10", $since )
		);

		// Recent logins by location (based on IP).
		$stats['login_ips'] = $wpdb->get_results(
			$wpdb->prepare( "SELECT ip_address, username, MAX(created_at) as last_login, COUNT(*) as login_count FROM {$table} WHERE event_type = 'login_success' AND created_at >= %s GROUP BY ip_address, username ORDER BY last_login DESC LIMIT 10", $since )
		);

		// Content changes count.
		$stats['content_changes'] = (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE event_group = 'content' AND created_at >= %s", $since )
		);

		// System changes count.
		$stats['system_changes'] = (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE event_group = 'system' AND created_at >= %s", $since )
		);

		// Security events count.
		$stats['security_events'] = (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE event_group = 'security' AND created_at >= %s", $since )
		);

		// Warning and critical events.
		$stats['warnings'] = isset( $stats['by_severity']['warning'] ) ? $stats['by_severity']['warning'] : 0;
		$stats['critical'] = isset( $stats['by_severity']['critical'] ) ? $stats['by_severity']['critical'] : 0;

		// Database size.
		$stats['db_rows'] = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" );

		return $stats;
	}

	/**
	 * Purge old log entries based on retention setting.
	 */
	public function purge_old_entries() {
		global $wpdb;
		$table = $wpdb->prefix . self::TABLE_NAME;

		$settings = $this->get_settings();
		$retention_days = absint( $settings['retention_days'] );
		if ( $retention_days < 1 ) {
			$retention_days = 90;
		}

		$cutoff = gmdate( 'Y-m-d H:i:s', strtotime( "-{$retention_days} days" ) );
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE created_at < %s", $cutoff ) );
	}

	// ─── AJAX Handlers ───────────────────────────────────────────────────

	/**
	 * Get activity log entries via AJAX.
	 */
	public function ajax_get_activity_log() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$args = array(
			'event_group' => isset( $_POST['event_group'] ) ? sanitize_key( $_POST['event_group'] ) : '',
			'event_type'  => isset( $_POST['event_type'] ) ? sanitize_key( $_POST['event_type'] ) : '',
			'severity'    => isset( $_POST['severity'] ) ? sanitize_key( $_POST['severity'] ) : '',
			'username'    => isset( $_POST['username'] ) ? sanitize_text_field( $_POST['username'] ) : '',
			'ip_address'  => isset( $_POST['ip_address'] ) ? sanitize_text_field( $_POST['ip_address'] ) : '',
			'search'      => isset( $_POST['search'] ) ? sanitize_text_field( $_POST['search'] ) : '',
			'date_from'   => isset( $_POST['date_from'] ) ? sanitize_text_field( $_POST['date_from'] ) : '',
			'date_to'     => isset( $_POST['date_to'] ) ? sanitize_text_field( $_POST['date_to'] ) : '',
			'per_page'    => isset( $_POST['per_page'] ) ? absint( $_POST['per_page'] ) : 25,
			'page'        => isset( $_POST['page'] ) ? absint( $_POST['page'] ) : 1,
		);

		$results = $this->get_entries( $args );
		wp_send_json_success( $results );
	}

	/**
	 * Export activity log as CSV.
	 */
	public function ajax_export_activity_log() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$args = array(
			'event_group' => isset( $_POST['event_group'] ) ? sanitize_key( $_POST['event_group'] ) : '',
			'date_from'   => isset( $_POST['date_from'] ) ? sanitize_text_field( $_POST['date_from'] ) : '',
			'date_to'     => isset( $_POST['date_to'] ) ? sanitize_text_field( $_POST['date_to'] ) : '',
			'per_page'    => 10000,
			'page'        => 1,
		);

		$results = $this->get_entries( $args );

		$csv_rows = array();
		$csv_rows[] = array( 'Date', 'User', 'Role', 'Event Type', 'Group', 'Severity', 'Description', 'Object', 'IP Address' );

		foreach ( $results['entries'] as $entry ) {
			$csv_rows[] = array(
				$entry->created_at,
				$entry->username,
				$entry->user_role,
				$entry->event_type,
				$entry->event_group,
				$entry->severity,
				$entry->description,
				$entry->object_name,
				$entry->ip_address,
			);
		}

		wp_send_json_success( array( 'csv' => $csv_rows, 'total' => $results['total'] ) );
	}

	/**
	 * Purge all activity log entries via AJAX.
	 */
	public function ajax_purge_activity_log() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		global $wpdb;
		$table = $wpdb->prefix . self::TABLE_NAME;
		$wpdb->query( "TRUNCATE TABLE {$table}" );

		wp_send_json_success( array( 'message' => 'Activity log purged successfully' ) );
	}

	/**
	 * Get activity stats via AJAX.
	 */
	public function ajax_get_activity_stats() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$days = isset( $_POST['days'] ) ? absint( $_POST['days'] ) : 30;
		$stats = $this->get_stats( $days );
		wp_send_json_success( $stats );
	}
}
