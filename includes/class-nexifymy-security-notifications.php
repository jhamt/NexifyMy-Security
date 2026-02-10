<?php
/**
 * Admin Notifications Module.
 * Surfaces high-severity security log events as unread "alerts" in the WP admin.
 *
 * DEV NOTES:
 * This module queries the security logs for unread critical/warning events.
 * It provides an admin bar icon and a custom branded notice for alerts.
 * Last Updated: 2026-02-06
 * Version: 2.1.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_Notifications {

	/**
	 * Per-user meta key used to track the last seen log ID.
	 */
	const LAST_SEEN_META_KEY = '_nexifymy_security_last_seen_log_id';

	/**
	 * Event types to exclude from notifications (too noisy/low value).
	 */
	const EXCLUDED_EVENT_TYPES = array(
		'login_failed',
		'waf_skip',
		'scan_skip',
		'log_cleanup',
	);

	/**
	 * Maximum number of alerts returned for the notifications page.
	 */
	const DEFAULT_LIMIT = 50;

	/**
	 * Initialize hooks.
	 */
	public function init() {
		if ( ! function_exists( 'is_user_logged_in' ) || ! is_user_logged_in() ) {
			return;
		}

		// Only admins should see notifications.
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		add_action( 'admin_bar_menu', array( $this, 'add_admin_bar_item' ), 100 );

		if ( is_admin() ) {
			add_action( 'admin_notices', array( $this, 'maybe_show_admin_notice' ) );

			// AJAX endpoints for the Notifications page.
			add_action( 'wp_ajax_nexifymy_get_notifications', array( $this, 'ajax_get_notifications' ) );
			add_action( 'wp_ajax_nexifymy_mark_all_notifications_read', array( $this, 'ajax_mark_all_read' ) );
		}
	}

	/**
	 * Get unread alert count for a user.
	 *
	 * @param int $user_id User ID.
	 * @return int
	 */
	public static function get_unread_count( $user_id ) {
		global $wpdb;

		$table = self::get_logs_table();
		if ( empty( $table ) ) {
			return 0;
		}

		$last_seen = self::get_last_seen_id( $user_id );

		$severities            = array( 'critical', 'warning' );
		$severity_placeholders = implode( ',', array_fill( 0, count( $severities ), '%s' ) );

		$sql    = "SELECT COUNT(*) FROM {$table} WHERE id > %d AND severity IN ({$severity_placeholders})";
		$params = array_merge( array( $last_seen ), $severities );

		$excluded = self::EXCLUDED_EVENT_TYPES;
		if ( ! empty( $excluded ) ) {
			$excluded_placeholders = implode( ',', array_fill( 0, count( $excluded ), '%s' ) );
			$sql                  .= " AND event_type NOT IN ({$excluded_placeholders})";
			$params                = array_merge( $params, $excluded );
		}

		return (int) $wpdb->get_var( $wpdb->prepare( $sql, $params ) );
	}

	/**
	 * Get unread alerts for a user.
	 *
	 * @param int $user_id User ID.
	 * @param int $limit Limit.
	 * @return array
	 */
	public static function get_unread_alerts( $user_id, $limit = self::DEFAULT_LIMIT ) {
		global $wpdb;

		$table = self::get_logs_table();
		if ( empty( $table ) ) {
			return array();
		}

		$last_seen = self::get_last_seen_id( $user_id );
		$limit     = max( 1, min( 200, absint( $limit ) ) );

		$severities            = array( 'critical', 'warning' );
		$severity_placeholders = implode( ',', array_fill( 0, count( $severities ), '%s' ) );

		$sql    = "SELECT id, created_at, event_type, severity, message, ip_address
			FROM {$table}
			WHERE id > %d AND severity IN ({$severity_placeholders})";
		$params = array_merge( array( $last_seen ), $severities );

		$excluded = self::EXCLUDED_EVENT_TYPES;
		if ( ! empty( $excluded ) ) {
			$excluded_placeholders = implode( ',', array_fill( 0, count( $excluded ), '%s' ) );
			$sql                  .= " AND event_type NOT IN ({$excluded_placeholders})";
			$params                = array_merge( $params, $excluded );
		}

		$sql     .= ' ORDER BY id DESC LIMIT %d';
		$params[] = $limit;

		return (array) $wpdb->get_results( $wpdb->prepare( $sql, $params ), ARRAY_A );
	}

	/**
	 * Mark all current alerts as read for a user.
	 *
	 * @param int $user_id User ID.
	 * @return int New last seen ID.
	 */
	public static function mark_all_read( $user_id ) {
		$max_id = self::get_max_log_id();
		update_user_meta( $user_id, self::LAST_SEEN_META_KEY, $max_id );
		return $max_id;
	}

	/**
	 * Add admin bar item with unread count.
	 *
	 * @param WP_Admin_Bar $wp_admin_bar Admin bar instance.
	 */
	public function add_admin_bar_item( $wp_admin_bar ) {
		$user_id = get_current_user_id();
		if ( ! $user_id ) {
			return;
		}

		$count = self::get_unread_count( $user_id );
		$title = __( 'Security Alerts', 'nexifymy-security' );
		if ( $count > 0 ) {
			$title .= ' (' . (int) $count . ')';
		}

		$wp_admin_bar->add_node(
			array(
				'id'    => 'nexifymy-security-alerts',
				'title' => $title,
				'href'  => admin_url( 'admin.php?page=nexifymy-security-notifications' ),
				'meta'  => array( 'class' => $count > 0 ? 'nexifymy-security-alerts-has-unread' : '' ),
			)
		);
	}

	/**
	 * Show a lightweight admin notice if there are unread critical/warning alerts.
	 * Redesigned with custom branding and separate look.
	 */
	public function maybe_show_admin_notice() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;

		// Don't show on notifications page itself.
		if ( $screen && isset( $screen->id ) && strpos( $screen->id, 'nexifymy-security-notifications' ) !== false ) {
			return;
		}

		$count = self::get_unread_count( get_current_user_id() );
		if ( $count <= 0 ) {
			return;
		}

		$url = admin_url( 'admin.php?page=nexifymy-security-notifications' );
		?>
		<div class="notice notice-warning nms-admin-notice is-dismissible">
			<div class="nms-admin-notice-icon">
				<span class="dashicons dashicons-shield-alt"></span>
			</div>
			<div class="nms-admin-notice-content">
				<p>
					<?php
					printf(
						__( 'NexifyMy Security: You have %d unread security alert(s).', 'nexifymy-security' ),
						(int) $count
					);
					?>
					<a href="<?php echo esc_url( $url ); ?>"><?php _e( 'Review Alerts &rsaquo;', 'nexifymy-security' ); ?></a>
				</p>
			</div>
		</div>
		<?php
	}

	/**
	 * AJAX: get unread alerts and unread count.
	 */
	public function ajax_get_notifications() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$user_id = get_current_user_id();
		$limit   = isset( $_POST['limit'] ) ? absint( $_POST['limit'] ) : self::DEFAULT_LIMIT;

		$alerts = self::get_unread_alerts( $user_id, $limit );
		$count  = self::get_unread_count( $user_id );

		wp_send_json_success(
			array(
				'unread_count' => $count,
				'alerts'       => $alerts,
			)
		);
	}

	/**
	 * AJAX: mark all alerts as read.
	 */
	public function ajax_mark_all_read() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$user_id = get_current_user_id();
		$max_id  = self::mark_all_read( $user_id );

		wp_send_json_success(
			array(
				'last_seen_id' => $max_id,
			)
		);
	}

	/**
	 * Get the security logs table name if it exists.
	 *
	 * @return string|null
	 */
	private static function get_logs_table() {
		global $wpdb;

		if ( ! isset( $wpdb ) || ! is_object( $wpdb ) ) {
			return null;
		}

		$table = $wpdb->prefix . 'nexifymy_security_logs';
		if ( $wpdb->get_var( "SHOW TABLES LIKE '{$table}'" ) !== $table ) {
			return null;
		}

		return $table;
	}

	/**
	 * Get last seen log id for the user.
	 *
	 * @param int $user_id User ID.
	 * @return int
	 */
	private static function get_last_seen_id( $user_id ) {
		$last_seen = (int) get_user_meta( $user_id, self::LAST_SEEN_META_KEY, true );
		return max( 0, $last_seen );
	}

	/**
	 * Get max log id currently in the table.
	 *
	 * @return int
	 */
	private static function get_max_log_id() {
		global $wpdb;

		$table = self::get_logs_table();
		if ( empty( $table ) ) {
			return 0;
		}

		return (int) $wpdb->get_var( "SELECT MAX(id) FROM {$table}" );
	}
}

