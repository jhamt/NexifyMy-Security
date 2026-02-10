<?php
/**
 * PHPUnit Bootstrap for NexifyMy Security Tests.
 *
 * Sets up the WordPress test environment.
 */

// Define test mode.
define( 'NEXIFYMY_TESTING', true );

// Mock WordPress functions for standalone testing.
if ( ! function_exists( '__' ) ) {
	function __( $text ) {
		return $text;
	}
}

if ( ! function_exists( 'esc_html__' ) ) {
	function esc_html__( $text ) {
		return $text;
	}
}

if ( ! function_exists( '__return_false' ) ) {
	function __return_false() {
		return false;
	}
}

if ( ! function_exists( '__return_true' ) ) {
	function __return_true() {
		return true;
	}
}

if ( ! function_exists( '__return_empty_string' ) ) {
	function __return_empty_string() {
		return '';
	}
}

if ( ! function_exists( 'trailingslashit' ) ) {
	function trailingslashit( $value ) {
		return rtrim( (string) $value, "/\\\t\n\r\0\x0B" ) . '/';
	}
}

if ( ! function_exists( 'wp_unslash' ) ) {
	function wp_unslash( $value ) {
		return $value;
	}
}

if ( ! function_exists( 'wp_doing_ajax' ) ) {
	function wp_doing_ajax() {
		return ! empty( $GLOBALS['nexifymy_testing_doing_ajax'] );
	}
}

if ( ! function_exists( 'wp_doing_cron' ) ) {
	function wp_doing_cron() {
		return ! empty( $GLOBALS['nexifymy_testing_doing_cron'] );
	}
}

if ( ! function_exists( 'add_action' ) ) {
	function add_action( $hook, $callback, $priority = 10, $accepted_args = 1 ) {
		$GLOBALS['nexifymy_test_actions'][ $hook ][] = array(
			'callback'       => $callback,
			'priority'       => $priority,
			'accepted_args'  => $accepted_args,
		);
		return true;
	}
}

if ( ! function_exists( 'add_filter' ) ) {
	function add_filter( $hook, $callback, $priority = 10, $accepted_args = 1 ) {
		$GLOBALS['nexifymy_test_filters'][ $hook ][] = array(
			'callback'       => $callback,
			'priority'       => $priority,
			'accepted_args'  => $accepted_args,
		);
		return true;
	}
}

if ( ! function_exists( 'do_action' ) ) {
	function do_action( $hook, ...$args ) {
		if ( empty( $GLOBALS['nexifymy_test_actions'][ $hook ] ) ) {
			return;
		}
		foreach ( $GLOBALS['nexifymy_test_actions'][ $hook ] as $handler ) {
			call_user_func_array( $handler['callback'], array_slice( $args, 0, (int) $handler['accepted_args'] ) );
		}
	}
}

if ( ! function_exists( 'apply_filters' ) ) {
	function apply_filters( $hook, $value, ...$args ) {
		if ( empty( $GLOBALS['nexifymy_test_filters'][ $hook ] ) ) {
			return $value;
		}
		foreach ( $GLOBALS['nexifymy_test_filters'][ $hook ] as $handler ) {
			$value = call_user_func_array(
				$handler['callback'],
				array_merge( array( $value ), array_slice( $args, 0, max( 0, (int) $handler['accepted_args'] - 1 ) ) )
			);
		}
		return $value;
	}
}

if ( ! function_exists( 'wp_next_scheduled' ) ) {
	function wp_next_scheduled( $hook ) {
		return $GLOBALS['nexifymy_test_cron'][ $hook ]['next'] ?? false;
	}
}

if ( ! function_exists( 'wp_schedule_event' ) ) {
	function wp_schedule_event( $timestamp, $recurrence, $hook, $args = array() ) {
		$GLOBALS['nexifymy_test_cron'][ $hook ] = array(
			'next'       => $timestamp,
			'recurrence' => $recurrence,
			'args'       => $args,
		);
		return true;
	}
}

if ( ! function_exists( 'current_time' ) ) {
	function current_time( $type = 'mysql' ) {
		if ( $type === 'timestamp' ) {
			return time();
		}
		if ( $type === 'G' ) {
			return (int) gmdate( 'G' );
		}
		if ( $type === 'w' ) {
			return (int) gmdate( 'w' );
		}
		if ( $type === 'mysql' ) {
			return gmdate( 'Y-m-d H:i:s' );
		}
		return gmdate( 'Y-m-d H:i:s' );
	}
}

if ( ! function_exists( 'get_current_user_id' ) ) {
	function get_current_user_id() {
		return (int) ( $GLOBALS['nexifymy_testing_user_id'] ?? 0 );
	}
}

if ( ! function_exists( 'check_ajax_referer' ) ) {
	function check_ajax_referer( $action, $query_arg = false, $die = true ) {
		return true;
	}
}

if ( ! function_exists( 'current_user_can' ) ) {
	function current_user_can( $capability ) {
		return true;
	}
}

if ( ! function_exists( 'wp_send_json_error' ) ) {
	function wp_send_json_error( $data = null, $status_code = null ) {
		throw new \RuntimeException( 'wp_send_json_error called: ' . wp_json_encode( $data ) );
	}
}

if ( ! function_exists( 'wp_send_json_success' ) ) {
	function wp_send_json_success( $data = null, $status_code = null ) {
		return array( 'success' => true, 'data' => $data, 'status_code' => $status_code );
	}
}

if ( ! function_exists( 'get_bloginfo' ) ) {
	function get_bloginfo( $show = '' ) {
		return 'Test Site';
	}
}

if ( ! function_exists( 'home_url' ) ) {
	function home_url( $path = '' ) {
		return 'http://example.com' . $path;
	}
}

if ( ! function_exists( 'wp_mail' ) ) {
	function wp_mail( $to, $subject, $message, $headers = '', $attachments = array() ) {
		$GLOBALS['nexifymy_test_mail'][] = compact( 'to', 'subject', 'message', 'headers', 'attachments' );
		return true;
	}
}

if ( ! class_exists( 'WP_Error' ) ) {
	class WP_Error {
		public $code;
		public $message;
		public $data;

		public function __construct( $code = '', $message = '', $data = null ) {
			$this->code    = $code;
			$this->message = $message;
			$this->data    = $data;
		}
	}
}

if ( ! function_exists( 'is_wp_error' ) ) {
	function is_wp_error( $thing ) {
		return $thing instanceof WP_Error;
	}
}

if ( ! function_exists( 'wp_mkdir_p' ) ) {
	function wp_mkdir_p( $target ) {
		if ( is_dir( $target ) ) {
			return true;
		}
		return mkdir( $target, 0777, true );
	}
}

if ( ! function_exists( 'wp_generate_password' ) ) {
	function wp_generate_password( $length = 12, $special_chars = true ) {
		$chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
		$out = '';
		for ( $i = 0; $i < $length; $i++ ) {
			$out .= $chars[ random_int( 0, strlen( $chars ) - 1 ) ];
		}
		return $out;
	}
}

if ( ! function_exists( 'sanitize_file_name' ) ) {
	function sanitize_file_name( $filename ) {
		$filename = preg_replace( '/[^A-Za-z0-9._-]/', '-', (string) $filename );
		$filename = preg_replace( '/-+/', '-', $filename );
		return trim( $filename, '-' );
	}
}

if ( ! function_exists( 'get_option' ) ) {
	/**
	 * Mock get_option for tests.
	 *
	 * @param string $option  Option name.
	 * @param mixed  $default Default value.
	 * @return mixed
	 */
	function get_option( $option, $default = false ) {
		global $nexifymy_test_options;
		return isset( $nexifymy_test_options[ $option ] ) ? $nexifymy_test_options[ $option ] : $default;
	}
}

if ( ! function_exists( 'update_option' ) ) {
	/**
	 * Mock update_option for tests.
	 *
	 * @param string $option Option name.
	 * @param mixed  $value  Value.
	 * @param mixed  $autoload Optional autoload flag (ignored in tests).
	 * @return bool
	 */
	function update_option( $option, $value, $autoload = null ) {
		global $nexifymy_test_options;
		$nexifymy_test_options[ $option ] = $value;
		return true;
	}
}

if ( ! function_exists( 'delete_option' ) ) {
	/**
	 * Mock delete_option for tests.
	 *
	 * @param string $option Option name.
	 * @return bool
	 */
	function delete_option( $option ) {
		global $nexifymy_test_options;
		unset( $nexifymy_test_options[ $option ] );
		return true;
	}
}

if ( ! function_exists( 'wp_parse_args' ) ) {
	/**
	 * Mock wp_parse_args for tests.
	 *
	 * @param array $args     Arguments.
	 * @param array $defaults Defaults.
	 * @return array
	 */
	function wp_parse_args( $args, $defaults = array() ) {
		return array_merge( $defaults, $args );
	}
}

if ( ! function_exists( 'sanitize_text_field' ) ) {
	/**
	 * Mock sanitize_text_field for tests.
	 *
	 * @param string $str String to sanitize.
	 * @return string
	 */
	function sanitize_text_field( $str ) {
		return strip_tags( trim( $str ) );
	}
}

if ( ! function_exists( 'sanitize_key' ) ) {
	/**
	 * Mock sanitize_key for tests.
	 *
	 * @param string $key Key to sanitize.
	 * @return string
	 */
	function sanitize_key( $key ) {
		return preg_replace( '/[^a-z0-9_\-]/', '', strtolower( $key ) );
	}
}

if ( ! function_exists( 'absint' ) ) {
	/**
	 * Mock absint for tests.
	 *
	 * @param mixed $maybeint Value to convert.
	 * @return int
	 */
	function absint( $maybeint ) {
		return abs( (int) $maybeint );
	}
}

if ( ! function_exists( 'wp_upload_dir' ) ) {
	/**
	 * Mock wp_upload_dir for tests.
	 *
	 * @return array
	 */
	function wp_upload_dir() {
		return array(
			'path'    => ABSPATH . 'wp-content/uploads/2024/01',
			'url'     => 'http://example.com/wp-content/uploads/2024/01',
			'subdir'  => '/2024/01',
			'basedir' => ABSPATH . 'wp-content/uploads',
			'baseurl' => 'http://example.com/wp-content/uploads',
			'error'   => false,
		);
	}
}

if ( ! function_exists( 'wp_json_encode' ) ) {
	/**
	 * Mock wp_json_encode for tests.
	 *
	 * @param mixed $data    Data to encode.
	 * @param int   $options Options.
	 * @param int   $depth   Depth.
	 * @return string|false
	 */
	function wp_json_encode( $data, $options = 0, $depth = 512 ) {
		return json_encode( $data, $options, $depth );
	}
}

if ( ! function_exists( 'is_user_logged_in' ) ) {
	function is_user_logged_in() {
		return ! empty( $GLOBALS['nexifymy_testing_user_id'] );
	}
}

if ( ! function_exists( 'wp_get_session_token' ) ) {
	function wp_get_session_token() {
		return $GLOBALS['nexifymy_testing_session_token'] ?? 'test-session-token';
	}
}

if ( ! function_exists( 'get_user_meta' ) ) {
	function get_user_meta( $user_id, $key = '', $single = false ) {
		if ( ! isset( $GLOBALS['nexifymy_test_user_meta'][ $user_id ] ) ) {
			return $single ? '' : array();
		}
		if ( empty( $key ) ) {
			return $GLOBALS['nexifymy_test_user_meta'][ $user_id ];
		}
		if ( ! isset( $GLOBALS['nexifymy_test_user_meta'][ $user_id ][ $key ] ) ) {
			return $single ? '' : array();
		}
		return $single
			? $GLOBALS['nexifymy_test_user_meta'][ $user_id ][ $key ]
			: array( $GLOBALS['nexifymy_test_user_meta'][ $user_id ][ $key ] );
	}
}

if ( ! function_exists( 'update_user_meta' ) ) {
	function update_user_meta( $user_id, $meta_key, $meta_value ) {
		if ( ! isset( $GLOBALS['nexifymy_test_user_meta'] ) ) {
			$GLOBALS['nexifymy_test_user_meta'] = array();
		}
		if ( ! isset( $GLOBALS['nexifymy_test_user_meta'][ $user_id ] ) ) {
			$GLOBALS['nexifymy_test_user_meta'][ $user_id ] = array();
		}
		$GLOBALS['nexifymy_test_user_meta'][ $user_id ][ $meta_key ] = $meta_value;
		return true;
	}
}

if ( ! function_exists( 'delete_user_meta' ) ) {
	function delete_user_meta( $user_id, $meta_key ) {
		unset( $GLOBALS['nexifymy_test_user_meta'][ $user_id ][ $meta_key ] );
		return true;
	}
}

if ( ! function_exists( 'wp_logout' ) ) {
	function wp_logout() {
		$GLOBALS['nexifymy_test_logged_out'] = true;
	}
}

if ( ! function_exists( 'wp_redirect' ) ) {
	function wp_redirect( $location, $status = 302 ) {
		$GLOBALS['nexifymy_test_redirect'] = $location;
		return true;
	}
}

if ( ! function_exists( 'wp_login_url' ) ) {
	function wp_login_url( $redirect = '' ) {
		return 'http://example.com/wp-login.php';
	}
}

if ( ! function_exists( 'add_query_arg' ) ) {
	function add_query_arg( $args, $url = '' ) {
		if ( is_array( $args ) ) {
			return $url . '?' . http_build_query( $args );
		}
		return $url;
	}
}

if ( ! function_exists( 'esc_url_raw' ) ) {
	function esc_url_raw( $url ) {
		return $url;
	}
}

if ( ! function_exists( 'admin_url' ) ) {
	function admin_url( $path = '' ) {
		return 'http://example.com/wp-admin/' . ltrim( $path, '/' );
	}
}

if ( ! function_exists( 'get_userdata' ) ) {
	function get_userdata( $user_id ) {
		if ( isset( $GLOBALS['nexifymy_test_userdata'][ $user_id ] ) ) {
			return $GLOBALS['nexifymy_test_userdata'][ $user_id ];
		}
		return false;
	}
}

if ( ! function_exists( 'wp_is_post_revision' ) ) {
	function wp_is_post_revision( $post_id ) {
		return false;
	}
}

if ( ! function_exists( 'get_post' ) ) {
	function get_post( $post_id ) {
		return (object) array(
			'ID'        => $post_id,
			'post_type' => 'post',
		);
	}
}

if ( ! function_exists( 'get_plugin_data' ) ) {
	function get_plugin_data( $plugin_file ) {
		return array( 'Name' => basename( $plugin_file ) );
	}
}

if ( ! function_exists( 'dbDelta' ) ) {
	function dbDelta( $queries ) {
		return array();
	}
}

// Define WP constants.
if ( ! defined( 'ARRAY_A' ) ) {
	define( 'ARRAY_A', 'ARRAY_A' );
}
if ( ! defined( 'ARRAY_N' ) ) {
	define( 'ARRAY_N', 'ARRAY_N' );
}
if ( ! defined( 'OBJECT' ) ) {
	define( 'OBJECT', 'OBJECT' );
}
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', dirname( __DIR__ ) . '/' );
}
if ( ! defined( 'WP_PLUGIN_DIR' ) ) {
	define( 'WP_PLUGIN_DIR', ABSPATH . 'wp-content/plugins' );
}

// Initialize test options storage.
global $nexifymy_test_options;
$nexifymy_test_options = array();

// Initialize hook/cron storage.
$GLOBALS['nexifymy_test_actions'] = array();
$GLOBALS['nexifymy_test_filters'] = array();
$GLOBALS['nexifymy_test_cron']    = array();
$GLOBALS['nexifymy_test_mail']    = array();
$GLOBALS['nexifymy_test_user_meta'] = array();
$GLOBALS['nexifymy_test_userdata']  = array();

// Minimal $wpdb mock for module/unit tests.
if ( empty( $GLOBALS['wpdb'] ) ) {
	class NexifyMy_Test_WPDB {
		public $prefix = 'wp_';
		public $dbname = 'wordpress';
		public $usermeta = 'wp_usermeta';
		public $insert_calls = array();
		public $update_calls = array();
		public $queries = array();
		public $get_var_map = array();
		public $get_col_map = array();
		public $get_row_map = array();
		public $get_results_map = array();
		public $insert_id = 1;

		public function get_charset_collate() {
			return 'CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci';
		}

		public function prepare( $query, ...$args ) {
			return $query;
		}

		public function get_var( $query ) {
			$this->queries[] = $query;
			foreach ( $this->get_var_map as $needle => $value ) {
				if ( strpos( $query, $needle ) !== false ) {
					return $value;
				}
			}
			return 0;
		}

		public function get_col( $query ) {
			$this->queries[] = $query;
			foreach ( $this->get_col_map as $needle => $value ) {
				if ( strpos( $query, $needle ) !== false ) {
					return $value;
				}
			}
			return array();
		}

		public function get_row( $query, $output = OBJECT ) {
			$this->queries[] = $query;
			foreach ( $this->get_row_map as $needle => $value ) {
				if ( strpos( $query, $needle ) !== false ) {
					return $value;
				}
			}
			return null;
		}

		public function insert( $table, $data, $format = null ) {
			$this->insert_calls[] = compact( 'table', 'data', 'format' );
			return true;
		}

		public function update( $table, $data, $where, $format = null, $where_format = null ) {
			$this->update_calls[] = compact( 'table', 'data', 'where', 'format', 'where_format' );
			return true;
		}

		public function query( $query ) {
			$this->queries[] = $query;
			return 0;
		}

		public function get_results( $query, $output = OBJECT ) {
			$this->queries[] = $query;
			foreach ( $this->get_results_map as $needle => $value ) {
				if ( strpos( $query, $needle ) !== false ) {
					return $value;
				}
			}
			return array();
		}
	}

	$GLOBALS['wpdb'] = new NexifyMy_Test_WPDB();
}

if ( ! function_exists( 'wp_update_user' ) ) {
	function wp_update_user( $userdata ) {
		$GLOBALS['nexifymy_test_wp_update_user'][] = $userdata;
		return isset( $userdata['ID'] ) ? $userdata['ID'] : 0;
	}
}

if ( ! function_exists( 'get_role' ) ) {
	function get_role( $role ) {
		$roles = array(
			'administrator' => (object) array(
				'capabilities' => array(
					'manage_options'    => true,
					'edit_posts'        => true,
					'delete_posts'      => true,
					'manage_categories' => true,
				),
			),
			'editor' => (object) array(
				'capabilities' => array(
					'edit_posts'   => true,
					'delete_posts' => true,
				),
			),
			'subscriber' => (object) array(
				'capabilities' => array(
					'read' => true,
				),
			),
		);
		return isset( $roles[ $role ] ) ? $roles[ $role ] : null;
	}
}

if ( ! function_exists( 'wp_clear_scheduled_hook' ) ) {
	function wp_clear_scheduled_hook( $hook ) {
		unset( $GLOBALS['nexifymy_test_cron'][ $hook ] );
		return true;
	}
}

if ( ! function_exists( 'esc_attr_e' ) ) {
	function esc_attr_e( $text ) {
		echo $text;
	}
}

if ( ! function_exists( 'wp_remote_post' ) ) {
	function wp_remote_post( $url, $args = array() ) {
		$GLOBALS['nexifymy_test_remote_posts'][] = compact( 'url', 'args' );
		return array( 'response' => array( 'code' => 200 ) );
	}
}

if ( ! function_exists( 'wp_remote_retrieve_body' ) ) {
	function wp_remote_retrieve_body( $response ) {
		return isset( $response['body'] ) ? $response['body'] : '';
	}
}
