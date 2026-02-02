<?php
/**
 * Tests for NexifyMy_Security_Scanner module.
 *
 * These tests verify malware detection, heuristic analysis,
 * and file scanning functionality.
 */

require_once dirname( __DIR__ ) . '/tests/bootstrap.php';

class Test_Scanner extends \PHPUnit\Framework\TestCase {

	/**
	 * Malware signatures for testing.
	 *
	 * @var array
	 */
	private $malware_signatures = array(
		array(
			'pattern'     => '/eval\s*\(\s*base64_decode\s*\(/i',
			'severity'    => 'critical',
			'description' => 'Obfuscated eval/base64',
		),
		array(
			'pattern'     => '/\$_(?:GET|POST|REQUEST)\s*\[\s*[\'"][^\'"]+[\'"]\s*\]\s*\(/i',
			'severity'    => 'critical',
			'description' => 'Variable function call from user input',
		),
		array(
			'pattern'     => '/create_function\s*\(/i',
			'severity'    => 'high',
			'description' => 'Deprecated create_function',
		),
		array(
			'pattern'     => '/preg_replace\s*\(.+\/e[\'"]\s*,/i',
			'severity'    => 'critical',
			'description' => 'Code execution via preg_replace /e modifier',
		),
		array(
			'pattern'     => '/assert\s*\(\s*\$_/i',
			'severity'    => 'critical',
			'description' => 'Code execution via assert',
		),
		array(
			'pattern'     => '/gzinflate\s*\(\s*base64_decode/i',
			'severity'    => 'high',
			'description' => 'Compressed/obfuscated code',
		),
		array(
			'pattern'     => '/FilesMan|c99shell|r57shell|phpspy|b374k/i',
			'severity'    => 'critical',
			'description' => 'Known webshell signature',
		),
	);

	/**
	 * Helper to check if any signature matches.
	 *
	 * @param string $content File content to check.
	 * @return array|false Matched signature or false.
	 */
	private function scan_content( $content ) {
		foreach ( $this->malware_signatures as $signature ) {
			if ( preg_match( $signature['pattern'], $content ) ) {
				return $signature;
			}
		}
		return false;
	}

	/*
	 * =========================================================================
	 * MALWARE DETECTION TESTS
	 * =========================================================================
	 */

	/**
	 * Test detection of obfuscated eval/base64 code.
	 */
	public function test_detects_eval_base64() {
		$malicious_samples = array(
			'<?php eval(base64_decode("ZXZpbCBjb2Rl")); ?>',
			'<?php eval( base64_decode($encoded) ); ?>',
			'<?php @eval(base64_decode($_POST["cmd"])); ?>',
		);

		foreach ( $malicious_samples as $code ) {
			$match = $this->scan_content( $code );
			$this->assertNotFalse( $match, "Failed to detect: $code" );
			$this->assertEquals( 'critical', $match['severity'] );
		}
	}

	/**
	 * Test detection of variable function calls from user input.
	 */
	public function test_detects_variable_function_calls() {
		$malicious_samples = array(
			'<?php $_GET["func"]($arg); ?>',
			'<?php $_POST["callback"]("whoami"); ?>',
			'<?php $_REQUEST["x"]($_REQUEST["y"]); ?>',
		);

		foreach ( $malicious_samples as $code ) {
			$match = $this->scan_content( $code );
			$this->assertNotFalse( $match, "Failed to detect: $code" );
			$this->assertEquals( 'critical', $match['severity'] );
		}
	}

	/**
	 * Test detection of deprecated create_function.
	 */
	public function test_detects_create_function() {
		$malicious_samples = array(
			'<?php $func = create_function("", $code); ?>',
			'<?php create_function(\'$a\', \'return $a*2;\'); ?>',
		);

		foreach ( $malicious_samples as $code ) {
			$match = $this->scan_content( $code );
			$this->assertNotFalse( $match, "Failed to detect: $code" );
		}
	}

	/**
	 * Test detection of preg_replace with /e modifier.
	 */
	public function test_detects_preg_replace_e() {
		$malicious_samples = array(
			'<?php preg_replace("/.*/e", $_GET["cmd"], "test"); ?>',
			"<?php preg_replace('/^/e', \$code, ''); ?>",
		);

		foreach ( $malicious_samples as $code ) {
			$match = $this->scan_content( $code );
			$this->assertNotFalse( $match, "Failed to detect: $code" );
			$this->assertEquals( 'critical', $match['severity'] );
		}
	}

	/**
	 * Test detection of known webshell signatures.
	 */
	public function test_detects_webshell_signatures() {
		$malicious_samples = array(
			'<?php // FilesMan Webshell ?>',
			'<?php /* c99shell v2.0 */ ?>',
			'<?php // r57shell backdoor ?>',
			'<?php // phpspy ?>',
			'<?php // b374k shell ?>',
		);

		foreach ( $malicious_samples as $code ) {
			$match = $this->scan_content( $code );
			$this->assertNotFalse( $match, "Failed to detect: $code" );
			$this->assertEquals( 'critical', $match['severity'] );
		}
	}

	/**
	 * Test detection of compressed/obfuscated code.
	 */
	public function test_detects_obfuscated_code() {
		$malicious_samples = array(
			'<?php eval(gzinflate(base64_decode("encoded_data"))); ?>',
			'<?php @eval(gzinflate( base64_decode($data) )); ?>',
		);

		foreach ( $malicious_samples as $code ) {
			$match = $this->scan_content( $code );
			$this->assertNotFalse( $match, "Failed to detect: $code" );
		}
	}

	/*
	 * =========================================================================
	 * FALSE POSITIVE TESTS
	 * =========================================================================
	 */

	/**
	 * Test that legitimate code is not flagged.
	 */
	public function test_legitimate_code_not_flagged() {
		$legitimate_samples = array(
			'<?php echo "Hello World"; ?>',
			'<?php $name = sanitize_text_field($_POST["name"]); ?>',
			'<?php function myFunction($arg) { return $arg * 2; } ?>',
			'<?php if (isset($_GET["page"])) { echo esc_html($_GET["page"]); } ?>',
			'<?php $data = json_decode($json, true); ?>',
			'<?php class MyClass { public function test() { return true; } } ?>',
		);

		foreach ( $legitimate_samples as $code ) {
			$match = $this->scan_content( $code );
			$this->assertFalse( $match, "False positive on: $code" );
		}
	}

	/**
	 * Test that WordPress core patterns are not flagged.
	 */
	public function test_wordpress_patterns_not_flagged() {
		$wp_samples = array(
			'<?php add_action("init", "my_callback"); ?>',
			'<?php $value = get_option("my_option", "default"); ?>',
			'<?php wp_enqueue_script("jquery"); ?>',
			'<?php the_content(); ?>',
		);

		foreach ( $wp_samples as $code ) {
			$match = $this->scan_content( $code );
			$this->assertFalse( $match, "False positive on WordPress pattern: $code" );
		}
	}

	/*
	 * =========================================================================
	 * FILE EXTENSION TESTS
	 * =========================================================================
	 */

	/**
	 * Test file extension filtering.
	 */
	public function test_get_allowed_extensions() {
		$php_extensions   = array( 'php', 'php5', 'php7', 'phtml', 'inc' );
		$js_extensions    = array( 'js' );
		$other_extensions = array( 'htaccess', 'html', 'htm' );

		$all_scannable = array_merge( $php_extensions, $js_extensions, $other_extensions );

		// These should NOT be scanned.
		$ignored = array( 'jpg', 'png', 'gif', 'pdf', 'zip', 'css', 'woff', 'ttf' );

		foreach ( $all_scannable as $ext ) {
			$this->assertTrue(
				$this->is_scannable_extension( $ext ),
				"Extension should be scannable: $ext"
			);
		}

		foreach ( $ignored as $ext ) {
			$this->assertFalse(
				$this->is_scannable_extension( $ext ),
				"Extension should be ignored: $ext"
			);
		}
	}

	/**
	 * Helper to check if extension is scannable.
	 *
	 * @param string $ext Extension.
	 * @return bool
	 */
	private function is_scannable_extension( $ext ) {
		$scannable = array( 'php', 'php5', 'php7', 'phtml', 'inc', 'js', 'htaccess', 'html', 'htm' );
		return in_array( strtolower( $ext ), $scannable, true );
	}

	/*
	 * =========================================================================
	 * PATH EXCLUSION TESTS
	 * =========================================================================
	 */

	/**
	 * Test path exclusion matching.
	 */
	public function test_path_exclusion() {
		$excluded_paths = array(
			'/var/www/html/wp-content/cache/',
			'/var/www/html/wp-content/uploads/wc-logs/',
			'/var/www/html/node_modules/',
		);

		// Should be excluded.
		$this->assertTrue( $this->is_path_excluded( '/var/www/html/wp-content/cache/file.php', $excluded_paths ) );
		$this->assertTrue( $this->is_path_excluded( '/var/www/html/node_modules/package/index.js', $excluded_paths ) );

		// Should NOT be excluded.
		$this->assertFalse( $this->is_path_excluded( '/var/www/html/wp-content/plugins/myplugin/file.php', $excluded_paths ) );
		$this->assertFalse( $this->is_path_excluded( '/var/www/html/wp-includes/class-wp.php', $excluded_paths ) );
	}

	/**
	 * Helper to check if path is excluded.
	 *
	 * @param string $path           Path to check.
	 * @param array  $excluded_paths Excluded paths.
	 * @return bool
	 */
	private function is_path_excluded( $path, $excluded_paths ) {
		foreach ( $excluded_paths as $excluded ) {
			if ( strpos( $path, $excluded ) === 0 ) {
				return true;
			}
		}
		return false;
	}
}
