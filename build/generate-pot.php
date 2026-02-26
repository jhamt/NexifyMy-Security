<?php
/**
 * PHP script to generate a .pot file for the plugin.
 *
 * Usage: php build/generate-pot.php
 */

// Define the plugin path (parent directory of this script).
$plugin_path = dirname( __DIR__ );
$text_domain = 'nexifymy-security';
$pot_file    = $plugin_path . '/languages/' . $text_domain . '.pot';

echo "Scanning $plugin_path for translatable strings...\n";

// Function to recursively scan directories.
function get_php_files( $dir ) {
	$files    = array();
	$iterator = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $dir ) );
	foreach ( $iterator as $file ) {
		if ( $file->isDir() ) {
			continue;
		}
		// Skip excluded directories.
		if ( strpos( $file->getPathname(), 'node_modules' ) !== false ||
			strpos( $file->getPathname(), 'vendor' ) !== false ||
			strpos( $file->getPathname(), '.git' ) !== false ||
			strpos( $file->getPathname(), '.vscode' ) !== false ||
			strpos( $file->getPathname(), 'tests' ) !== false ) {
			continue;
		}
		if ( $file->getExtension() === 'php' ) {
			$files[] = $file->getPathname();
		}
	}
	return $files;
}

$php_files = get_php_files( $plugin_path );
echo 'Found ' . count( $php_files ) . " PHP files.\n";

$strings = array();

// Regex to capture translation functions.
// Matches: __(), _e(), _x(), esc_html__(), esc_html_e(), esc_html_x(), esc_attr__(), esc_attr_e(), esc_attr_x(), _n(), _nx()
// We need to capture the string and the context (for _x functions)
foreach ( $php_files as $file_path ) {
	$content = file_get_contents( $file_path );

	// Simple parsing - iterate over patterns
	// 1. Standard functions
	$regex = '/\b(__|_e|esc_html__|esc_html_e|esc_attr__|esc_attr_e)\s*\(\s*([\'"])(.*?)(?<!\\\\)\2\s*,\s*([\'"])(.*?)(?<!\\\\)\4\s*\)/s';
	// Simplified: Just match any function that takes 'domain' as 2nd arg.
	// Pattern: FUNC ( 'STRING', 'DOMAIN' )
	if ( preg_match_all( $regex, $content, $matches, PREG_SET_ORDER ) ) {
		foreach ( $matches as $match ) {
			$string = $match[3]; // Raw string inside quotes
			$domain = $match[5];

			if ( $domain === $text_domain ) {
				$decoded_string = stripcslashes( $string );
				if ( ! isset( $strings[ $decoded_string ] ) ) {
					$strings[ $decoded_string ] = array( 'files' => array() );
				}

				$rel_path                              = str_replace( $plugin_path . DIRECTORY_SEPARATOR, '', $file_path );
				$rel_path                              = str_replace( '\\', '/', $rel_path );
				$strings[ $decoded_string ]['files'][] = $rel_path;
			}
		}
	}

	// 2. Context functions: _x( 'text', 'context', 'domain' )
	// Pattern: FUNC ( 'STRING', 'CONTEXT', 'DOMAIN' )
	$regex_x = '/\b(_x|esc_html_x|esc_attr_x)\s*\(\s*([\'"])(.*?)(?<!\\\\)\2\s*,\s*([\'"])(.*?)(?<!\\\\)\4\s*,\s*([\'"])(.*?)(?<!\\\\)\6\s*\)/s';
	if ( preg_match_all( $regex_x, $content, $matches, PREG_SET_ORDER ) ) {
		foreach ( $matches as $match ) {
			$string  = $match[3];
			$context = $match[5];
			$domain  = $match[7];

			if ( $domain === $text_domain ) {
				$decoded_string  = stripcslashes( $string );
				$decoded_context = stripcslashes( $context );

				$key = $decoded_string . "\004" . $decoded_context; // Null byte separator, standard for PO

				if ( ! isset( $strings[ $key ] ) ) {
					$strings[ $key ] = array(
						'string'  => $decoded_string,
						'context' => $decoded_context,
						'files'   => array(),
					);
				}

				$rel_path                   = str_replace( $plugin_path . DIRECTORY_SEPARATOR, '', $file_path );
				$rel_path                   = str_replace( '\\', '/', $rel_path );
				$strings[ $key ]['files'][] = $rel_path;
			}
		}
	}

	// 3. _n( 'single', 'plural', number, 'domain' )
	$regex_n = '/\b_n\s*\(\s*([\'"])(.*?)(?<!\\\\)\1\s*,\s*([\'"])(.*?)(?<!\\\\)\3\s*,.*?,\s*([\'"])(.*?)(?<!\\\\)\5\s*\)/s';
	if ( preg_match_all( $regex_n, $content, $matches, PREG_SET_ORDER ) ) {
		foreach ( $matches as $match ) {
			$single = $match[2];
			$plural = $match[4];
			$domain = $match[6];

			if ( $domain === $text_domain ) {
				$decoded_single = stripcslashes( $single );
				$decoded_plural = stripcslashes( $plural );
				$key            = $decoded_single; // Use single as key, add plural info

				if ( ! isset( $strings[ $key ] ) ) {
					$strings[ $key ] = array(
						'string' => $decoded_single,
						'plural' => $decoded_plural,
						'files'  => array(),
					);
				} else {
					$strings[ $key ]['plural'] = $decoded_plural;
				}

				$rel_path                   = str_replace( $plugin_path . DIRECTORY_SEPARATOR, '', $file_path );
				$rel_path                   = str_replace( '\\', '/', $rel_path );
				$strings[ $key ]['files'][] = $rel_path;
			}
		}
	}
}

// Build POT file content.
$output  = '# Copyright (C) ' . date( 'Y' ) . " SecureWP360\n";
$output .= "msgid \"\"\n";
$output .= "msgstr \"\"\n";
$output .= "\"Project-Id-Version: SecureWP360 2.1.0\\n\"\n";
$output .= "\"Report-Msgid-Bugs-To: https://wordpress.org/support/plugin/nexifymy-security\\n\"\n";
$output .= '"POT-Creation-Date: ' . date( 'Y-m-d H:iO' ) . "\\n\"\n";
$output .= "\"MIME-Version: 1.0\\n\"\n";
$output .= "\"Content-Type: text/plain; charset=UTF-8\\n\"\n";
$output .= "\"Content-Transfer-Encoding: 8bit\\n\"\n";
$output .= '"PO-Revision-Date: ' . date( 'Y' ) . "-MO-DA HO:MI+ZONE\\n\"\n";
$output .= "\"Last-Translator: FULL NAME <EMAIL@ADDRESS>\\n\"\n";
$output .= "\"Language-Team: LANGUAGE <LL@li.org>\\n\"\n";
$output .= "\n";

foreach ( $strings as $key => $data ) {

	// Deduplicate files and grab line numbers is hard without token_get_all,
	// so we just list filenames for now.
	$files = array_unique( $data['files'] );
	foreach ( $files as $f ) {
		$output .= "#: $f\n";
	}

	// Handle context
	if ( isset( $data['context'] ) ) {
		$output .= 'msgctxt "' . addcslashes( $data['context'], '"' ) . "\"\n";
		$output .= 'msgid "' . addcslashes( $data['string'], '"' ) . "\"\n";
		$output .= "msgstr \"\"\n\n";
	}
	// Handle plurals
	elseif ( isset( $data['plural'] ) ) {
		$output .= 'msgid "' . addcslashes( $key, '"' ) . "\"\n";
		$output .= 'msgid_plural "' . addcslashes( $data['plural'], '"' ) . "\"\n";
		$output .= "msgstr[0] \"\"\n";
		$output .= "msgstr[1] \"\"\n\n";
	}
	// Standard
	else {
		// key is the string
		$output .= 'msgid "' . addcslashes( $key, '"' ) . "\"\n";
		$output .= "msgstr \"\"\n\n";
	}
}

file_put_contents( $pot_file, $output );

echo "Generated POT file at: $pot_file\n";
echo 'Total strings: ' . count( $strings ) . "\n";
