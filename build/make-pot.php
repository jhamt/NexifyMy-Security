<?php
/**
 * Simple POT Generator
 * Scans PHP files for translation functions and generates a .pot file.
 */

$source_dir  = dirname( __DIR__ ); // Plugin root
$output_file = $source_dir . '/languages/nexifymy-security.pot';
$text_domain = 'nexifymy-security';

echo "Scanning $source_dir for translation strings...\n";

$iterator = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $source_dir ) );
$regex    = '/\b(?:__|__e|_e|esc_html__|esc_html_e|esc_attr__|esc_attr_e|_x|_ex|esc_html_x|esc_attr_x)\s*\(\s*([\'"])((?:\\\\.|(?!\1).)*)\1\s*,\s*[\'"]' . preg_quote( $text_domain, '/' ) . '[\'"]/';

$strings = array();

foreach ( $iterator as $file ) {
	if ( $file->getExtension() !== 'php' || strpos( $file->getPathname(), 'node_modules' ) !== false || strpos( $file->getPathname(), 'vendor' ) !== false ) {
		continue;
	}

	$content = file_get_contents( $file->getPathname() );
	if ( preg_match_all( $regex, $content, $matches ) ) {
		foreach ( $matches[2] as $match ) {
			// Unescape single quotes if single-quoted string
			$string             = str_replace( "\'", "'", $match );
			$strings[ $string ] = true;
		}
	}
}

ksort( $strings );

$pot_content  = '# Copyright (C) ' . date( 'Y' ) . " NexifyMy\n";
$pot_content .= "msgid \"\"\n";
$pot_content .= "msgstr \"\"\n";
$pot_content .= "\"Project-Id-Version: NexifyMy Security 2.1.0\\n\"\n";
$pot_content .= '"POT-Creation-Date: ' . date( 'Y-m-d H:iO' ) . "\\n\"\n";
$pot_content .= "\"MIME-Version: 1.0\\n\"\n";
$pot_content .= "\"Content-Type: text/plain; charset=UTF-8\\n\"\n";
$pot_content .= "\"Content-Transfer-Encoding: 8bit\\n\"\n\n";

foreach ( array_keys( $strings ) as $string ) {
	$pot_content .= 'msgid "' . addcslashes( $string, '"' ) . "\"\n";
	$pot_content .= "msgstr \"\"\n\n";
}

if ( ! is_dir( dirname( $output_file ) ) ) {
	mkdir( dirname( $output_file ), 0755, true );
}

file_put_contents( $output_file, $pot_content );
echo "Generated $output_file with " . count( $strings ) . " strings.\n";
