<?php
/**
 * Simple PO to MO Compiler for PHP
 * Converts .po files to .mo files binary format.
 */

if ( php_sapi_name() !== 'cli' ) {
	die( 'CLI only' );
}

if ( $argc < 3 ) {
	die( "Usage: php compile-mo.php <input.po> <output.mo>\n" );
}

$input  = $argv[1];
$output = $argv[2];

if ( ! file_exists( $input ) ) {
	die( "Input file not found: $input\n" );
}

echo "Compiling $input -> $output\n";

$po_content = file_get_contents( $input );
$entries    = array();

// Very basic PO parser (handles msgid and msgstr)
// Note: This is a simplified parser for this specific task.
// It assumes msgid and msgstr are on separate lines and handles basic multiline.

$lines          = explode( "\n", $po_content );
$current_msgid  = null;
$current_msgstr = null;
$state          = null; // 'id' or 'str'

foreach ( $lines as $line ) {
	$line = trim( $line );
	if ( empty( $line ) || $line[0] === '#' ) {
		continue;
	}

	if ( strpos( $line, 'msgid "' ) === 0 ) {
		if ( $current_msgid !== null && $current_msgstr !== null ) {
			$entries[ $current_msgid ] = $current_msgstr;
		}
		$state          = 'id';
		$current_msgid  = parse_po_string( $line );
		$current_msgstr = null;
	} elseif ( strpos( $line, 'msgstr "' ) === 0 ) {
		$state          = 'str';
		$current_msgstr = parse_po_string( $line );
	} elseif ( $line[0] === '"' ) {
		$str = parse_po_string( $line );
		if ( $state === 'id' ) {
			$current_msgid .= $str;
		} elseif ( $state === 'str' ) {
			$current_msgstr .= $str;
		}
	}
}
// Add last entry
if ( $current_msgid !== null && $current_msgstr !== null ) {
	$entries[ $current_msgid ] = $current_msgstr;
}

// Generate MO Binary
$mo_data = generate_mo( $entries );
file_put_contents( $output, $mo_data );
echo 'Done. ' . count( $entries ) . " entries compiled.\n";

function parse_po_string( $line ) {
	$first_quote = strpos( $line, '"' );
	$last_quote  = strrpos( $line, '"' );
	if ( $first_quote === false || $last_quote === false || $last_quote <= $first_quote ) {
		return '';
	}
	return stripcslashes( substr( $line, $first_quote + 1, $last_quote - $first_quote - 1 ) );
}

function generate_mo( $entries ) {
	// Filter out empty translations
	$entries = array_filter(
		$entries,
		function ( $v ) {
			return $v !== '';
		}
	);
	ksort( $entries ); // Helper hash table requires sorted keys for binary search

	$count        = count( $entries );
	$originals    = array_keys( $entries );
	$translations = array_values( $entries );

	// Header
	// Magic: 0x950412de
	// Format: 0
	// Count: N
	// Offset Originals: O
	// Offset Translations: T
	// Size of Hashes: 0
	// Offset Hashes: H

	$header_size         = 28;
	$offset_originals    = $header_size;
	$offset_translations = $offset_originals + ( $count * 8 );
	$current_offset      = $offset_translations + ( $count * 8 );

	// Prepare table data
	$original_table    = '';
	$translation_table = '';
	$strings_block     = '';

	// We append strings after the tables
	$strings_start_offset = $current_offset;

	foreach ( $originals as $i => $original ) {
		$len             = strlen( $original );
		$original_table .= pack( 'LL', $len, $strings_start_offset + strlen( $strings_block ) );
		$strings_block  .= $original . "\0";
	}

	foreach ( $translations as $i => $trans ) {
		$len                = strlen( $trans );
		$translation_table .= pack( 'LL', $len, $strings_start_offset + strlen( $strings_block ) );
		$strings_block     .= $trans . "\0";
	}

	$header = pack(
		'L7',
		0x950412de, // Magic
		0,          // Revision
		$count,     // Count
		$offset_originals,
		$offset_translations,
		0,          // Hash size
		$offset_translations + ( $count * 8 ) // Hash offset (after translations table, though we have 0 hashes)
	);

	return $header . $original_table . $translation_table . $strings_block;
}
